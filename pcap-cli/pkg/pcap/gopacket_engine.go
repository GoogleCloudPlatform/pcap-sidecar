// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pcap

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/GoogleCloudPlatform/pcap-sidecar/pcap-cli/pkg/transformer"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var gopacketLogger = log.New(os.Stderr, "[gopacket] - ", log.LstdFlags)

func (p *Pcap) IsActive() bool {
	return p.isActive.Load()
}

func (p *Pcap) newPcap(ctx context.Context) (*pcap.InactiveHandle, error) {
	cfg := *p.config

	var err error

	inactiveHandle, err := pcap.NewInactiveHandle(cfg.Iface)
	if err != nil {
		gopacketLogger.Printf("could not create: %v\n", err)
	}

	if err = inactiveHandle.SetSnapLen(cfg.Snaplen); err != nil {
		gopacketLogger.Printf("could not set snap length: %v\n", err)
		return nil, err
	}

	if err = inactiveHandle.SetPromisc(cfg.Promisc); err != nil {
		gopacketLogger.Printf("could not set promisc mode: %v\n", err)
		return nil, err
	}

	// [TODO]: make handle timeout dynamic
	if err = inactiveHandle.SetTimeout(100 * time.Millisecond); err != nil {
		gopacketLogger.Printf("could not set timeout: %v\n", err)
		return nil, err
	}

	if cfg.TsType != "" {
		if t, err := pcap.TimestampSourceFromString(cfg.TsType); err != nil {
			gopacketLogger.Printf("Supported timestamp types: %v\n", inactiveHandle.SupportedTimestamps())
			return nil, err
		} else if err := inactiveHandle.SetTimestampSource(t); err != nil {
			gopacketLogger.Printf("Supported timestamp types: %v\n", inactiveHandle.SupportedTimestamps())
			return nil, err
		}
	}

	p.inactiveHandle = inactiveHandle

	return inactiveHandle, nil
}

func (p *Pcap) Start(
	ctx context.Context,
	writers []PcapWriter,
	stopDeadline <-chan *time.Duration,
) error {
	// atomically activate the packet capture
	if !p.isActive.CompareAndSwap(false, true) {
		return fmt.Errorf("already started")
	}

	var err error
	var handle *pcap.Handle

	inactiveHandle, err := p.newPcap(ctx)
	if err != nil {
		return err
	}
	defer inactiveHandle.CleanUp()

	if handle, err = inactiveHandle.Activate(); err != nil {
		p.isActive.Store(false)
		return fmt.Errorf("failed to activate: %s", err)
	}
	defer handle.Close()
	p.activeHandle = handle

	cfg := *p.config
	debug := cfg.Debug
	compat := cfg.Compat

	device := cfg.Device
	var iface *transformer.PcapIface
	if device != nil {
		// `device` is not safe to use outside this branch
		addrs := mapset.NewSetWithSize[string](len(device.Addresses))
		for _, addr := range device.Addresses {
			// [ToDo]: use `net.IP` instead of `string`
			addrs.Add(addr.IP.String())
		}
		iface = &transformer.PcapIface{
			Index: uint8(device.NetInterface.Index),
			Name:  device.Name,
			Addrs: addrs,
		}
	} else {
		iface = &transformer.PcapIface{
			Index: anyDeviceIndex,
			Name:  anyDeviceName,
			Addrs: mapset.NewThreadUnsafeSetWithSize[string](0),
		}
	}

	loggerPrefix := fmt.Sprintf("[%d/%s]", iface.Index, iface.Name)

	if !compat {
		// set packet capture filter; i/e: `tcp port 8080`
		if filter := providePcapFilter(ctx, &cfg.Filter, cfg.Filters); *filter != "" {
			if err = handle.SetBPFFilter(*filter); err != nil {
				gopacketLogger.Printf("%s - BPF filter error: [%s] => %+v\n", loggerPrefix, *filter, err)
				return fmt.Errorf("BPF filter error: %s", err)
			}
			gopacketLogger.Printf("%s - filter: %s\n", loggerPrefix, *filter)
		}
	}

	gopacketLogger.Printf("%s - starting packet capture\n", loggerPrefix)

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	// https://github.com/google/gopacket/blob/master/packet.go#L660-L680
	source.Lazy = true
	// https://github.com/google/gopacket/blob/master/packet.go#L655-L659
	source.NoCopy = true
	source.SkipDecodeRecovery = false
	source.DecodeStreamsAsDatagrams = true

	// `io.Writer` is what `fmt.Fprintf` requires
	ioWriters := make([]io.Writer, len(writers))
	for i, writer := range writers {
		ioWriters[i] = writer
	}

	format := cfg.Format
	compatFilters, ok := cfg.CompatFilters.(transformer.PcapFilters)
	if !ok {
		compatFilters = nil
	}

	// create new transformer for the specified output format
	if cfg.Ordered {
		p.fn, err = transformer.NewOrderedTransformer(ctx, iface, cfg.Ephemerals, compatFilters, ioWriters, &format, debug, compat)
	} else if cfg.ConnTrack {
		p.fn, err = transformer.NewConnTrackTransformer(ctx, iface, cfg.Ephemerals, compatFilters, ioWriters, &format, debug, compat)
	} else {
		p.fn, err = transformer.NewTransformer(ctx, iface, cfg.Ephemerals, compatFilters, ioWriters, &format, debug, compat)
	}

	if err != nil {
		return fmt.Errorf("invalid format: %s", err)
	}

	if firstPacket, err := source.NextPacket(); err == nil && firstPacket != nil {
		serial := uint64(0)
		if err = p.fn.Apply(ctx, &firstPacket, &serial); err != nil {
			gopacketLogger.Printf("%s - #:0 | failed to translate 1st packet: %v\n", loggerPrefix, err)
		}
	} else {
		gopacketLogger.Printf("%s - #:0 | error: %v\n", loggerPrefix, err)
	}

	gopacketLogger.Printf("%s - translating packets\n", loggerPrefix)

	var packetsCounter atomic.Uint64
	var ctxDoneTS time.Time
	for p.isActive.Load() {
		select {
		case <-ctx.Done():
			if p.isActive.CompareAndSwap(true, false) {
				ctxDoneTS = time.Now()
				gopacketLogger.Printf("%s - stopping packet capture\n", loggerPrefix)
			}

		case packet := <-source.Packets():
			serial := packetsCounter.Add(1)
			// non-blocking operation
			if err = p.fn.Apply(ctx, &packet, &serial); err != nil && p.isActive.Load() {
				gopacketLogger.Printf("%s - #:%d | failed to translate: %v\n", loggerPrefix, serial, err)
			}
		}
	}

	gopacketLogger.Printf("%s - stopping packet capture\n", loggerPrefix)

	engineStopDeadline := <-stopDeadline
	deadline := *engineStopDeadline - time.Since(ctxDoneTS)
	p.fn.WaitDone(ctx, &deadline)

	gopacketLogger.Printf("%s – total packets: %d\n", loggerPrefix, packetsCounter.Load())

	return ctx.Err()
}

func NewPcap(config *PcapConfig) (PcapEngine, error) {
	var isActive atomic.Bool
	isActive.Store(false)

	debug := config.Debug
	if debugEnvVar, err := strconv.ParseBool(os.Getenv("PCAP_DEBUG")); err == nil {
		config.Debug = debug || debugEnvVar
	}

	// `config.Ephemerals` is already a safe type,
	// here the validation only enforces correctness of port range.
	if config.Ephemerals == nil ||
		config.Ephemerals.Min < pcap_min_ephemeral_port ||
		config.Ephemerals.Min >= config.Ephemerals.Max {
		config.Ephemerals = &PcapEmphemeralPorts{
			Min: PCAP_MIN_EPHEMERAL_PORT,
			Max: PCAP_MAX_EPHEMERAL_PORT,
		}
	}

	pcap := Pcap{config: config, isActive: &isActive}

	if strings.EqualFold(config.Iface, anyDeviceName) {
		config.Device = nil
	} else {
		devices, err := FindDevicesByName(&config.Iface)
		if err == nil {
			config.Device = devices[0]
		}
	}

	return &pcap, nil
}
