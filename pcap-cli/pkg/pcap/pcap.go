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
	"net"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/GoogleCloudPlatform/pcap-sidecar/pcap-cli/pkg/transformer"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/wissance/stringFormatter"
)

type (
	TCPFlag  = transformer.TCPFlag
	TCPFlags = transformer.TCPFlags

	L3Proto = transformer.L3Proto

	L4Proto = transformer.L4Proto

	PcapEmphemeralPorts = transformer.PcapEmphemeralPorts

	PcapFilterMode uint8

	PcapFilter struct {
		Raw *string
	}

	// PCAP owns the behavior that will be exposed to consumers
	PcapFilters interface {
		AddL3Proto(L3Proto)
		AddL3Protos(...L3Proto)
		AddIPv4(string)
		AddIPv4s(...string)
		AddIPv6(string)
		AddIPv6s(...string)
		AddIPv4Range(string)
		AddIPv4Ranges(...string)
		AddIPv6Range(string)
		AddIPv6Ranges(...string)
		AddL4Proto(L4Proto)
		AddL4Protos(...L4Proto)
		AddPort(uint16)
		AddPorts(...uint16)
		AddTCPFlags(...TCPFlag)
		CombineAndAddTCPFlags(...TCPFlag)
	}

	PcapFilterProvider interface {
		fmt.Stringer
		Get(context.Context) (*string, bool)
		Apply(context.Context, *string, PcapFilterMode) *string
	}

	PcapConfig struct {
		Compat        bool
		Debug         bool
		Promisc       bool
		Iface         string
		Snaplen       int
		TsType        string
		Format        string
		Filter        string
		Output        string
		Interval      int
		Extension     string
		Ordered       bool
		ConnTrack     bool
		Device        *PcapDevice
		Filters       []PcapFilterProvider
		CompatFilters PcapFilters
		Ephemerals    *PcapEmphemeralPorts
	}

	PcapEngine interface {
		Start(context.Context, []PcapWriter, <-chan *time.Duration) error
		IsActive() bool
	}

	PcapDevice struct {
		NetInterface *net.Interface
		pcap.Interface
	}

	Pcap struct {
		config         *PcapConfig
		isActive       *atomic.Bool
		activeHandle   gopacket.PacketDataSource
		inactiveHandle *pcap.InactiveHandle
		fn             transformer.IPcapTransformer
	}

	Tcpdump struct {
		config   *PcapConfig
		isActive *atomic.Bool
		tcpdump  string
	}
)

const (
	PCAP_FILTER_MODE_AND PcapFilterMode = iota
	PCAP_FILTER_MODE_OR
)

const (
	PcapContextID      = transformer.ContextID
	PcapContextLogName = transformer.ContextLogName
)

const (
	PcapDefaultFilter = "(tcp or udp or icmp or icmp6) and (ip or ip6 or arp)"
)

const (
	pcap_min_ephemeral_port uint16 = 0x0400 // 1024 – start of registered ports per RFC 6056
	PCAP_MIN_EPHEMERAL_PORT uint16 = 0x8000 // 32768 – preferred MIN ephemeral port ( not as high as 0x0C000 / 49152 )
	PCAP_MAX_EPHEMERAL_PORT uint16 = 0xFFFF // 65535 ( Linux: 60999 / 0xEE47 )
)

const (
	// see: https://github.com/google/gopacket/blob/master/pcap/pcap.go#L802-L808
	anyDeviceName  string = "any"
	anyDeviceIndex uint8  = 0
)

const (
	TCP_FLAG_SYN = TCPFlag("SYN")
	TCP_FLAG_ACK = TCPFlag("ACK")
	TCP_FLAG_PSH = TCPFlag("PSH")
	TCP_FLAG_FIN = TCPFlag("FIN")
	TCP_FLAG_RST = TCPFlag("RST")
	TCP_FLAG_URG = TCPFlag("URG")
	TCP_FLAG_ECE = TCPFlag("ECE")
	TCP_FLAG_CWR = TCPFlag("CWR")

	L3_PROTO_IPv4 = L3Proto(0x04)
	L3_PROTO_IP4  = L3_PROTO_IPv4
	L3_PROTO_IPv6 = L3Proto(0x29)
	L3_PROTO_IP6  = L3_PROTO_IPv6

	L4_PROTO_TCP   = L4Proto(0x06)
	L4_PROTO_UDP   = L4Proto(0x11)
	L4_PROTO_ICMP  = L4Proto(0x01)
	L4_PROTO_ICMP4 = L4_PROTO_ICMP
	L4_PROTO_ICMP6 = L4Proto(0x3A)
)

func providePcapFilter(
	ctx context.Context,
	filter *string,
	providers []PcapFilterProvider,
) *string {
	select {
	case <-ctx.Done():
		return filter
	default:
	}

	pcapFilter := ""

	// if `filter` is available, then providers are not used to build the BPF filter.
	if filter != nil && *filter != "" && !strings.EqualFold(*filter, "DISABLED") {
		// `filter` is extremely unsafe as it is a free form expression:
		// [ToDo] – validate `filter` to enforce correctness of expressions.
		pcapFilter = stringFormatter.Format("({0})", *filter)
	} else if len(providers) > 0 {
		for _, provider := range providers {
			if provider != nil {
				if f := provider.Apply(ctx,
					&pcapFilter, PCAP_FILTER_MODE_AND); f != nil {
					pcapFilter = *f
				}
			}
		}
	} else {
		pcapFilter = string(PcapDefaultFilter)
	}

	return &pcapFilter
}

func findAllDevs(compare func(*string) bool) ([]*PcapDevice, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	var devs []*PcapDevice
	for _, device := range devices {
		if compare(&device.Name) {
			if iface, err := net.InterfaceByName(device.Name); err == nil {
				devs = append(devs, &PcapDevice{iface, device})
			}
		}
	}
	return devs, nil
}

func FindDevicesByRegex(exp *regexp.Regexp) ([]*PcapDevice, error) {
	compare := func(deviceName *string) bool {
		return exp.MatchString(*deviceName)
	}
	return findAllDevs(compare)
}

func FindDevicesByName(deviceName *string) ([]*PcapDevice, error) {
	name := *deviceName
	compare := func(deviceName *string) bool {
		return name == *deviceName
	}
	return findAllDevs(compare)
}

func NewPcapFilters() PcapFilters {
	return transformer.NewPcapFilters()
}
