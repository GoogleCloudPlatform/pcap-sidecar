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

package transformer

import (
	"context"
	"fmt"
	"net/netip"
	"runtime/debug"
	"sync"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type (
	pcapTranslatorWorker struct {
		ifaces     netIfaceIndex
		iface      *PcapIface
		filters    PcapFilters
		serial     *uint64
		packet     *gopacket.Packet
		translator PcapTranslator
		conntrack  bool
		compat     bool

		loggerPrefix *string
	}

	packetLayerTranslator = func(context.Context, *pcapTranslatorWorker, bool) fmt.Stringer
	layersTranslators     = map[gopacket.LayerType]packetLayerTranslator

	httpRequest struct {
		timestamp   *time.Time
		url, method *string
	}

	traceAndSpan struct {
		traceID, spanID *string
		streamID        *uint32
	}
)

var (
	// alternatives per layer; there can only be one!
	packetLayerTranslators = [][]packetLayerTranslator{
		// [0]: L2
		{
			// [0][0]
			func(ctx context.Context, w *pcapTranslatorWorker, deep bool) fmt.Stringer {
				return w.translateEthernetLayer(ctx, deep)
			},
		},

		// [1]: L3
		{
			// [1][0]
			func(ctx context.Context, w *pcapTranslatorWorker, deep bool) fmt.Stringer {
				return w.translateIPv4Layer(ctx, deep)
			},
			// [1][1]
			func(ctx context.Context, w *pcapTranslatorWorker, deep bool) fmt.Stringer {
				return w.translateIPv6Layer(ctx, deep)
			},
		},

		// [2]: L4
		{
			// ICMP layers
			//   - ICMP is not a transport layer protocol, but if it is present
			//   - then actual transport layer protocol translations are disabled;
			//   - thus, TCP/UDP translations are causally dependant on the lack of ICMP.

			// [2][0]
			func(ctx context.Context, w *pcapTranslatorWorker, deep bool) fmt.Stringer {
				return w.translateICMPv4Layer(ctx, deep)
			},
			// [2][1]
			func(ctx context.Context, w *pcapTranslatorWorker, deep bool) fmt.Stringer {
				return w.translateICMPv6Layer(ctx, deep)
			},

			// non-ICMP layers

			// [2][2]
			func(ctx context.Context, w *pcapTranslatorWorker, deep bool) fmt.Stringer {
				return w.translateTCPLayer(ctx, deep)
			},
			// [2][3]
			func(ctx context.Context, w *pcapTranslatorWorker, deep bool) fmt.Stringer {
				return w.translateUDPLayer(ctx, deep)
			},
		},

		// [3]: L7
		{
			// [3][0]
			func(ctx context.Context, w *pcapTranslatorWorker, deep bool) fmt.Stringer {
				return w.translateDNSLayer(ctx, deep)
			},
			// [3][1]
			func(ctx context.Context, w *pcapTranslatorWorker, deep bool) fmt.Stringer {
				return w.translateTLSLayer(ctx, deep)
			},
		},
	}

	packetLayerTranslatorsSize = len(packetLayerTranslators)

	packetLayerTranslatorsMap layersTranslators = map[gopacket.LayerType]packetLayerTranslator{
		layers.LayerTypeEthernet: packetLayerTranslators[0][0],
		layers.LayerTypeIPv4:     packetLayerTranslators[1][0],
		layers.LayerTypeIPv6:     packetLayerTranslators[1][1],
		layers.LayerTypeICMPv4:   packetLayerTranslators[2][0],
		layers.LayerTypeICMPv6:   packetLayerTranslators[2][1],
		layers.LayerTypeTCP:      packetLayerTranslators[2][2],
		layers.LayerTypeUDP:      packetLayerTranslators[2][3],
		layers.LayerTypeDNS:      packetLayerTranslators[3][0],
		layers.LayerTypeTLS:      packetLayerTranslators[3][1],
		layers.LayerTypeICMPv6Echo: func(
			ctx context.Context,
			w *pcapTranslatorWorker,
			deep bool,
		) fmt.Stringer {
			return w.translateICMPv6EchoLayer(ctx, deep)
		},
		layers.LayerTypeICMPv6Redirect: func(
			ctx context.Context,
			w *pcapTranslatorWorker,
			deep bool,
		) fmt.Stringer {
			return w.translateICMPv6RedirectLayer(ctx, deep)
		},
		gopacket.LayerTypeDecodeFailure: func(
			ctx context.Context,
			w *pcapTranslatorWorker,
			deep bool,
		) fmt.Stringer {
			return w.translateErrorLayer(ctx, deep)
		},
	}

	skippedLayersList = []gopacket.LayerType{
		gopacket.LayerTypePayload,
		gopacket.LayerTypeDecodeFailure,
		layers.LayerTypeLinuxSLL,
	}
	skippedLayers = mapset.NewSet(skippedLayersList...)
)

func (w pcapTranslatorWorker) pkt(ctx context.Context) gopacket.Packet {
	return *w.packet
}

func (w *pcapTranslatorWorker) asLayer(ctx context.Context, layer gopacket.LayerType) gopacket.Layer {
	// https://github.com/google/gopacket/blob/master/packet.go#L568-L585
	// https://github.com/google/gopacket/blob/master/packet.go#L476-L483
	return w.pkt(ctx).Layer(layer)
}

func (w *pcapTranslatorWorker) translateLayer(
	ctx context.Context, layer gopacket.LayerType, deep bool,
) fmt.Stringer {
	// confirm that the packet actually contains the requested layer
	l := w.asLayer(ctx, layer)
	if l == nil {
		return nil
	}

	switch lType := l.(type) {
	default:
		return nil
	case *layers.Ethernet:
		return w.translator.translateEthernetLayer(ctx, lType)
	case *layers.ARP:
		return w.translator.translateARPLayer(ctx, lType)
	case *layers.IPv4:
		return w.translator.translateIPv4Layer(ctx, lType)
	case *layers.IPv6:
		return w.translator.translateIPv6Layer(ctx, lType)
	case *layers.ICMPv4:
		return w.translator.translateICMPv4Layer(ctx, lType)
	case *layers.ICMPv6:
		icmp6 := w.translator.translateICMPv6Layer(ctx, lType)

		// [ToDo]: handle layers.ICMPv6TypePacketTooBig
		if lType.TypeCode.Type() == layers.ICMPv6TypeDestinationUnreachable ||
			lType.TypeCode.Type() == layers.ICMPv6TypeTimeExceeded {
			return w.translator.translateICMPv6L3HeaderLayer(ctx, icmp6, lType)
		}

		if !deep {
			return icmp6
		}

		_l := w.asLayer(ctx, lType.NextLayerType())

		switch _lType := _l.(type) {
		default:
			return icmp6
		case *layers.ICMPv6Echo:
			return w.translator.translateICMPv6EchoLayer(ctx, icmp6, _lType)
		case *layers.ICMPv6Redirect:
			return w.translator.translateICMPv6RedirectLayer(ctx, icmp6, _lType)
		}
	case *layers.ICMPv6Echo:
		return w.translator.translateICMPv6EchoLayer(ctx, nil, lType)
	case *layers.ICMPv6Redirect:
		return w.translator.translateICMPv6RedirectLayer(ctx, nil, lType)
	case *layers.TCP:
		return w.translator.translateTCPLayer(ctx, lType)
	case *layers.UDP:
		return w.translator.translateUDPLayer(ctx, lType)
	case *layers.DNS:
		return w.translator.translateDNSLayer(ctx, lType)
	case *layers.TLS:
		return w.translator.translateTLSLayer(ctx, lType)
	case *gopacket.DecodeFailure:
		// see: https://github.com/google/gopacket/blob/v1.1.19/decode.go#L118-L126
		return w.translator.translateErrorLayer(ctx, lType)
	}
}

func (w pcapTranslatorWorker) translateEthernetLayer(ctx context.Context, deep bool) fmt.Stringer {
	return w.translateLayer(ctx, layers.LayerTypeEthernet, deep)
}

func (w pcapTranslatorWorker) translateARPLayer(ctx context.Context, deep bool) fmt.Stringer {
	return w.translateLayer(ctx, layers.LayerTypeARP, deep)
}

func (w *pcapTranslatorWorker) translateIPv4Layer(ctx context.Context, deep bool) fmt.Stringer {
	return w.translateLayer(ctx, layers.LayerTypeIPv4, deep)
}

func (w *pcapTranslatorWorker) translateIPv6Layer(ctx context.Context, deep bool) fmt.Stringer {
	return w.translateLayer(ctx, layers.LayerTypeIPv6, deep)
}

func (w *pcapTranslatorWorker) translateICMPv4Layer(ctx context.Context, deep bool) fmt.Stringer {
	return w.translateLayer(ctx, layers.LayerTypeICMPv4, deep)
}

func (w *pcapTranslatorWorker) translateICMPv6Layer(ctx context.Context, deep bool) fmt.Stringer {
	return w.translateLayer(ctx, layers.LayerTypeICMPv6, deep)
}

func (w *pcapTranslatorWorker) translateICMPv6EchoLayer(ctx context.Context, deep bool) fmt.Stringer {
	return w.translateLayer(ctx, layers.LayerTypeICMPv6Echo, deep)
}

func (w *pcapTranslatorWorker) translateICMPv6RedirectLayer(ctx context.Context, deep bool) fmt.Stringer {
	return w.translateLayer(ctx, layers.LayerTypeICMPv6Redirect, deep)
}

func (w *pcapTranslatorWorker) translateTCPLayer(ctx context.Context, deep bool) fmt.Stringer {
	return w.translateLayer(ctx, layers.LayerTypeTCP, deep)
}

func (w *pcapTranslatorWorker) translateUDPLayer(ctx context.Context, deep bool) fmt.Stringer {
	return w.translateLayer(ctx, layers.LayerTypeUDP, deep)
}

func (w *pcapTranslatorWorker) translateDNSLayer(ctx context.Context, deep bool) fmt.Stringer {
	return w.translateLayer(ctx, layers.LayerTypeDNS, deep)
}

func (w *pcapTranslatorWorker) translateTLSLayer(ctx context.Context, deep bool) fmt.Stringer {
	/*
		packet := w.pkt(ctx)
		if packet.ApplicationLayer() != nil {
			var tls layers.TLS
			var decoded []gopacket.LayerType
			parser := gopacket.NewDecodingLayerParser(layers.LayerTypeTLS, &tls)
			err := parser.DecodeLayers(packet.ApplicationLayer().LayerContents(), &decoded)
			if err == nil {
				for _, layerType := range decoded {
					switch layerType {
					case layers.LayerTypeTLS:
						return w.translator.translateTLSLayer(ctx, &tls)
					}
				}
			}
		}
	*/

	return w.translateLayer(ctx, layers.LayerTypeTLS, deep)
}

func (w *pcapTranslatorWorker) translateErrorLayer(ctx context.Context, deep bool) fmt.Stringer {
	return w.translateLayer(ctx, gopacket.LayerTypeDecodeFailure, deep)
}

func (w *pcapTranslatorWorker) toIP4Addrs(
	ip4 *layers.IPv4,
) (*netip.Addr, *netip.Addr) {
	var ip4Bytes [4]byte

	copy(ip4Bytes[:], ip4.SrcIP.To4())
	srcAddr := netip.AddrFrom4(ip4Bytes)

	copy(ip4Bytes[:], ip4.DstIP.To4())
	dstAddr := netip.AddrFrom4(ip4Bytes)

	return &srcAddr, &dstAddr
}

func (w *pcapTranslatorWorker) toIP6Addrs(
	ip6 *layers.IPv6,
) (*netip.Addr, *netip.Addr) {
	var ip6Bytes [16]byte

	copy(ip6Bytes[:], ip6.SrcIP.To16())
	srcAddr := netip.AddrFrom16(ip6Bytes)

	copy(ip6Bytes[:], ip6.DstIP.To16())
	dstAddr := netip.AddrFrom16(ip6Bytes)

	return &srcAddr, &dstAddr
}

func (w *pcapTranslatorWorker) isIPv4Allowed(
	ctx context.Context,
	ip4 *layers.IPv4,
) (*netip.Addr, *netip.Addr, bool) {
	src, dst := w.toIP4Addrs(ip4)

	if w.filters.HasL3Protos() && !w.filters.AllowsIPv4() {
		// fail fast: nothing to verify
		return src, dst, false
	}

	if !w.filters.HasIPv4s() {
		// fail open: ALL IPv4s are allowed
		return src, dst, true
	}

	if !w.filters.AllowsIPv4Addr(src) {
		// fail fast: if SRC is not allowed, skip checking DST
		return src, dst, false
	}

	return src, dst, w.filters.AllowsIPv4Addr(dst)
}

func (w *pcapTranslatorWorker) isIPv6Allowed(
	ctx context.Context,
	ip6 *layers.IPv6,
) (*netip.Addr, *netip.Addr, bool) {
	src, dst := w.toIP6Addrs(ip6)

	if w.filters.HasL3Protos() && !w.filters.AllowsIPv6() {
		// fail fast: nothing to verify
		return src, dst, false
	}

	if !w.filters.HasIPv6s() {
		// fail open: ALL IPv6s are allowed
		return src, dst, true
	}

	if !w.filters.AllowsIPv6Addr(src) {
		// fail fast: if SRC is not allowed, skip checking DST
		return src, src, false
	}

	return src, dst, w.filters.AllowsIPv6Addr(dst)
}

func (w *pcapTranslatorWorker) isL3Allowed(
	ctx context.Context,
) (*netip.Addr, *netip.Addr, bool) {
	layer := w.asLayer(ctx, layers.LayerTypeIPv4)
	isIPv6 := false
	if layer == nil {
		if layer = w.asLayer(ctx, layers.LayerTypeIPv6); layer == nil {
			// the packet does not contain IP layer information
			// fail open: nothing to verify
			return nil, nil, true
		}
		isIPv6 = true
	}

	if isIPv6 {
		ip6 := layer.(*layers.IPv6)
		return w.isIPv6Allowed(ctx, ip6)
	}

	ip4 := layer.(*layers.IPv4)
	return w.isIPv4Allowed(ctx, ip4)
}

func (w *pcapTranslatorWorker) arePortsAllowed(
	ctx context.Context,
	src *uint16, dst *uint16,
) (*uint16, *uint16, bool) {
	if w.filters.AllowsAnyL4Addr(*src, *dst) {
		return src, dst, true
	}
	// fail open
	return src, dst, false
}

func (w *pcapTranslatorWorker) isL4Allowed(
	ctx context.Context,
) (*uint16, *uint16, bool) {
	isProtosFilterAvailable := w.filters.HasL4Protos()
	isTCPflagsFilterAvailable := w.filters.HasTCPflags()
	isL4AddrsFilterAvailable := w.filters.HasL4Addrs()

	layer := w.asLayer(ctx, layers.LayerTypeTCP)
	if layer != nil {
		tcp := layer.(*layers.TCP)

		srcPort := uint16(tcp.SrcPort)
		dstPort := uint16(tcp.DstPort)

		if isProtosFilterAvailable && !w.filters.AllowsTCP() {
			// fail fast: if TCP is not allowed, do not check ports
			return &srcPort, &dstPort, false
		}

		if isTCPflagsFilterAvailable {
			// fail fast & open: if this it TCP, then flags cannot be 0; some flag must be set
			if flags := parseTCPflags(tcp); !w.filters.AllowsAnyTCPflags(&flags) {
				return &srcPort, &dstPort, false
			}
		}

		if isL4AddrsFilterAvailable {
			return w.arePortsAllowed(ctx, &srcPort, &dstPort)
		}

		return &srcPort, &dstPort, true
	}

	layer = w.asLayer(ctx, layers.LayerTypeUDP)
	if layer == nil {
		// the packet does not contain TCP/UDP information
		// fail open
		return nil, nil, true
	}

	udp := layer.(*layers.UDP)

	srcPort := uint16(udp.SrcPort)
	dstPort := uint16(udp.DstPort)

	if isProtosFilterAvailable && !w.filters.AllowsUDP() {
		// fail fast: if UDP is not allowed, do not check ports
		return &srcPort, &dstPort, false
	}

	if isL4AddrsFilterAvailable {
		return w.arePortsAllowed(ctx, &srcPort, &dstPort)
	}

	return &srcPort, &dstPort, true
}

func (w *pcapTranslatorWorker) isSocketAllowed(
	srcAddr *netip.Addr, srcPort *uint16,
	dstAddr *netip.Addr, dstPort *uint16,
) bool {
	if srcAddr == nil || srcPort == nil || dstAddr == nil || dstPort == nil {
		// fail open: if any input is `nil`, skip socket filter
		return true
	}
	return w.filters.AllowsSocket(srcAddr, srcPort, dstAddr, dstPort)
}

func (w *pcapTranslatorWorker) shouldTranslate(ctx context.Context) bool {
	srcAddr, dstAddr, l3Allowed := w.isL3Allowed(ctx)
	srcPort, dstPort, l4Allowed := w.isL4Allowed(ctx)
	if l3Allowed && l4Allowed {
		// only enforce sockets if everything else is allowed
		return w.isSocketAllowed(srcAddr, srcPort, dstAddr, dstPort)
	}
	return false
}

func (w *pcapTranslatorWorker) translate(
	ctx context.Context,
	index int,
	layer gopacket.Layer,
	translations chan<- fmt.Stringer,
	wg *sync.WaitGroup,
) {
	layerType := layer.LayerType()

	defer func(index int, layer gopacket.Layer, wg *sync.WaitGroup) {
		if r := recover(); r != nil {
			translations <- w.translator.translateLayerError(ctx,
				layerType, fmt.Errorf("%v: %s", r, string(debug.Stack())))
		}
		wg.Done()
	}(index, layer, wg)

	if translator, ok := packetLayerTranslatorsMap[layerType]; ok {
		if t := translator(ctx, w, false /* deep */); t == nil {
			translations <- w.translator.translateLayerError(ctx,
				layerType, fmt.Errorf("unavailable@%d", index))
		} else {
			translations <- t
		}
		return
	}

	// translator does not have an implementation to handle this layer type
	switch layer.(type) {
	default:
		if !skippedLayers.Contains(layerType) {
			translations <- w.translator.translateLayerError(ctx,
				layerType, fmt.Errorf("unimplemented@%d", index))
		}
	}
}

// The work that needs to be performed
// The input type should implement the WorkFunction interface
func (w *pcapTranslatorWorker) Run(ctx context.Context) (buffer interface{}) {
	defer func() {
		if r := recover(); r != nil {
			transformerLogger.Printf("%s @translator | panic: %s\n%s\n",
				*w.loggerPrefix, r, string(debug.Stack()))
			buffer = nil
		}
	}()

	// fail open:
	//   - if there aren't any filters, continue with translation.
	// fail fast:
	//   - do not translate any layers before enforcing filters.
	if w.filters != nil && !w.shouldTranslate(ctx) {
		return nil
	}

	var _buffer fmt.Stringer = nil

	select {
	case <-ctx.Done():
		_buffer = nil
	default:
		_buffer = w.translator.next(ctx, w.iface, w.serial, w.packet)
	}

	if _buffer == nil {
		transformerLogger.Printf("%s @translator | failed", *w.loggerPrefix)
		buffer = nil
		return nil
	}

	translations := make(chan fmt.Stringer, packetLayerTranslatorsSize)
	var wg sync.WaitGroup

	// number of layers to be translated
	packetLayers := w.pkt(ctx).Layers()
	wg.Add(len(packetLayers))

	go func(wg *sync.WaitGroup) {
		wg.Wait()
		close(translations)
	}(&wg)

	// O(N); N is the number of layers available in the packet
	// this is a faster implementation as there is no layer discovery;
	// layers are translated on-demand based on the packet's contents.
	for i, l := range packetLayers {
		// translate layers concurrently:
		//   - layers must know nothing about each other
		go w.translate(ctx, i, l, translations, &wg)
	}

	for translation := range translations {
		// translations are `nil` if layer is not available
		if translation != nil {
			// see: https://github.com/Jeffail/gabs?tab=readme-ov-file#merge-two-containers
			_buffer, _ = w.translator.merge(ctx, _buffer, translation)
		}
	}

	select {
	case <-ctx.Done():
		// skip `finalize` deliver translation as-is
		transformerLogger.Printf("%s @translator | incomplete", *w.loggerPrefix)
	default:
		// `finalize` is the only method that is allowed to work across layers
		_buffer, _ = w.translator.finalize(ctx, w.ifaces, w.iface, w.serial, w.packet, w.conntrack, _buffer)
	}

	buffer = &_buffer
	return &_buffer
}

func newPcapTranslatorWorker(
	ifaces netIfaceIndex,
	iface *PcapIface,
	filters PcapFilters,
	serial *uint64,
	packet *gopacket.Packet,
	translator PcapTranslator,
	connTrack bool,
	compat bool,
) *pcapTranslatorWorker {
	loggerPrefix := fmt.Sprintf("[%d/%s] - #:%d |", iface.Index, iface.Name, *serial)

	worker := &pcapTranslatorWorker{
		filters:      filters,
		ifaces:       ifaces,
		iface:        iface,
		serial:       serial,
		packet:       packet,
		translator:   translator,
		conntrack:    connTrack,
		compat:       compat,
		loggerPrefix: &loggerPrefix,
	}
	return worker
}
