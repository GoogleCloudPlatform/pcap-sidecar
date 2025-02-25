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

//go:build json

package transformer

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Jeffail/gabs/v2"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/pkg/errors"
	"github.com/segmentio/fasthash/fnv1a"
	"github.com/wissance/stringFormatter"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/alphadose/haxmap"
	mapset "github.com/deckarep/golang-set/v2"
)

type (
	JSONPcapTranslator struct {
		fm                        *flowMutex
		iface                     *PcapIface
		ephemerals                *PcapEmphemeralPorts
		traceToHttpRequestMap     *haxmap.Map[string, *httpRequest]
		flowToStreamToSequenceMap FTSTSM
	}
)

const (
	jsonTranslationSummary          = "#:{serial} | @:{ifaceIndex}/{ifaceName} | flow:{flowID} | "
	jsonTranslationSummaryWithoutL4 = jsonTranslationSummary + "{L3Src} > {L3Dst}"
	jsonTranslationSummaryICMP      = jsonTranslationSummary + "ICMPv{icmpVersion} | {L3Src} > {L3Dst} | {icmpMessage}"
	jsonTranslationSummaryUDP       = jsonTranslationSummary + "{L4Proto} | {srcProto}/{L3Src}:{L4Src} > {dstProto}/{L3Dst}:{L4Dst}"
	jsonTranslationSummaryTCP       = jsonTranslationSummaryUDP + " | [{tcpFlags}] | len/seq/ack:{tcpLen}/{tcpSeq}/{tcpAck}"
	jsonTranslationFlowTemplate     = "{0}/iface/{1}/flow/{2}:{3}"
)

func init() {
	translators.Store(JSON, newJSONPcapTranslator)
}

func (t *JSONPcapTranslator) translate(_ *gopacket.Packet) error {
	return fmt.Errorf("not implemented")
}

func (t *JSONPcapTranslator) done(ctx context.Context) {
	t.fm.MutexMap.ForEach(func(flowID uint64, lock *flowLockCarrier) bool {
		if lock.mu.TryLock() {
			t.fm.untrackConnection(ctx, &flowID, lock)
			transformerLogger.Printf("[%d/%s] – untracked flow: %d\n", t.iface.Index, t.iface.Name, flowID)
			lock.mu.Unlock()
		}
		return true
	})
	t.fm.MutexMap.Clear()
	t.flowToStreamToSequenceMap.Clear()
	t.traceToHttpRequestMap.Clear()
}

// return pointer to `struct` `gabs.Container`
func (t *JSONPcapTranslator) next(
	ctx context.Context,
	nic *PcapIface,
	serial *uint64,
	packet *gopacket.Packet,
) fmt.Stringer {
	flowID := fnv1a.AddUint64(fnv1a.Init64, uint64(t.iface.Index))
	flowIDstr := strconv.FormatUint(flowID, 10)

	json := gabs.New()

	id := ctx.Value(ContextID)
	logName := ctx.Value(ContextLogName)

	pcap, _ := json.Object("pcap")
	pcap.Set(id, "id")
	pcap.Set(logName, "ctx")

	serialStr := strconv.FormatUint(*serial, 10)
	pcap.Set(serialStr, "num")

	metadata := (*packet).Metadata()
	info := metadata.CaptureInfo

	meta, _ := json.Object("meta")
	meta.Set(metadata.Truncated, "trunc")
	meta.Set(info.Length, "len")
	meta.Set(info.CaptureLength, "cap_len")
	meta.Set(flowIDstr, "flow")
	meta.Set(info.Timestamp.Format(time.RFC3339Nano), "timestamp")

	timestamp, _ := json.Object("timestamp")
	timestamp.Set(info.Timestamp.Unix(), "seconds")
	timestamp.Set(info.Timestamp.Nanosecond(), "nanos")

	netIface := *nic
	iface, _ := json.Object("iface")
	iface.Set(netIface.Index, "index")
	iface.Set(netIface.Name, "name")
	if sizeOfAddrs := nic.Addrs.Cardinality(); sizeOfAddrs > 0 {
		addrs, _ := iface.ArrayOfSize(sizeOfAddrs, "addrs")
		netIface.Addrs.Each(func(IP string) bool {
			sizeOfAddrs -= 1
			addrs.SetIndex(IP, sizeOfAddrs)
			return false
		})
	}

	labels, _ := json.Object("logging.googleapis.com/labels")
	labels.Set("pcap", "run.googleapis.com/tool")
	labels.Set(id, "run.googleapis.com/pcap/id")
	labels.Set(logName, "run.googleapis.com/pcap/name")
	labels.Set(t.iface.Name, "run.googleapis.com/pcap/iface")

	return json
}

func (t *JSONPcapTranslator) asTranslation(buffer fmt.Stringer) *gabs.Container {
	if buffer == nil {
		return nil
	}
	return buffer.(*gabs.Container)
}

func newError(
	ctx context.Context,
	err error,
) (fmt.Stringer, *gabs.Container) {
	json := gabs.New()

	errors, _ := json.ArrayOfSize(1, "err")

	errJSON, _ := errors.ObjectI(0)
	errJSON.Set(err.Error(), "msg")

	json.Set("severity", "ERROR")

	// return only the error for caller to hydrate.
	return json, errJSON
}

func (t *JSONPcapTranslator) translateErrorLayer(
	ctx context.Context,
	err *gopacket.DecodeFailure,
) fmt.Stringer {
	json, errJSON := newError(ctx, err.Error())
	errJSON.Set(err.Dump(), "trace")
	return json
}

func (t *JSONPcapTranslator) translateLayerError(
	ctx context.Context,
	lType gopacket.LayerType,
	err error,
) fmt.Stringer {
	json, errJSON := newError(ctx, err)
	errJSON.Set(lType.String(), "layer")
	return json
}

func (t *JSONPcapTranslator) translateError(
	ctx context.Context,
	err error,
) fmt.Stringer {
	json, _ := newError(ctx, err)
	return json
}

func (t *JSONPcapTranslator) translateEthernetLayer(ctx context.Context, eth *layers.Ethernet) fmt.Stringer {
	json := gabs.New()

	L2, _ := json.Object("L2")
	L2.Set(eth.EthernetType.String(), "type")
	L2.Set(eth.SrcMAC.String(), "src")
	L2.Set(eth.DstMAC.String(), "dst")

	return json
}

func (t *JSONPcapTranslator) translateARPLayer(ctx context.Context, arp *layers.ARP) fmt.Stringer {
	json := gabs.New()

	arpJSON, _ := json.Object("ARP")

	arpJSON.Set(arp.Operation, "op")

	var ipBytes [4]byte

	copy(ipBytes[:], arp.SourceProtAddress)
	ip4 := netip.AddrFrom4(ipBytes)
	mac := net.HardwareAddr(arp.SourceHwAddress[:])

	srcJSON, _ := arpJSON.Object("src")
	srcJSON.Set(ip4.String(), "IP")
	srcJSON.Set(mac.String(), "MAC")

	copy(ipBytes[:], arp.DstProtAddress)
	ip4 = netip.AddrFrom4(ipBytes)
	mac = net.HardwareAddr(arp.DstHwAddress[:])

	dstJSON, _ := arpJSON.Object("dst")
	dstJSON.Set(ip4.String(), "IP")
	dstJSON.Set(mac.String(), "MAC")

	flowID := fnv1a.HashUint64(fnv1a.HashBytes64(arp.SourceProtAddress) + fnv1a.HashBytes64(arp.DstProtAddress))
	flowIDstr := strconv.FormatUint(flowID, 10)
	arpJSON.Set(flowIDstr, "flow")

	return json
}

func (t *JSONPcapTranslator) addEndpoints(
	json *gabs.Container,
	flow *gopacket.Flow,
) {
	flows, _ := json.Object("endpoints")

	flows.Set(flow.Src().String(), "src")
	flows.Set(flow.Dst().String(), "dst")
	flows.Set(flow.String(), "fwd")
	flows.Set(flow.Reverse().String(), "bwd")
	flows.Set(strconv.FormatUint(flow.FastHash(), 10), "hash")
}

func (t *JSONPcapTranslator) translateIPv4Layer(
	ctx context.Context,
	ip4 *layers.IPv4,
) fmt.Stringer {
	json := gabs.New()

	// https://github.com/google/gopacket/blob/master/layers/ip4.go#L43

	L3, _ := json.Object("L3")

	networkFlow := ip4.NetworkFlow()
	t.addEndpoints(L3, &networkFlow)

	L3.Set(ip4.Version, "v")
	L3.Set(ip4.SrcIP, "src")
	L3.Set(ip4.DstIP, "dst")
	L3.Set(ip4.Id, "id")
	L3.Set(ip4.IHL, "ihl")
	L3.Set(ip4.TTL, "ttl")
	L3.Set(ip4.TOS, "tos")
	L3.Set(ip4.Length, "len")
	L3.Set(ip4.FragOffset, "foff")
	L3.Set(ip4.Checksum, "xsum")

	opts, _ := L3.ArrayOfSize(len(ip4.Options), "opts")
	for i, opt := range ip4.Options {
		o, _ := opts.ObjectI(i)
		o.Set(string(opt.OptionData), "data")
		o.Set(opt.OptionType, "type")
	}

	proto, _ := L3.Object("proto")
	proto.Set(ip4.Protocol, "num")
	proto.Set(ip4.Protocol.String(), "name")
	// https://github.com/google/gopacket/blob/master/layers/ip4.go#L28-L40
	L3.SetP(strings.Split(ip4.Flags.String(), "|"), "flags")

	// hashing bytes yields `uint64`, and addition is commutative:
	//   - so hashing the IP byte array representations and then adding then resulting `uint64`s is a commutative operation as well.
	flowID := fnv1a.HashUint64(uint64(4) + fnv1a.HashBytes64(ip4.SrcIP.To4()) + fnv1a.HashBytes64(ip4.DstIP.To4()))
	flowIDstr := strconv.FormatUint(flowID, 10)
	L3.Set(flowIDstr, "flow") // IPv4(4) (0x04)

	return json
}

func (t *JSONPcapTranslator) translateIPv6Layer(
	ctx context.Context,
	ip6 *layers.IPv6,
) fmt.Stringer {
	json := gabs.New()

	// https://github.com/google/gopacket/blob/master/layers/ip6.go#L28-L43

	L3, _ := json.Object("L3")

	networkFlow := ip6.NetworkFlow()
	t.addEndpoints(L3, &networkFlow)

	L3.Set(ip6.Version, "v")
	L3.Set(ip6.SrcIP, "src")
	L3.Set(ip6.DstIP, "dst")
	L3.Set(ip6.Length, "len")
	L3.Set(ip6.TrafficClass, "cls")
	L3.Set(ip6.FlowLabel, "lbl")
	L3.Set(ip6.HopLimit, "ttl")

	proto, _ := L3.Object("proto")
	proto.Set(ip6.NextHeader, "num")
	proto.Set(ip6.NextHeader.String(), "name")

	// hashing bytes yields `uint64`, and addition is commutative:
	//   - so hashing the IP byte array representations and then adding then resulting `uint64`s is a commutative operation as well.
	flowID := fnv1a.HashUint64(uint64(41) + fnv1a.HashBytes64(ip6.SrcIP.To16()) + fnv1a.HashBytes64(ip6.DstIP.To16()))
	flowIDstr := strconv.FormatUint(flowID, 10)
	L3.Set(flowIDstr, "flow") // IPv6(41) (0x29)

	// missing `HopByHop`: https://github.com/google/gopacket/blob/master/layers/ip6.go#L40
	return json
}

func (t *JSONPcapTranslator) translateICMPv4Layer(ctx context.Context, icmp4 *layers.ICMPv4) fmt.Stringer {
	// see: https://github.com/google/gopacket/blob/master/layers/icmp4.go#L208-L215

	json := gabs.New()

	ICMP4, _ := json.Object("ICMP")

	ICMP4.Set(icmp4.TypeCode.Type(), "type")
	ICMP4.Set(icmp4.TypeCode.Code(), "code")
	ICMP4.Set(icmp4.Checksum, "xsum")

	// see: https://github.com/google/gopacket/blob/master/layers/icmp4.go#L78-L153
	ICMP4.Set(icmp4.TypeCode.String(), "msg")

	switch icmp4.TypeCode.Type() {
	case layers.ICMPv4TypeEchoRequest, layers.ICMPv4TypeEchoReply:
		ICMP4.Set(icmp4.Id, "id")
		ICMP4.Set(icmp4.Seq, "seq")
	case layers.ICMPv4TypeTimeExceeded, layers.ICMPv4TypeDestinationUnreachable, layers.ICMPv4TypeRedirect:
		IPv4, _ := ICMP4.Object("IPv4")

		// original IPv4 header starts from offset 8
		// reference:
		//   - https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Time_exceeded
		//   - https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Destination_unreachable
		ipHeader := icmp4.LayerPayload()

		IPv4.Set(binary.BigEndian.Uint16(ipHeader[4:6]), "id")
		IPv4.Set(uint8(ipHeader[8]), "ttl")
		IPv4.Set(uint8(ipHeader[9]), "proto")
		IPv4.Set(binary.BigEndian.Uint16(ipHeader[10:12]), "xsum")

		// IP addresses are represented as bigendian []byte slices in Go
		var ipBytes [4]byte

		copy(ipBytes[:], ipHeader[12:16])
		srcIP := netip.AddrFrom4(ipBytes)
		IPv4.Set(srcIP.String(), "src")

		copy(ipBytes[:], ipHeader[16:20])
		dstIP := netip.AddrFrom4(ipBytes)
		IPv4.Set(dstIP.String(), "dst")

		if icmp4.TypeCode.Type() == layers.ICMPv4TypeRedirect {
			// see: https://github.com/google/gopacket/blob/master/layers/icmp4.go#L230
			copy(ipBytes[:], icmp4.LayerContents()[4:8])
			ICMP4.Set(netip.AddrFrom4(ipBytes).String(), "tgt")
		}
	}

	return json
}

func (t *JSONPcapTranslator) translateICMPv6Layer(ctx context.Context, icmp6 *layers.ICMPv6) fmt.Stringer {
	// see: https://github.com/google/gopacket/blob/master/layers/icmp6.go#L174-L183

	json := gabs.New()

	ICMP6, _ := json.Object("ICMP")

	ICMP6.Set(icmp6.TypeCode.Type(), "type")
	ICMP6.Set(icmp6.TypeCode.Code(), "code")
	ICMP6.Set(icmp6.Checksum, "xsum")

	ICMP6.Set(icmp6.TypeCode.String(), "msg")

	return json
}

func (t *JSONPcapTranslator) asICMPv6(
	ctx context.Context,
	buffer fmt.Stringer,
) (*gabs.Container, *gabs.Container) {
	var ICMPv6 *gabs.Container

	json := t.asTranslation(buffer)

	if json == nil {
		json = gabs.New()
		ICMPv6, _ = json.Object("ICMP")
	} else if json.Exists("ICMP") {
		ICMPv6 = json.S("ICMP")
	} else {
		ICMPv6, _ = json.Object("ICMP")
	}

	return json, ICMPv6
}

func (t *JSONPcapTranslator) translateICMPv6EchoLayer(
	ctx context.Context, json fmt.Stringer, icmp6 *layers.ICMPv6Echo,
) fmt.Stringer {
	// see: https://github.com/google/gopacket/blob/master/layers/icmp6msg.go#L57-L62

	_json, ICMP6 := t.asICMPv6(ctx, json)

	ICMP6.Set(icmp6.Identifier, "id")
	ICMP6.Set(icmp6.SeqNumber, "seq")

	return _json
}

func (t *JSONPcapTranslator) translateICMPv6RedirectLayer(
	ctx context.Context, json fmt.Stringer, icmp6 *layers.ICMPv6Redirect,
) fmt.Stringer {
	// see: https://github.com/google/gopacket/blob/master/layers/icmp6msg.go#L97-L104

	_json, ICMP6 := t.asICMPv6(ctx, json)

	ICMP6.Set(icmp6.TargetAddress, "tgt")
	ICMP6.Set(icmp6.DestinationAddress, "dst")

	return _json
}

func (t *JSONPcapTranslator) translateICMPv6L3HeaderLayer(
	ctx context.Context, json fmt.Stringer, icmp6 *layers.ICMPv6,
) fmt.Stringer {
	// see: https://github.com/google/gopacket/blob/master/layers/icmp6msg.go#L97-L104

	_json, ICMP6 := t.asICMPv6(ctx, json)

	IPv6, _ := ICMP6.Object("IPv6")

	ipHeader := icmp6.LayerPayload()[4:]

	// IPv6 header 1st 32 bits ( 4 bytes )
	ipHeaderBytes0to3 := binary.BigEndian.Uint32(ipHeader[:4])

	// Version: from bit 0 to 3 ( 4 bits )
	//   - bin mask: 11110000000000000000000000000000
	//   - hex mask: 0xF0000000
	//   - must be shifted 28 positions to the right to discard `TrafficClass` (8 bits) and `FlowLabel` (20 bits)
	version := ipHeaderBytes0to3 & uint32(0xF0000000) >> 28
	IPv6.Set(version, "v")

	// FlowLabel: from bit 12 to 31 ( 20 bits )
	//   - bin mask: 00000000000011111111111111111111
	//   - hex mask: 0x000FFFFF
	flowLabel := ipHeaderBytes0to3 & uint32(0x000FFFFF)
	IPv6.Set(flowLabel, "lbl")

	// TrafficClass: from bit 4 to 11 ( 6+2 bits )
	//   - bin mask: 00001111111100000000000000000000
	//   - hex mask: 0x0FF00000
	//   - must be shifted 20 positions to the right to discard `FlowLabel` bits
	trafficClass := (ipHeaderBytes0to3 & uint32(0x0FF00000)) >> 20
	// The six most-significant bits hold the differentiated services field
	//   - DS field mask: `11111100` or `0xFC`
	//   - must be shifted 2 bits to the right to remove bits from ECN
	IPv6.Set((trafficClass&0xFC)>>2, "dsf")
	// The remaining two bits are used for Explicit Congestion Notification
	//   - ECN mask: `00000011` or `0x03`
	IPv6.Set((trafficClass & 0x03), "ecn")

	// HopLimit (aka TTL): 8 bits, 7th byte
	IPv6.Set(uint32(ipHeader[7]), "ttl")

	var ipBytes [16]byte

	copy(ipBytes[:], ipHeader[8:24])
	srcIP := netip.AddrFrom16(ipBytes)
	IPv6.Set(srcIP.String(), "src")

	copy(ipBytes[:], ipHeader[24:40])
	dstIP := netip.AddrFrom16(ipBytes)
	IPv6.Set(dstIP.String(), "dst")

	nextHeader := uint8(ipHeader[6])
	switch nextHeader {
	default:
		IPv6.Set(nextHeader, "proto")
	case 0x06: // TCP
		IPv6.Set("TCP", "proto")
	case 0x11: // UDP
		IPv6.Set("UDP", "proto")
	}

	return _json
}

func (t *JSONPcapTranslator) translateUDPLayer(ctx context.Context, udp *layers.UDP) fmt.Stringer {
	json := gabs.New()

	// https://github.com/google/gopacket/blob/master/layers/udp.go#L17-L25

	L4, _ := json.Object("L4")

	transportFlow := udp.TransportFlow()
	t.addEndpoints(L4, &transportFlow)

	L4.Set(len(udp.Payload), "size")

	L4.Set(udp.Checksum, "xsum")
	L4.Set(udp.Length, "len")

	L4.Set(udp.SrcPort, "src")
	if name, ok := layers.UDPPortNames[udp.SrcPort]; ok {
		L4.Set(name, "sproto")
	}

	L4.SetP(udp.DstPort, "dst")
	if name, ok := layers.UDPPortNames[udp.DstPort]; ok {
		L4.Set(name, "dproto")
	}

	// UDP(17) (0x11) | `SrcPort` and `DstPort` are `uint8`
	flowID := fnv1a.HashUint64(uint64(17) + uint64(udp.SrcPort) + uint64(udp.DstPort))
	flowIDstr := strconv.FormatUint(flowID, 10)
	L4.Set(flowIDstr, "flow")

	return json
}

func (t *JSONPcapTranslator) addTCPWindowScale(
	tcp *layers.TCP,
	optKey, optHexVal *string,
	optJSON, L4 *gabs.Container,
) {
	winScalePowerOf2, winScaleErr := strconv.ParseUint(*optHexVal, 0, 16)
	if winScaleErr != nil {
		optJSON.ArrayAppend(*optHexVal, *optKey)
		return
	}

	winScaleMultiplier := uint64(2 << (winScalePowerOf2 - 1))
	realWindowSizeStr := strconv.FormatUint(uint64(tcp.Window)*winScaleMultiplier, 10)
	winScale := gabs.New()
	winScale.Set(optHexVal, "hex")
	winScale.Set(winScalePowerOf2, "dec")
	winScale.Set(strconv.FormatUint(winScaleMultiplier, 10), "scale")
	winScale.Set(realWindowSizeStr, "win")

	optJSON.ArrayAppend(winScale, *optKey)
	L4.Set(realWindowSizeStr, "xwin")
}

func (t *JSONPcapTranslator) addTCPOptions(tcp *layers.TCP, L4 *gabs.Container) {
	opts, _ := L4.ArrayOfSize(len(tcp.Options), "opts")
	for i, tcpOpt := range tcp.Options {
		// see: https://github.com/google/gopacket/blob/master/layers/tcp.go#L104C9-L128
		if o := tcpOptionRgx.FindStringSubmatch(tcpOpt.String()); o != nil {
			tcpOptVal := strings.TrimSpace(o[2])

			if tcpOptVal == "" {
				opts.SetIndex(o[1], i)
				continue
			}

			opt, _ := opts.ObjectI(i)
			optKey := strings.TrimSpace(o[1])
			optVals := strings.Split(tcpOptVal, " ")
			opt.Array(optKey)

			for _, optVal := range optVals {
				optVal = strings.TrimSpace(optVal)

				// see: https://github.com/google/gopacket/blob/master/layers/tcp.go#L37-L57
				// [ToDo] – handle: SACK
				if optVal == "" {
					continue
				} else if strings.HasPrefix(optVal, "0x") {
					optHexVal := strings.TrimRight(optVal, "0")
					switch tcpOpt.OptionType {
					case 3: // WindowScale
						t.addTCPWindowScale(tcp, &optKey, &optHexVal, opt, L4)
					default:
						opt.ArrayAppend(optHexVal, optKey)
					}
				} else {
					switch tcpOpt.OptionType {
					case 8: // Timestamps
						for _, ts := range strings.Split(optVal, "/") {
							opt.ArrayAppend(strings.TrimSpace(ts), optKey)
						}
					default:
						opt.ArrayAppend(optVal, optKey)
					}
				}
			}

		}
	}
}

func (t *JSONPcapTranslator) translateTCPLayer(ctx context.Context, tcp *layers.TCP) fmt.Stringer {
	json := gabs.New()

	// https://github.com/google/gopacket/blob/master/layers/tcp.go#L19-L35

	L4, _ := json.Object("L4")

	transportFlow := tcp.TransportFlow()
	t.addEndpoints(L4, &transportFlow)

	L4.Set(strconv.FormatInt(int64(len(tcp.Payload)), 10), "len")

	L4.Set(tcp.Seq, "seq")
	L4.Set(tcp.Ack, "ack")
	L4.Set(tcp.DataOffset, "off")
	L4.Set(tcp.Window, "win")
	L4.Set(tcp.Checksum, "xsum")
	L4.Set(tcp.Urgent, "urg")

	flags, _ := L4.Object("flags")

	flagsMap, _ := flags.Object("map")

	flagsMap.Set(tcp.SYN, "SYN")
	flagsMap.Set(tcp.ACK, "ACK")
	flagsMap.Set(tcp.PSH, "PSH")
	flagsMap.Set(tcp.FIN, "FIN")
	flagsMap.Set(tcp.RST, "RST")
	flagsMap.Set(tcp.URG, "URG")
	flagsMap.Set(tcp.ECE, "ECE")
	flagsMap.Set(tcp.CWR, "CWR")

	flagsMap.Set(tcp.NS, "NS")

	setFlags := parseTCPflags(tcp)
	flags.Set(setFlags, "dec")
	flags.Set("0b"+strconv.FormatUint(uint64(setFlags), 2), "bin")
	flags.Set("0x"+strconv.FormatUint(uint64(setFlags), 16), "hex")

	if flagsStr, ok := tcpFlagsStr[setFlags]; ok {
		flags.Set(flagsStr, "str")
	} else {
		// this scenario is slow, but it should also be exceedingly rare
		flagsStr := make([]string, 0, len(tcpFlags))
		for key := range tcpFlags {
			if isSet, _ := flagsMap.Path(key).Data().(bool); isSet {
				flagsStr = append(flagsStr, key)
			}
		}
		flags.Set(strings.Join(flagsStr, "|"), "str")
	}

	t.addTCPOptions(tcp, L4)

	L4.Set(tcp.SrcPort, "src")
	if name, ok := layers.TCPPortNames[tcp.SrcPort]; ok {
		L4.Set(name, "sproto")
	}

	L4.Set(tcp.DstPort, "dst")
	if name, ok := layers.TCPPortNames[tcp.DstPort]; ok {
		L4.Set(name, "dproto")
	}

	// TCP(6) (0x06) | `SrcPort` and `DstPort` are `uint8`
	flowID := fnv1a.HashUint64(uint64(6) + uint64(tcp.SrcPort) + uint64(tcp.DstPort))
	flowIDstr := strconv.FormatUint(flowID, 10)
	L4.Set(flowIDstr, "flow")

	return json
}

func (t *JSONPcapTranslator) translateTLSLayer(ctx context.Context, tls *layers.TLS) fmt.Stringer {
	json := gabs.New()

	TLS, _ := json.Object("TLS")

	// disabled until memory leak is fixed
	// [TODO]: fix memory leak...
	// t.decodeTLSRecords(1, tls.Contents, TLS)

	if len(tls.ChangeCipherSpec) > 0 {
		t.translateTLSLayer_ChangeCipherSpec(ctx, TLS, tls)
	}

	if len(tls.Handshake) > 0 {
		t.translateTLSLayer_Handshake(ctx, TLS, tls)
	}

	if len(tls.AppData) > 0 {
		t.translateTLSLayer_AppData(ctx, TLS, tls)
	}

	return json
}

func (t *JSONPcapTranslator) translateDNSLayer(ctx context.Context, dns *layers.DNS) fmt.Stringer {
	json := gabs.New()

	domain, _ := json.Object("DNS")
	domain.Set(dns.ID, "id")
	domain.Set(dns.OpCode.String(), "op")
	domain.Set(dns.ResponseCode.String(), "response_code")

	/*
		json.SetP(dns.QR, "DNS.QR")
		json.SetP(dns.AA, "DNS.AA")
		json.SetP(dns.TC, "DNS.TC")
		json.SetP(dns.RD, "DNS.RD")
		json.SetP(dns.RA, "DNS.RA")
	*/

	domain.Set(dns.QDCount, "questions_count")
	domain.Set(dns.ANCount, "answers_count")
	/*
		json.SetP(dns.NSCount, "DNS.authorities_count")
		json.SetP(dns.ARCount, "DNS.additionals_count")
	*/

	questions, _ := domain.ArrayOfSize(len(dns.Questions), "questions")
	for i, question := range dns.Questions {
		q, _ := questions.ObjectI(i)
		q.Set(string(question.Name), "name")
		q.Set(question.Type.String(), "type")
		q.Set(question.Class.String(), "class")
	}

	answers, _ := domain.ArrayOfSize(len(dns.Answers), "answers")
	for i, answer := range dns.Answers {
		a, _ := answers.ObjectI(i)

		// Header
		a.Set(string(answer.Name), "name")
		a.Set(answer.Type.String(), "type")
		a.Set(answer.Class.String(), "class")
		a.Set(answer.TTL, "ttl")

		if answer.IP != nil {
			a.Set(answer.IP.String(), "ip")
		}

		if answer.NS != nil && len(answer.NS) > 0 {
			a.Set(string(answer.NS), "ns")
		}

		if answer.CNAME != nil && len(answer.CNAME) > 0 {
			a.Set(string(answer.CNAME), "cname")
		}

		if answer.PTR != nil && len(answer.PTR) > 0 {
			a.Set(string(answer.PTR), "ptr")
		}

		txts, _ := a.ArrayOfSize(len(answer.TXTs))
		for i, txt := range answer.TXTs {
			txts.SetIndex(string(txt), i)
		}

		soaJSON, _ := a.Object("SOA")
		soaJSON.Set(string(answer.SOA.MName), "mname")
		soaJSON.Set(string(answer.SOA.RName), "rname")
		soaJSON.Set(answer.SOA.Serial, "serial")
		soaJSON.Set(answer.SOA.Expire, "expire")
		soaJSON.Set(answer.SOA.Refresh, "refresh")
		soaJSON.Set(answer.SOA.Retry, "retry")

		srvJSON, _ := a.Object("SRV")
		srvJSON.SetP(string(answer.SRV.Name), "name")
		srvJSON.SetP(answer.SRV.Port, "port")
		srvJSON.SetP(answer.SRV.Weight, "weight")
		srvJSON.SetP(answer.SRV.Priority, "priority")

		/*
			a.SetP(string(answer.MX.Name), "mx.name")
			a.SetP(answer.MX.Preference, "mx.preference")

			a.SetP(string(answer.URI.Target), "uri.target")
			a.SetP(answer.URI.Priority, "uri.priority")
			a.SetP(answer.URI.Weight, "uri.weight")
		*/

		opts, _ := a.ArrayOfSize(len(answer.OPT), "opt")
		for i, opt := range answer.OPT {
			o, _ := opts.ObjectI(i)
			o.Set(opt.Code.String(), "code")
			o.Set(string(opt.Data), "data")
		}
	}

	return json
}

func (t *JSONPcapTranslator) merge(ctx context.Context, tgt fmt.Stringer, src fmt.Stringer) (fmt.Stringer, error) {
	return tgt, t.asTranslation(tgt).Merge(t.asTranslation(src))
}

// for JSON translator, this mmethod generates:
//   - the `flowID` for any 6-tuple conversation
//   - the summary line at {`message`: $summary}
func (t *JSONPcapTranslator) finalize(
	ctx context.Context,
	ifaces netIfaceIndex,
	iface *PcapIface,
	serial *uint64,
	p *gopacket.Packet,
	conntrack bool,
	packet fmt.Stringer,
) (fmt.Stringer, error) {
	json := t.asTranslation(packet)

	data := make(map[string]any, 15)

	id := ctx.Value(ContextID)
	logName := ctx.Value(ContextLogName)

	operation, _ := json.Object("logging.googleapis.com/operation")
	operation.Set(logName, "producer")
	if *serial == 1 {
		operation.Set(true, "first")
	}

	data["ifaceIndex"] = t.iface.Index
	data["ifaceName"] = t.iface.Name

	data["serial"] = *serial

	flowIDstr, _ := json.S("meta", "flow").Data().(string) // this is always available
	flowID, _ := strconv.ParseUint(flowIDstr, 10, 64)

	l3Src, _ := json.S("L3", "src").Data().(net.IP)
	l3Dst, _ := json.S("L3", "dst").Data().(net.IP)

	// handle cases where there is L3 is not available
	if l3Src == nil && l3Dst == nil {
		if json.Exists("ARP") {
			arpSrcIP, _ := json.S("ARP", "src", "IP").Data().(string)
			l3Src = net.ParseIP(arpSrcIP)
			data["L3Src"] = arpSrcIP

			arpDstIP, _ := json.S("ARP", "dst", "IP").Data().(string)
			l3Dst = net.ParseIP(arpDstIP)
			data["L3Dst"] = arpDstIP

			t.checkL3Address(ctx, json, data, ifaces, iface, l3Src, l3Dst)

			if arpFlowIDstr, arpOK := json.S("ASP", "flow").Data().(string); arpOK {
				arpFlowID, _ := strconv.ParseUint(arpFlowIDstr, 10, 64)
				flowID = fnv1a.AddUint64(flowID, arpFlowID)
				flowIDstr = strconv.FormatUint(flowID, 10)

				data["flowID"] = flowIDstr
				json.Set(flowIDstr, "flow")
			}

			operation.Set(stringFormatter.Format(jsonTranslationFlowTemplate, id, t.iface.Name, "arp", flowIDstr), "id")
			json.Set(stringFormatter.FormatComplex(jsonTranslationSummaryWithoutL4, data), "message")

			return json, nil
		}

		operation.Set(stringFormatter.Format(jsonTranslationFlowTemplate, id, t.iface.Name, "l2", flowIDstr), "id")
		json.Set(stringFormatter.FormatComplex(jsonTranslationSummary, data), "message")

		return json, nil
	}

	data["L3Src"] = l3Src
	data["L3Dst"] = l3Dst

	// report complete interface details when capturing for `any` interface
	t.checkL3Address(ctx, json, data, ifaces, iface, l3Src, l3Dst)

	isSrcLocal := iface.Addrs.Contains(l3Src.String())

	proto := json.S("L3", "proto", "num").Data().(layers.IPProtocol)
	isTCP := proto == layers.IPProtocolTCP
	isUDP := proto == layers.IPProtocolUDP
	isICMPv4 := proto == layers.IPProtocolICMPv4
	isICMPv6 := proto == layers.IPProtocolICMPv6

	// `flowID` is the unique ID of this conversation:
	// given by the 6-tuple: iface_index+protocol+src_ip+src_port+dst_ip+dst_port.
	// Addition is commutative, so after hashing `net.IP` bytes and L4 ports to `uint64`,
	// the same `uint64`/`flowID` is produced after adding everything up, no matter the order.
	// Using the same `flowID` will produce grouped logs in Cloud Logging.
	if l3FlowIDstr, l3OK := json.S("L3", "flow").Data().(string); l3OK {
		l3FlowID, _ := strconv.ParseUint(l3FlowIDstr, 10, 64)
		flowID = fnv1a.AddUint64(flowID, l3FlowID)
	}
	if l4FlowIDstr, l4OK := json.S("L4", "flow").Data().(string); l4OK {
		l4FlowID, _ := strconv.ParseUint(l4FlowIDstr, 10, 64)
		flowID = fnv1a.AddUint64(flowID, l4FlowID)
	} else {
		flowID = fnv1a.AddUint64(flowID, 255) // RESERVED (0xFF)
	}
	flowIDstr = strconv.FormatUint(flowID, 10)

	data["flowID"] = flowIDstr
	json.Set(flowIDstr, "flow")

	if !isTCP && !isUDP {
		if isICMPv4 || isICMPv6 {
			if isICMPv6 {
				data["icmpVersion"] = 6
			} else {
				data["icmpVersion"] = 4
			}
			data["icmpMessage"] = json.S("ICMP", "msg").Data().(string)

			operation.Set(stringFormatter.Format(jsonTranslationFlowTemplate, id, t.iface.Name, "icmp", flowIDstr), "id")
			json.Set(stringFormatter.FormatComplex(jsonTranslationSummaryICMP, data), "message")

			return json, nil
		}

		// unhandled L3 protocol
		operation.Set(stringFormatter.Format(jsonTranslationFlowTemplate, id, t.iface.Name, "l3", flowIDstr), "id")
		json.Set(stringFormatter.FormatComplex(jsonTranslationSummaryWithoutL4, data), "message")

		return json, nil
	}

	l4SrcProto, _ := json.S("L4", "sproto").Data().(string)
	data["srcProto"] = l4SrcProto

	l4DstProto, _ := json.S("L4", "dproto").Data().(string)
	data["dstProto"] = l4DstProto

	if isUDP {
		data["L4Proto"] = "UDP"
		srcPort, _ := json.S("L4", "src").Data().(layers.UDPPort)
		data["L4Src"] = uint16(srcPort)
		dstPort, _ := json.S("L4", "dst").Data().(layers.UDPPort)
		data["L4Dst"] = uint16(dstPort)

		isSrcLocal = isSrcLocal && !t.ephemerals.isEphemeralUDPPort(&srcPort)
		json.Set(isSrcLocal, "local")

		operation.Set(stringFormatter.Format(jsonTranslationFlowTemplate, id, t.iface.Name, "udp", flowIDstr), "id")
		json.Set(stringFormatter.FormatComplex(jsonTranslationSummaryUDP, data), "message")
		return json, nil
	}

	data["L4Proto"] = "TCP"
	srcPort, _ := json.S("L4", "src").Data().(layers.TCPPort)
	data["L4Src"] = uint16(srcPort)
	dstPort, _ := json.S("L4", "dst").Data().(layers.TCPPort)
	data["L4Dst"] = uint16(dstPort)

	setFlags, _ := json.S("L4", "flags", "dec").Data().(uint8)
	data["tcpFlags"] = json.S("L4", "flags", "str").Data().(string)

	seq, _ := json.S("L4", "seq").Data().(uint32)
	data["tcpSeq"] = seq
	ack, _ := json.S("L4d", "ack").Data().(uint32)
	data["tcpAck"] = ack
	tcpLen, _ := json.S("L4", "len").Data().(string)
	data["tcpLen"] = tcpLen

	operation.Set(stringFormatter.Format(jsonTranslationFlowTemplate, id, t.iface.Name, "tcp", flowIDstr), "id")

	message := stringFormatter.FormatComplex(jsonTranslationSummaryTCP, data)

	// local means: a service running within the sandbox
	//   - so it is not a client which created a socket to communicate with a remote host using an ephemeral port
	// this approach is best effort as a client may use a `not ephemeral port` to create a socket for egress networking.
	isSrcLocal = isSrcLocal && !t.ephemerals.isEphemeralTCPPort(&srcPort)
	json.Set(isSrcLocal, "local")

	// `finalize` is invoked from a `worker` via a go-routine `pool`:
	//   - there are no guarantees about which packet will get `finalize`d 1st
	//   - there are no guarantees about about which packet will get the `lock` next
	// minimize locking: lock per-flow instead of across-flows.
	// Locking is done in the name of throubleshoot-ability, so some contention at the flow level should be acceptable...
	lock, traceAndSpanProvider := t.fm.lock(ctx, serial, &flowID, &setFlags, &seq, &ack, isSrcLocal)

	if conntrack {
		t.analyzeConnection(p, &flowID, &setFlags, json)
	}

	appLayer := (*p).ApplicationLayer()
	if ((tcpSyn|tcpFin|tcpRst)&setFlags == 0) && appLayer != nil {
		return t.addAppLayerData(ctx, p, lock, &flowID, &setFlags, &seq, &appLayer, json, &message, traceAndSpanProvider)
	}

	if !lock.IsHTTP2() {
		// most ingress traffic is HTTP/1.1 , so:
		//   - try to get trace tracking information using h1 stream id
		streamID := http11StreamID
		if ts, ok := traceAndSpanProvider(&streamID); ok {
			t.setTraceAndSpan(json, ts)
		}
	}

	json.Set(message, "message")

	// packet is not carrying any data, unlock using TCP flags
	_, lockLatency := lock.UnlockWithTCPFlags(ctx, &setFlags)
	json.Set(lockLatency.String(), "ll")

	return json, nil
}

func (t *JSONPcapTranslator) checkL3Address(
	ctx context.Context,
	json *gabs.Container,
	data map[string]any,
	ifaces netIfaceIndex,
	iface *PcapIface,
	srcIP, dstIP net.IP,
) {
	if iface.Index != 0 {
		return
	}

	// O(1) interface lookups by IP
	_iface, ok := ifaces[srcIP.String()]
	if !ok {
		_iface, ok = ifaces[dstIP.String()]
	}

	if !ok {
		// this should never happen
		return
	}

	data["ifaceIndex"] = _iface.Index
	data["ifaceName"] = _iface.Name

	ifaceJSON := json.S("iface")

	ifaceJSON.Set(_iface.Index, "index")
	ifaceJSON.Set(_iface.Name, "name")

	if sizeOfAddrs := _iface.Addrs.Cardinality(); sizeOfAddrs > 0 {
		addrs, _ := ifaceJSON.ArrayOfSize(sizeOfAddrs, "addrs")
		_iface.Addrs.Each(func(IP string) bool {
			sizeOfAddrs -= 1
			addrs.SetIndex(IP, sizeOfAddrs)
			return false
		})
	}
}

func (t *JSONPcapTranslator) analyzeConnection(
	_ *gopacket.Packet,
	_ *uint64, /* flowID */
	_ *uint8, /* TCP flags */
	_ *gabs.Container, /* JSON object */
) {
	// implement connection tracking
}

func (t *JSONPcapTranslator) addAppLayerData(
	ctx context.Context,
	packet *gopacket.Packet,
	lock *flowLock,
	flowID *uint64,
	tcpFlags *uint8,
	sequence *uint32,
	appLayer *gopacket.ApplicationLayer,
	json *gabs.Container,
	message *string,
	tsp TraceAndSpanProvider,
) (*gabs.Container, error) {
	appLayerData := (*appLayer).LayerContents()

	sizeOfAppLayerData := len(appLayerData)
	if sizeOfAppLayerData == 0 {
		_, lockLatency := lock.UnlockWithTCPFlags(ctx, tcpFlags)
		json.Set(lockLatency.String(), "ll")
		return json, errors.New("AppLayer is empty")
	}

	if L7, handled, isHTTP2 := t.trySetHTTP(ctx, packet, lock, flowID,
		tcpFlags, sequence, appLayerData, json, message, tsp); handled {
		// this `size` is not the same as `length`:
		//   - `size` includes everything, not only the HTTP `payload`
		L7.Set(sizeOfAppLayerData, "size")
		// HTTP/2.0 is binary so not showing it raw
		if !isHTTP2 && sizeOfAppLayerData > 512 {
			L7.Set(string(appLayerData[:512-3])+"...", "raw")
		} else if !isHTTP2 {
			L7.Set(string(appLayerData), "raw")
		}
		return json, nil
	}

	// best-effort to add some information about L7
	json.Set(stringFormatter.Format("{0} | size:{1}",
		*message, sizeOfAppLayerData), "message")

	L7, _ := json.Object("L7")
	L7.Set(sizeOfAppLayerData, "length")

	if sizeOfAppLayerData > 128 {
		L7.Set(string(appLayerData[:128-3])+"...", "sample")
	} else {
		L7.Set(string(appLayerData), "content")
	}

	_, lockLatency := lock.UnlockWithTCPFlags(ctx, tcpFlags)
	json.Set(lockLatency.String(), "ll")

	return json, nil
}

func (t *JSONPcapTranslator) trySetHTTP(
	ctx context.Context,
	packet *gopacket.Packet,
	lock *flowLock,
	flowID *uint64,
	tcpFlags *uint8,
	sequence *uint32,
	appLayerData []byte,
	json *gabs.Container,
	message *string,
	tsp TraceAndSpanProvider,
) (*gabs.Container, bool /* handled */, bool /* isHTTP2 */) {
	isHTTP11Request := http11RequestPayloadRegex.Match(appLayerData)
	isHTTP11Response := !isHTTP11Request && http11ResponsePayloadRegex.Match(appLayerData)

	isHTTP2 := !isHTTP11Request && !isHTTP11Response && http2PrefaceRegex.Match(appLayerData)
	framer := http2.NewFramer(io.Discard, bytes.NewReader(appLayerData))
	frame, frameErr := framer.ReadFrame()

	// if content is not HTTP in clear text, abort
	if !isHTTP11Request && !isHTTP11Response && !isHTTP2 && frame == nil {
		return json, false, false
	}

	// SETs are used to avoid duplicates
	streams := mapset.NewThreadUnsafeSet[uint32]()
	requestStreams := mapset.NewThreadUnsafeSet[uint32]()
	responseStreams := mapset.NewThreadUnsafeSet[uint32]()
	dataStreams := mapset.NewThreadUnsafeSet[uint32]()
	requestTS := make(map[uint32]*traceAndSpan)
	responseTS := make(map[uint32]*traceAndSpan)

	// making at least 1 big assumption:
	//   HTTP request/status line and headers fit in 1 packet ( TCP segment )
	//     which is not always the case when fragmentation occurs
	L7, _ := json.Object("HTTP")

	defer func() {
		var lockLatency *time.Duration = nil
		if requestStreams.Cardinality() > 0 ||
			responseStreams.Cardinality() > 0 {
			_, lockLatency = lock.UnlockWithTraceAndSpan(
				ctx, tcpFlags, isHTTP2,
				requestStreams.ToSlice(),
				responseStreams.ToSlice(),
				requestTS, responseTS,
			)
		} else {
			_, lockLatency = lock.UnlockWithTCPFlags(ctx, tcpFlags)
		}
		json.Set(lockLatency.String(), "ll")
	}()

	if isHTTP2 {
		L7.Set(true, "preface")
		h2cData := http2PrefaceRegex.ReplaceAll(appLayerData, nil)
		if len(h2cData) == 0 {
			L7.Set("h2c", "proto")
			L7.Set(string(appLayerData), "raw")
			return L7, true, true
		}
		framer = http2.NewFramer(io.Discard, bytes.NewReader(h2cData))
		frame, frameErr = framer.ReadFrame()
	}

	isHTTP2 = (isHTTP2 || frame != nil)

	// handle h2c traffic
	if isHTTP2 {
		L7.Set("h2c", "proto")
		streamsJSON, _ := L7.Object("streams")

		// multple h2 frames ( from multiple streams ) may be delivered by the same packet
		for frame != nil {

			isRequest := false
			isResponse := false

			frameHeader := frame.Header()

			// h2 is multiplexed, `StreamID` allows to link HTTP conversations
			//   - see: https://datatracker.ietf.org/doc/html/rfc9113#name-stream-identifiers
			//     - Streams initiated by a client MUST use odd-numbered stream identifiers
			//     - Streams initiated by the server MUST use even-numbered stream identifiers
			//     - A stream identifier of zero (0x00) is used for connection control messages
			//     - Stream identifiers cannot be reused.
			// A stream is equal to a single HTTP conversation: request and response.
			StreamID := frameHeader.StreamID
			StreamIDstr := strconv.FormatUint(uint64(StreamID), 10)
			streams.Add(StreamID)

			ts, traced := tsp(&StreamID)

			var stream, frames *gabs.Container
			if stream = streamsJSON.S(StreamIDstr); stream == nil {
				stream, _ = streamsJSON.Object(StreamIDstr)
				_, _ = stream.Array("frames")
				stream.Set(StreamID, "id")
			} else if frames = stream.S("frames"); frames == nil {
				_, _ = stream.Array("frames")
			}

			frameJSON := gabs.New()
			stream.ArrayAppend(frameJSON, "frames")

			if m := http2RawFrameRegex.
				FindStringSubmatch(frameHeader.String()); len(m) > 0 {
				frameJSON.Set(m[1], "raw")
			}

			sizeOfFrame := frameHeader.Length /* uint32 */
			frameJSON.Set(sizeOfFrame, "len")

			// see: https://pkg.go.dev/golang.org/x/net/http2#Flags
			flagsJSON, _ := frameJSON.Object("flags")
			flagsJSON.Set("0b"+strconv.FormatUint(uint64(frameHeader.Flags /* uint8 */), 2), "bin")
			flagsJSON.Set("0x"+strconv.FormatUint(uint64(frameHeader.Flags /* uint8 */), 16), "hex")
			flagsJSON.Set(strconv.FormatUint(uint64(frameHeader.Flags /* uint8 */), 10), "dec")

			var _ts *traceAndSpan = nil

			switch frame := frame.(type) {
			case *http2.GoAwayFrame:
				frameJSON.Set("goaway", "type")

			case *http2.RSTStreamFrame:
				frameJSON.Set("rst", "type")

			case *http2.PingFrame:
				frameJSON.Set("ping", "type")
				frameJSON.Set(frame.IsAck(), "ack")
				frameJSON.Set(string(frame.Data[:]), "data")

			case *http2.SettingsFrame:
				frameJSON.Set("settings", "type")
				settings, _ := frameJSON.Object("settings")
				frame.ForeachSetting(func(s http2.Setting) error {
					// see: https://pkg.go.dev/golang.org/x/net/http2#SettingID
					settings.Set(strconv.FormatUint(uint64(s.Val), 10),
						"0x"+strconv.FormatUint(uint64(s.ID), 16))
					return nil
				})
				frameJSON.Set(frame.IsAck(), "ack")

			case *http2.HeadersFrame:
				frameJSON.Set("headers", "type")
				decoder := hpack.NewDecoder(2048, nil)
				hf, _ := decoder.DecodeFull(frame.HeaderBlockFragment())
				headers := http.Header{}
				for _, header := range hf {
					isRequest = (isRequest || (header.Name == ":method"))
					isResponse = (isResponse || (header.Name == ":status"))
					// `Add(...)` internally applies `http.CanonicalHeaderKey(...)`
					headers.Add(header.Name, header.Value)
				}
				decoder.Close()
				if _ts = t.addHTTPHeaders(frameJSON, &headers); _ts != nil {
					_ts.streamID = &StreamID
					if isRequest {
						requestTS[StreamID] = _ts
					} else if isResponse {
						responseTS[StreamID] = _ts
					}
				} else if traced && isResponse {
					responseTS[StreamID] = ts
				}

			case *http2.MetaHeadersFrame:
				frameJSON.Set("metadata", "type")
				mdJSON, _ := frameJSON.Object("metadata")
				for _, md := range frame.Fields {
					mdJSON.Set(md.Value, md.Name)
				}

			case *http2.DataFrame:
				dataStreams.Add(StreamID)
				frameJSON.Set("data", "type")
				data := frame.Data()
				sizeOfData := int64(sizeOfFrame)
				t.addHTTPBodyDetails(frameJSON, &sizeOfData, bytes.NewReader(data))
			}

			if isRequest {
				requestStreams.Add(StreamID)
				frameJSON.Set("request", "kind")
			} else if isResponse {
				responseStreams.Add(StreamID)
				frameJSON.Set("response", "kind")
			}

			// multiple streams with frames for req/res
			// might arrive within the same TCP segment
			if _ts != nil {
				t.setTraceAndSpan(frameJSON, _ts)
			} else if traced {
				t.setTraceAndSpan(frameJSON, ts)
			}

			// read next frame
			frame, frameErr = framer.ReadFrame()
		}

		if frameErr != nil && frameErr != io.EOF && frameErr != io.ErrUnexpectedEOF {
			errorJSON, _ := L7.Object("error")
			errorJSON.Set("INVALID_HTTP2_FRAME", "code")
			errorJSON.Set(frameErr.Error(), "info")
		}

		streamsJSONbytes, err := streams.MarshalJSON()
		if err == nil {
			L7.Set(string(streamsJSONbytes), "includes")
		} else {
			L7.Set(streams.ToSlice(), "includes")
		}

		sizeOfStreams := streams.Cardinality()
		if (sizeOfStreams == 1 && streams.Contains(0)) || sizeOfStreams > 10 {
			json.Set(stringFormatter.Format("{0} | {1}", *message, "h2c"), "message")
		} else {
			json.Set(stringFormatter.Format("{0} | {1} | streams:{2} | req:{3} | res:{4} | data:{5}", *message, "h2c",
				streams.ToSlice(), requestStreams.ToSlice(), responseStreams.ToSlice(), dataStreams.ToSlice()), "message")
		}

		return L7, true, true
	}

	// HTTP/1.1 is not multiplexed, so `StreamID` is always `1`
	StreamID := http11StreamID
	ts, traced := tsp(&StreamID)

	streams.Add(StreamID)

	fragmented := false // stop tracking is the default behavior
	defer func() {
		// some HTTP Servers split headers and body by flushing immediately after headers,
		// so if this packet is carrying an HTTP Response, stop trace-tracking if:
		//   - the packet contains the full HTTP Response body, or more specifically:
		//     - if the `Content-Length` header value is equal to the observed `size-of-payload`:
		//       - which means that the HTTP Response is not fragmented.
		L7.Set(fragmented, "fragmented")
	}()

	// L7 is a quasi-RAW representation of the HTTP message.
	// see: https://www.rfc-editor.org/rfc/rfc7540#section-8.1.3
	dataBytes := bytes.SplitN(appLayerData, http11BodySeparator, 2)
	// `parts` is everything before HTTP payload separator (`2*line-break`)
	//   - it includes: the HTTP line, and HTTP headers
	parts := bytes.Split(dataBytes[0], http11Separator)
	meta, _ := json.Object("L7") // `parts[0]` is the HTTP/1.1 preface
	meta.Set("HTTP", "proto")
	meta.Set(string(parts[0]), "preface")
	metaHeaders, _ := meta.ArrayOfSize(len(parts)-1, "headers")
	// HTTP headers starts at `parts[1]`
	for i, header := range parts[1:] {
		if len(header) > 128 {
			metaHeaders.SetIndex(string(header[:128-3]), i)
		} else if len(header) > 0 {
			metaHeaders.SetIndex(string(header), i)
		} else {
			metaHeaders.SetIndex("<EMPTY>", i)
		}
	}
	if len(dataBytes) > 1 {
		parts = bytes.Split(dataBytes[1], http11Separator)
		body, _ := meta.ArrayOfSize(len(parts), "body")
		for i, line := range parts {
			if len(line) > 128 {
				body.SetIndex(string(line[:128-3])+"...", i)
			} else if len(line) > 0 {
				body.SetIndex(string(line), i)
			} else {
				body.SetIndex("<EMPTY>", i)
			}
		}
	}

	httpDataReader := bufio.NewReaderSize(bytes.NewReader(appLayerData), len(appLayerData))

	// attempt to parse HTTP/1.1 request
	if isHTTP11Request {
		requestStreams.Add(StreamID)

		L7.Set("request", "kind")

		request, err := http.ReadRequest(httpDataReader)

		if (err != nil && err != io.EOF && err != io.ErrUnexpectedEOF) || request == nil {
			errorJSON, _ := L7.Object("error")
			errorJSON.Set("INVALID_HTTP11_REQUEST", "code")
			if err != nil {
				errorJSON.Set(err.Error(), "info")
			}
			errorJSON.Set(request != nil, "parsed")

			L7.Set("HTTP/1.1", "proto")

			json.Set(stringFormatter.Format("{0} | {1}: {2}",
				*message, "INVALID_HTTP11_REQUEST", err.Error()), "message")

			return L7, true, false
		}

		url := ""
		if _url := request.URL; _url != nil {
			url = _url.String()
		}

		if url == "" {
			if parts := http11RequestPayloadRegex.
				FindSubmatch(appLayerData); len(parts) >= 3 {
				url = string(parts[2])
				L7.Set(url, "url")
				L7.Set("HTTP/1.1", "proto")
			}
			// abort, not safe to continue,
			// the "quasi-RAW" will tell...
			return L7, true, false
		}

		L7.Set(url, "url")
		L7.Set(request.Proto, "proto")
		L7.Set(request.Method, "method")

		if _ts := t.addHTTPHeaders(L7, &request.Header); _ts != nil {
			_ts.streamID = &StreamID
			requestTS[StreamID] = _ts
			// include trace and span id for traceability
			t.setTraceAndSpan(json, _ts)
			t.recordHTTP11Request(packet, flowID, sequence, _ts, &request.Method, &request.Host, &url)
		}

		sizeOfBody := t.addHTTPBodyDetails(L7, &request.ContentLength, request.Body)
		if sizeOfBody > 0 {
			dataStreams.Add(StreamID)
		}
		if cl, clErr := strconv.ParseUint(request.Header.Get(httpContentLengthHeader), 10, 64); clErr == nil {
			fragmented = cl > sizeOfBody
		}

		json.Set(stringFormatter.Format("{0} | {1} {2} {3}", *message, request.Proto, request.Method, url), "message")

		return L7, true, false
	}

	// attempt to parse HTTP/1.1 response
	if isHTTP11Response {
		responseStreams.Add(StreamID)

		L7.Set("response", "kind")

		// Go's `http` implementation may miss the `Transfer-Encoding` header
		//   - see: https://github.com/golang/go/issues/27061
		response, err := http.ReadResponse(httpDataReader, nil)

		if (err != nil && err != io.EOF && err != io.ErrUnexpectedEOF) || response == nil {
			errorJSON, _ := L7.Object("error")
			errorJSON.Set("INVALID_HTTP11_RESPONSE", "code")
			if err != nil {
				errorJSON.Set(err.Error(), "info")
			}
			errorJSON.Set(response != nil, "parsed")

			L7.Set("HTTP/1.1", "proto")

			json.Set(stringFormatter.Format("{0} | {1}: {2}",
				*message, "INVALID_HTTP11_RESPONSE", err.Error()), "message")

			return L7, true, false
		}

		L7.Set(response.Proto, "proto")
		L7.Set(response.StatusCode, "code")
		L7.Set(response.Status, "status")

		if _ts := t.addHTTPHeaders(L7, &response.Header); _ts != nil {
			_ts.streamID = &StreamID
			responseTS[StreamID] = _ts
			// include trace and span id for traceability
			t.setTraceAndSpan(json, _ts)
			if linkErr := t.linkHTTP11ResponseToRequest(packet, flowID, L7, _ts); linkErr != nil {
				io.WriteString(os.Stderr, linkErr.Error()+"\n")
			}
		} else if traced {
			responseTS[StreamID] = ts
			t.setTraceAndSpan(json, ts)
			t.linkHTTP11ResponseToRequest(packet, flowID, L7, ts)
		}

		sizeOfBody := t.addHTTPBodyDetails(L7, &response.ContentLength, response.Body)
		if sizeOfBody > 0 {
			dataStreams.Add(StreamID)
		}
		if cl, clErr := strconv.ParseUint(response.Header.Get(httpContentLengthHeader), 10, 64); clErr == nil {
			// if content-length is greater than the size of body:
			//   - this HTTP message is fragmented and so there's more to come
			fragmented = cl > sizeOfBody
		}

		json.Set(stringFormatter.Format("{0} | {1} {2}", *message, response.Proto, response.Status), "message")

		return L7, true, false
	}

	return json, true, false
}

func (t *JSONPcapTranslator) addHTTPBodyDetails(L7 *gabs.Container, contentLength *int64, body io.Reader) uint64 {
	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		return uint64(0)
	}

	bodyJSON, _ := L7.Object("body")

	sizeOfBody := uint64(len(bodyBytes))
	bodyLengthJSON, _ := bodyJSON.ArrayOfSize(2, "length")
	bodyLengthJSON.SetIndex(strconv.FormatUint(sizeOfBody, 10), 0)
	bodyLengthJSON.SetIndex(strconv.FormatInt(*contentLength, 10), 1)

	if sizeOfBody > 512 {
		bodyJSON.Set(string(bodyBytes[:512-3])+"...", "sample")
	} else if sizeOfBody > 0 {
		bodyJSON.Set(string(bodyBytes), "data")
	}

	return sizeOfBody
}

func (t *JSONPcapTranslator) recordHTTP11Request(
	packet *gopacket.Packet,
	_ *uint64, /* flowID */
	_ *uint32, /* TCP sequence */
	ts *traceAndSpan,
	method, host, url *string,
) {
	fullURL := stringFormatter.Format("{0}{1}", *host, *url)
	_httpRequest := &httpRequest{
		timestamp: &(*packet).Metadata().Timestamp,
		method:    method,
		url:       &fullURL,
	}
	t.traceToHttpRequestMap.Set(*ts.traceID, _httpRequest)
}

func (t *JSONPcapTranslator) linkHTTP11ResponseToRequest(
	packet *gopacket.Packet,
	_ *uint64, /* flowID */
	response *gabs.Container,
	ts *traceAndSpan,
) error {
	jsonTranslatorRequest, ok := t.traceToHttpRequestMap.Get(*ts.traceID)
	if !ok {
		return errors.New(stringFormatter.Format("no request found for trace-id: {0}", *ts.traceID))
	}

	translatorRequest := *jsonTranslatorRequest
	// hydrate response with information from request
	request, _ := response.Object("request")
	request.Set(*translatorRequest.method, "method")
	request.Set(*translatorRequest.url, "url")
	requestTimestamp := *translatorRequest.timestamp
	responseTimestamp := (*packet).Metadata().Timestamp
	latency := responseTimestamp.Sub(requestTimestamp)
	request.Set(requestTimestamp.Format(time.RFC3339Nano), "timestamp")
	request.Set(latency.Milliseconds(), "latency")

	// intentionally not removing from `traceToHttpRequestMap`:
	//   - it will be done by `untrackConnection` on `RST` or `FIN+ACK`
	//   - allows to link multiple `traceID`s with the same flow
	return nil
}

func (t *JSONPcapTranslator) addHTTPHeaders(L7 *gabs.Container, headers *http.Header) *traceAndSpan {
	jsonHeaders, _ := L7.Object("headers")
	var traceAndSpan *traceAndSpan = nil
	for key, value := range *headers {
		jsonHeaders.Set(value, key)
		for headerStr, headerRgx := range traceAndSpanRegex {
			if strings.EqualFold(key, headerStr) {
				traceAndSpan = t.getTraceAndSpan(headerRgx, &value[0])
			}
		}
	}
	return traceAndSpan
}

func (t *JSONPcapTranslator) getTraceAndSpan(
	headerRgx *regexp.Regexp,
	rawTraceAndSpan *string,
) *traceAndSpan {
	if ts := headerRgx.FindStringSubmatch(*rawTraceAndSpan); ts != nil {
		return &traceAndSpan{traceID: &ts[1], spanID: &ts[2]}
	}
	return nil
}

func (t *JSONPcapTranslator) setTraceAndSpan(json *gabs.Container, ts *traceAndSpan) bool {
	if ts == nil {
		json.Set(false, "logging.googleapis.com/trace_sampled")
		return false
	}

	json.Set(cloudTracePrefix+*ts.traceID, "logging.googleapis.com/trace")
	json.Set(*ts.spanID, "logging.googleapis.com/spanId")
	json.Set(true, "logging.googleapis.com/trace_sampled")

	return true
}

func (t *JSONPcapTranslator) toJSONBytes(packet *fmt.Stringer) (int, []byte, error) {
	translation, err := t.asTranslation(*packet).MarshalJSON()
	if err != nil {
		return 0, nil, errors.Wrap(err, "JSON translation failed")
	}
	lineBreak := []byte("\n")
	b := make([]byte, len(lineBreak)+len(translation))
	return copy(b[copy(b[0:], translation):], lineBreak), b, nil
}

func (t *JSONPcapTranslator) write(ctx context.Context, writer io.Writer, packet *fmt.Stringer) (int, error) {
	bytesCount, translationBytes, err := t.toJSONBytes(packet)
	if err != nil {
		return 0, errors.Wrap(err, "JSON translation failed")
	}
	writtenBytes, err := writer.Write(translationBytes)
	if err != nil {
		return 0, errors.Wrap(err, "failed to write JSON translation")
	}
	if bytesCount != writtenBytes {
		return writtenBytes, errors.New("translationBytes(" + strconv.Itoa(bytesCount) + ") != writtenBytes(" + strconv.Itoa(writtenBytes) + ")")
	}
	return writtenBytes, nil
}

func newJSONPcapTranslator(
	ctx context.Context,
	debug bool,
	iface *PcapIface,
	ephemerals *PcapEmphemeralPorts,
) PcapTranslator {
	flowToStreamToSequenceMap := haxmap.New[uint64, FTSM]()
	traceToHttpRequestMap := haxmap.New[string, *httpRequest]()
	flowMutex := newFlowMutex(ctx, debug, flowToStreamToSequenceMap, traceToHttpRequestMap)

	return &JSONPcapTranslator{
		fm:                        flowMutex,
		iface:                     iface,
		ephemerals:                ephemerals,
		traceToHttpRequestMap:     traceToHttpRequestMap,
		flowToStreamToSequenceMap: flowToStreamToSequenceMap,
	}
}
