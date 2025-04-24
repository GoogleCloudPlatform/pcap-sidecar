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

//go:build proto

package transformer

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/GoogleCloudPlatform/pcap-sidecar/pcap-cli/internal/pb"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type (
	ProtoPcapTranslator struct {
		*pcapTranslator
	}
)

func init() {
	registerTranslatorFactory(PROTO, newPROTOPcapTranslator)
}

func (t *ProtoPcapTranslator) done(_ context.Context) {
	// not implemented
}

func (t *ProtoPcapTranslator) next(
	ctx context.Context,
	nic *PcapIface,
	serial *uint64,
	packet *gopacket.Packet,
) fmt.Stringer {
	// `next` returns the container to be used for merging all layers
	p := &pb.Packet{}

	metadata := (*packet).Metadata()
	info := metadata.CaptureInfo

	p.Timestamp = timestamppb.New(info.Timestamp)

	pcap := p.GetPcap()
	pcap.Context = ctx.Value(ContextID).(string)
	pcap.Serial = *serial

	meta := p.GetMeta()
	meta.Truncated = metadata.Truncated
	meta.Length = uint64(info.Length)
	meta.CaptureLength = uint64(info.CaptureLength)

	iface := p.GetIface()
	iface.Index = uint32(t.iface.Index)
	iface.Name = t.iface.Name

	return p
}

func (t *ProtoPcapTranslator) asTranslation(
	buffer fmt.Stringer,
) *pb.Packet {
	return buffer.(*pb.Packet)
}

func (t *ProtoPcapTranslator) translateErrorLayer(
	ctx context.Context,
	err *gopacket.DecodeFailure,
) fmt.Stringer {
	// [TODO]: implement ERROR layer translation
	p := &pb.Packet{}
	return p
}

func (t *ProtoPcapTranslator) translateLayerError(
	ctx context.Context,
	lType gopacket.LayerType,
	err error,
) fmt.Stringer {
	// [TODO]: implement layer ERROR translation
	p := &pb.Packet{}
	return p
}

func (t *ProtoPcapTranslator) translateError(
	ctx context.Context,
	err error,
) fmt.Stringer {
	// [TODO]: implement ERROR translation
	p := &pb.Packet{}
	return p
}

func (t *ProtoPcapTranslator) translateEthernetLayer(
	ctx context.Context,
	eth *layers.Ethernet,
) fmt.Stringer {
	p := &pb.Packet{}

	L2 := p.GetL2()

	L2.Source = eth.SrcMAC.String()
	L2.Target = eth.DstMAC.String()

	return p
}

func (t *ProtoPcapTranslator) translateARPLayer(
	ctx context.Context,
	arp *layers.ARP,
) fmt.Stringer {
	// [TODO]: implement ARP layer translation
	p := &pb.Packet{}
	return p
}

func (t *ProtoPcapTranslator) translateICMPv4Layer(
	ctx context.Context,
	icmp4 *layers.ICMPv4,
) fmt.Stringer {
	// [TODO]: implement ICMPv4 layer translation
	p := &pb.Packet{}
	return p
}

func (t *ProtoPcapTranslator) translateICMPv6Layer(
	ctx context.Context,
	icmp6 *layers.ICMPv6,
) fmt.Stringer {
	// [TODO]: implement ICMPv6 layer translation
	p := &pb.Packet{}
	return p
}

func (t *ProtoPcapTranslator) translateICMPv6EchoLayer(
	ctx context.Context,
	prto fmt.Stringer,
	icmp6 *layers.ICMPv6Echo,
) fmt.Stringer {
	// see: https://github.com/google/gopacket/blob/master/layers/icmp6msg.go#L57-L62
	// [TODO]: implement ICMPv6 ECHO layer translation
	p := &pb.Packet{}
	return p
}

func (t *ProtoPcapTranslator) translateICMPv6RedirectLayer(
	ctx context.Context,
	json fmt.Stringer,
	icmp6 *layers.ICMPv6Redirect,
) fmt.Stringer {
	// see: https://github.com/google/gopacket/blob/master/layers/icmp6msg.go#L97-L104
	// [TODO]: implement ICMPv6 REDIRECT layer translation
	p := &pb.Packet{}
	return p
}

func (t *ProtoPcapTranslator) translateICMPv6L3HeaderLayer(
	ctx context.Context,
	json fmt.Stringer,
	icmp6 *layers.ICMPv6,
) fmt.Stringer {
	// [TODO]: implement ICMPv6 HEADER layer translation
	p := &pb.Packet{}
	return p
}

func (t *ProtoPcapTranslator) translateIPv4Layer(
	ctx context.Context,
	ip4 *layers.IPv4,
) fmt.Stringer {
	// [TODO]: implement IPv4 layer translation
	p := &pb.Packet{}

	L3 := p.GetIp4()

	L3.Source = ip4.SrcIP
	L3.Target = ip4.DstIP

	return p
}

func (t *ProtoPcapTranslator) translateIPv6Layer(
	ctx context.Context,
	ip6 *layers.IPv6,
) fmt.Stringer {
	// [TODO]: implement IPv6 layer translation
	p := &pb.Packet{}

	L3 := p.GetIp6()

	L3.Source = ip6.SrcIP
	L3.Target = ip6.DstIP

	return p
}

func (t *ProtoPcapTranslator) translateUDPLayer(
	ctx context.Context,
	udp *layers.UDP,
) fmt.Stringer {
	// [TODO]: implement UDP layer translation
	p := &pb.Packet{}

	L4 := p.GetUdp()

	L4.Source = uint32(udp.SrcPort)
	L4.Target = uint32(udp.DstPort)

	return p
}

func (t *ProtoPcapTranslator) translateTCPLayer(
	ctx context.Context,
	tcp *layers.TCP,
) fmt.Stringer {
	// [TODO]: implement TCP layer translation
	p := &pb.Packet{}

	L4 := p.GetTcp()

	L4.Source = uint32(tcp.SrcPort)
	L4.Target = uint32(tcp.DstPort)

	L4.Seq = tcp.Seq
	L4.Ack = tcp.Ack

	flags := L4.GetFlags()

	flags.Flags = uint32(parseTCPflags(tcp))

	flags.Syn = tcp.SYN
	flags.Ack = tcp.ACK
	flags.Psh = tcp.PSH
	flags.Fin = tcp.FIN
	flags.Rst = tcp.RST
	flags.Urg = tcp.RST
	flags.Ece = tcp.ECE
	flags.Cwr = tcp.CWR

	return p
}

func (t *ProtoPcapTranslator) translateTLSLayer(
	ctx context.Context,
	tls *layers.TLS,
) fmt.Stringer {
	// [TODO]: implement TLS layer translation
	p := &pb.Packet{}
	return p
}

func (t *ProtoPcapTranslator) translateDNSLayer(
	ctx context.Context,
	dns *layers.DNS,
) fmt.Stringer {
	// [TODO]: implement DNS layer translation
	p := &pb.Packet{}
	return p
}

func (t *ProtoPcapTranslator) merge(
	ctx context.Context,
	tgt fmt.Stringer,
	src fmt.Stringer,
) (fmt.Stringer, error) {
	proto.Merge(
		t.asTranslation(tgt),
		t.asTranslation(src),
	)
	return tgt, nil
}

func (t *ProtoPcapTranslator) finalize(
	ctx context.Context,
	ifaces netIfaceIndex,
	iface *PcapIface,
	serial *uint64,
	p *gopacket.Packet,
	conntrack bool,
	packet fmt.Stringer,
) (fmt.Stringer, error) {
	return packet, nil
}

func (t *ProtoPcapTranslator) write(
	ctx context.Context,
	writer io.Writer,
	packet *fmt.Stringer,
) (int, error) {
	translation := t.asTranslation(*packet)
	protoBytes, err := proto.Marshal(translation)
	if err != nil {
		return 0, err
	}

	protoBytesLen := len(protoBytes)

	// https://protobuf.dev/programming-guides/techniques/#streaming
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, uint32(protoBytesLen))
	if _, err := writer.Write(buf); err != nil {
		return protoBytesLen + 4, err
	}

	if _, err := writer.Write(protoBytes); err != nil {
		return protoBytesLen, err
	}

	return protoBytesLen, nil
}

func newPROTOPcapTranslator(
	ctx context.Context,
	debug bool,
	verbosity PcapVerbosity,
	iface *PcapIface,
	ephemerals *PcapEphemeralPorts,
) PcapTranslator {
	translator := newPcapTranslator(ctx, debug, verbosity, iface, ephemerals)
	return &ProtoPcapTranslator{
		pcapTranslator: translator,
	}
}
