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

package filter

import (
	"context"
	"strings"

	"github.com/GoogleCloudPlatform/pcap-sidecar/pcap-cli/pkg/pcap"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/wissance/stringFormatter"
)

type (
	L4ProtoFilterProvider struct {
		*pcap.PcapFilter
		pcap.PcapFilters
	}
)

const (
	l4_PROTO_DEFAULT_FILTER string = "tcp or udp or icmp or icmp6"
	l4_PROTO_TCP_FILTER     string = "tcp"
	l4_PROTO_UDP_FILTER     string = "udp"
	l4_PROTO_ICMPv4_FILTER  string = "icmp"
	l4_PROTO_ICMPv6_FILTER  string = "icmp6"
)

func (p *L4ProtoFilterProvider) Get(ctx context.Context) (*string, bool) {
	if *p.Raw == "" ||
		*p.Raw == "23" || // tcp(6) + udp(17)
		*p.Raw == "0x17" || // tcp(0x06) + udp(0x11)
		strings.EqualFold(*p.Raw, "ALL") ||
		strings.EqualFold(*p.Raw, "ANY") ||
		strings.EqualFold(*p.Raw, l4_PROTO_DEFAULT_FILTER) {
		filter := string(l4_PROTO_DEFAULT_FILTER)
		return &filter, true
	}

	protos := strings.Split(*p.Raw, ",")
	if len(protos) == 0 || (len(protos) == 1 && protos[0] == "") {
		filter := string(l4_PROTO_DEFAULT_FILTER)
		return &filter, true
	}

	l4Protos := mapset.NewThreadUnsafeSet[string]()

	for _, proto := range protos {
		switch proto {
		case "tcp", "6", "0x06":
			l4Protos.Add(string(l4_PROTO_TCP_FILTER))
			p.AddL4Proto(pcap.L4_PROTO_TCP)
		case "udp", "17", "0x11":
			l4Protos.Add(string(l4_PROTO_UDP_FILTER))
			p.AddL4Proto(pcap.L4_PROTO_UDP)
		case "icmp", "icmp4", "1", "0x01":
			l4Protos.Add(string(l4_PROTO_ICMPv4_FILTER))
			p.AddL4Proto(pcap.L4_PROTO_ICMP)
		case "icmp6", "58", "0x3A":
			l4Protos.Add(string(l4_PROTO_ICMPv6_FILTER))
			p.AddL4Proto(pcap.L4_PROTO_ICMP6)
		}
	}

	if l4Protos.IsEmpty() {
		filter := string(l4_PROTO_DEFAULT_FILTER)
		return &filter, true
	}

	filter := stringFormatter.Format("{0}", strings.Join(l4Protos.ToSlice(), " or "))
	return &filter, true
}

func (p *L4ProtoFilterProvider) String() string {
	if filter, ok := p.Get(context.Background()); ok {
		return stringFormatter.Format("L4Proto[{0}] => ({1})", *p.Raw, *filter)
	}
	return "L4Proto[nil]"
}

func (p *L4ProtoFilterProvider) Apply(
	ctx context.Context,
	srcFilter *string,
	mode pcap.PcapFilterMode,
) *string {
	return applyFilter(ctx, srcFilter, p, mode)
}

func newL4ProtoFilterProvider(
	filter *pcap.PcapFilter,
	compatFilters pcap.PcapFilters,
) pcap.PcapFilterProvider {
	provider := &L4ProtoFilterProvider{
		PcapFilter:  filter,
		PcapFilters: compatFilters,
	}
	return provider
}
