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
	L3ProtoFilterProvider struct {
		*pcap.PcapFilter
		pcap.PcapFilters
	}
)

const (
	l3_PROTO_DEFAULT_FILTER string = "ip or ip6 or arp"
	l3_PROTO_IPv4_FILTER    string = "ip"
	l3_PROTO_IPv6_FILTER    string = "ip6"
	l3_PROTO_ARP_FILTER     string = "arp"
)

func (p *L3ProtoFilterProvider) Get(ctx context.Context) (*string, bool) {
	if *p.Raw == "" ||
		strings.EqualFold(*p.Raw, "ALL") ||
		strings.EqualFold(*p.Raw, "ANY") ||
		strings.EqualFold(*p.Raw, l3_PROTO_DEFAULT_FILTER) {
		filter := string(l3_PROTO_DEFAULT_FILTER)
		return &filter, true
	}

	protos := strings.Split(*p.Raw, ",")
	if len(protos) == 0 || (len(protos) == 1 && protos[0] == "") {
		filter := string(l3_PROTO_DEFAULT_FILTER)
		return &filter, true
	}

	l3Protos := mapset.NewThreadUnsafeSet[string]()

	for _, proto := range protos {
		switch proto {
		case "ip", "ip4", "ipv4", "4", "0x04":
			l3Protos.Add(string(l3_PROTO_IPv4_FILTER))
			p.AddL3Proto(pcap.L3_PROTO_IPv4)
		case "ip6", "ipv6", "41", "0x29":
			l3Protos.Add(string(l3_PROTO_IPv6_FILTER))
			p.AddL3Proto(pcap.L3_PROTO_IPv6)
		case "arp", "0x0806":
			l3Protos.Add(string(l3_PROTO_ARP_FILTER))
		}
	}

	if l3Protos.IsEmpty() {
		filter := string(l3_PROTO_DEFAULT_FILTER)
		return &filter, true
	}

	filter := stringFormatter.Format("{0}", strings.Join(l3Protos.ToSlice(), " or "))
	return &filter, true
}

func (p *L3ProtoFilterProvider) String() string {
	if filter, ok := p.Get(context.Background()); ok {
		return stringFormatter.Format("L3Proto[{0}] => ({1})", *p.Raw, *filter)
	}
	return "L3Proto[nil]"
}

func (p *L3ProtoFilterProvider) Apply(
	ctx context.Context,
	srcFilter *string,
	mode pcap.PcapFilterMode,
) *string {
	return applyFilter(ctx, srcFilter, p, mode)
}

func newL3ProtoFilterProvider(
	filter *pcap.PcapFilter,
	compatFilters pcap.PcapFilters,
) pcap.PcapFilterProvider {
	provider := &L3ProtoFilterProvider{
		PcapFilter:  filter,
		PcapFilters: compatFilters,
	}
	return provider
}
