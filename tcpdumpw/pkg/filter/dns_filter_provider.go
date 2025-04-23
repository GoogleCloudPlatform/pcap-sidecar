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
	"net"
	"net/netip"
	"strings"

	"github.com/GoogleCloudPlatform/pcap-sidecar/pcap-cli/pkg/pcap"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/wissance/stringFormatter"
)

type (
	DNSFilterProvider struct {
		*pcap.PcapFilter
		resolver      *net.Resolver
		compatFilters pcap.PcapFilters
	}
)

func (p *DNSFilterProvider) hostToIPs(ctx context.Context, host *string) ([]string, bool) {
	if *host == "" {
		return nil, false
	}

	addrs, err := p.resolver.LookupHost(ctx, *host)
	if err != nil {
		return nil, false
	}
	return addrs, true
}

func (p *DNSFilterProvider) hostsToIPs(ctx context.Context) (mapset.Set[string], bool) {
	if *p.Raw == "" ||
		strings.EqualFold(*p.Raw, "ALL") ||
		strings.EqualFold(*p.Raw, "ANY") {
		return nil, false
	}

	hosts := strings.Split(*p.Raw, ",")
	if len(hosts) == 0 || (len(hosts) == 1 && hosts[0] == "") {
		return nil, false
	}

	ipSet := mapset.NewThreadUnsafeSet[string]()
	for _, host := range hosts {
		if host == "" ||
			strings.EqualFold(host, "ALL") ||
			strings.EqualFold(host, "ANY") {
			continue
		}

		if IPs, ok := p.hostToIPs(ctx, &host); ok {
			for _, IP := range IPs {
				if addr, err := netip.ParseAddr(IP); err == nil {
					ipSet.Add(addr.String())
					if addr.Is4() {
						p.compatFilters.AddIPv4s(IP)
					} else {
						p.compatFilters.AddIPv6s(IP)
					}
				}
			}
		}
	}

	return ipSet, true
}

func (p *DNSFilterProvider) Get(ctx context.Context) (*string, bool) {
	if ipSet, ok := p.hostsToIPs(ctx); ok && ipSet != nil && !ipSet.IsEmpty() {
		filter := stringFormatter.Format("host {0}", strings.Join(ipSet.ToSlice(), " or host "))
		return &filter, true
	}
	return nil, false
}

func (p *DNSFilterProvider) String() string {
	if filter, ok := p.Get(context.Background()); ok {
		return stringFormatter.Format("DNSFilter[{0}] => ({1})", *p.Raw, *filter)
	}
	return "DNSFilter[nil]"
}

func (p *DNSFilterProvider) Apply(
	ctx context.Context,
	srcFilter *string,
	mode pcap.PcapFilterMode,
) *string {
	return applyFilter(ctx, srcFilter, p, mode)
}

func newDNSFilterProvider(
	filter *pcap.PcapFilter,
	compatFilters pcap.PcapFilters,
) pcap.PcapFilterProvider {
	return &DNSFilterProvider{
		PcapFilter: filter,
		resolver: &net.Resolver{
			PreferGo: true,
		},
		compatFilters: compatFilters,
	}
}

func newDNSFilterProviderFromRawFilter(
	rawFilter *string,
	compatFilters pcap.PcapFilters,
) pcap.PcapFilterProvider {
	return newDNSFilterProvider(
		&pcap.PcapFilter{
			Raw: rawFilter,
		}, compatFilters)
}
