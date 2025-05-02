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
	"strconv"
	"strings"

	"github.com/GoogleCloudPlatform/pcap-sidecar/pcap-cli/pkg/pcap"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/wissance/stringFormatter"
)

type (
	PortsFilterProvider struct {
		*pcap.PcapFilter
		pcap.PcapFilters
	}
)

func (p *PortsFilterProvider) Get(ctx context.Context) (*string, bool) {
	if *p.Raw == "" {
		return nil, false
	}

	ports := strings.Split(strings.ToLower(*p.Raw), ",")
	if len(ports) == 0 || (len(ports) == 1 && ports[0] == "") {
		return nil, false
	}

	portSet := mapset.NewThreadUnsafeSet(ports...)
	portSet.Each(func(portStr string) bool {
		if strings.EqualFold(portStr, "ALL") || strings.EqualFold(portStr, "ANY") {
			portSet.Clear()
			return true
		} else if port, err := strconv.
			ParseUint(portStr, 10, 16); err == nil && port > 0 && port <= 0xFFFF {
			p.AddPort(uint16(port))
		} else {
			// a PORT must be a number not greater than 65535 ( 0xFFFF )
			portSet.Remove(portStr)
		}
		return false
	})

	if portSet.IsEmpty() {
		return nil, false
	}

	filter := stringFormatter.Format("port {0}",
		strings.Join(portSet.ToSlice(), " or port "))

	return &filter, true
}

func (p *PortsFilterProvider) String() string {
	if filter, ok := p.Get(context.Background()); ok {
		return stringFormatter.Format("PortsFilter[{0}] => ({1})", *p.Raw, *filter)
	}
	return "PortsFilter[nil]"
}

func (p *PortsFilterProvider) Apply(
	ctx context.Context,
	srcFilter *string,
	mode pcap.PcapFilterMode,
) *string {
	return applyFilter(ctx, srcFilter, p, mode)
}

func newPortsFilterProvider(
	filter *pcap.PcapFilter,
	compatFilters pcap.PcapFilters,
) pcap.PcapFilterProvider {
	provider := &PortsFilterProvider{
		PcapFilter:  filter,
		PcapFilters: compatFilters,
	}
	return provider
}
