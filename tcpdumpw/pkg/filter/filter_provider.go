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

	"github.com/GoogleCloudPlatform/pcap-sidecar/pcap-cli/pkg/pcap"
	"github.com/wissance/stringFormatter"
)

type (
	pcapFilterProviderFactory = func(*pcap.PcapFilter, pcap.PcapFilters) pcap.PcapFilterProvider
	PcapFilterProviderFactory = func(*string, pcap.PcapFilters) pcap.PcapFilterProvider

	PcapFilterProvider interface {
		pcap.PcapFilterProvider
		Initialize(context.Context) pcap.PcapFilterProvider
	}
)

func applyFilter(
	ctx context.Context,
	srcFilter *string,
	provider pcap.PcapFilterProvider,
	mode pcap.PcapFilterMode,
) *string {
	if provider == nil {
		return srcFilter
	}

	filter, ok := provider.Get(ctx)
	if !ok || filter == nil || *filter == "" {
		return srcFilter
	}

	if srcFilter == nil || *srcFilter == "" {
		*filter = stringFormatter.Format("({0})", *filter)
		return filter
	}

	switch mode {
	case pcap.PCAP_FILTER_MODE_AND:
		*filter = stringFormatter.Format("{0} and ({1})", *srcFilter, *filter)
	case pcap.PCAP_FILTER_MODE_OR:
		*filter = stringFormatter.Format("{0} or ({1})", *srcFilter, *filter)
	}

	return filter
}

func newPcapFilter(rawFilter *string) *pcap.PcapFilter {
	return &pcap.PcapFilter{
		Raw: rawFilter,
	}
}

func newPcapFilterProvider(
	rawFilter *string,
	compatFilters pcap.PcapFilters,
	factory pcapFilterProviderFactory,
) pcap.PcapFilterProvider {
	pcapFilter := newPcapFilter(rawFilter)
	return factory(pcapFilter, compatFilters)
}

func NewIPFilterProvider(
	ipv4RawFilter, ipv6RawFilter, dnsRawFilter *string,
	compatFilters pcap.PcapFilters,
) pcap.PcapFilterProvider {
	return newIPFilterProvider(ipv4RawFilter, ipv6RawFilter, dnsRawFilter, compatFilters)
}

func NewDNSFilterProvider(rawFilter *string, compatFilters pcap.PcapFilters) pcap.PcapFilterProvider {
	return newPcapFilterProvider(rawFilter, compatFilters, newDNSFilterProvider)
}

func NewL3ProtoFilterProvider(rawFilter *string, compatFilters pcap.PcapFilters) pcap.PcapFilterProvider {
	return newPcapFilterProvider(rawFilter, compatFilters, newL3ProtoFilterProvider)
}

func NewL4ProtoFilterProvider(rawFilter *string, compatFilters pcap.PcapFilters) pcap.PcapFilterProvider {
	return newPcapFilterProvider(rawFilter, compatFilters, newL4ProtoFilterProvider)
}

func NewPortsFilterProvider(rawFilter *string, compatFilters pcap.PcapFilters) pcap.PcapFilterProvider {
	return newPcapFilterProvider(rawFilter, compatFilters, newPortsFilterProvider)
}

func NewTCPFlagsFilterProvider(rawFilter *string, compatFilters pcap.PcapFilters) pcap.PcapFilterProvider {
	return newPcapFilterProvider(rawFilter, compatFilters, newTCPFlagsFilterProvider)
}

func NewProcessFilterProvider(
	supervisorURL *string,
	processNames *string,
	refreshSecs uint8,
	debug bool,
	compatFilters pcap.PcapFilters,
) PcapFilterProvider {
	return newProcessFilterProvider(supervisorURL, processNames, refreshSecs, debug, compatFilters)
}
