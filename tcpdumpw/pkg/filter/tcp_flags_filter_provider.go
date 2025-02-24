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
	TCPFlagsFilterProvider struct {
		*pcap.PcapFilter
		pcap.PcapFilters
	}
)

func (p *TCPFlagsFilterProvider) Get(ctx context.Context) (*string, bool) {
	if *p.Raw == "" ||
		strings.EqualFold(*p.Raw, "ALL") ||
		strings.EqualFold(*p.Raw, "ANY") {
		return nil, false
	}

	flags := strings.Split(strings.ToLower(*p.Raw), ",")
	if len(flags) == 0 || (len(flags) == 1 && flags[0] == "") {
		return nil, false
	}

	flagsSet := mapset.NewThreadUnsafeSet(flags...)

	var setFlags uint8 = 0
	flagsSet.Each(func(flagStr string) bool {
		flagStr = strings.ToUpper(flagStr)
		tcpFlag := pcap.TCPFlag(flagStr)
		if flag := tcpFlag.ToUint8(); flag == 0 {
			flagsSet.Remove(flagStr)
		} else {
			setFlags |= flag
			p.AddTCPFlags(tcpFlag)
		}
		return false // do not stop iteration
	})

	if setFlags == 0 || flagsSet.IsEmpty() {
		return nil, false
	}

	ip6Filter := stringFormatter.Format("ip6[13+40]&0x{0}!=0", strconv.FormatUint(uint64(setFlags), 16))
	// OR'ing out all the TCP flags: if any of the flags is set, packet will be captured
	ip4Filter := stringFormatter.Format("tcp-{0}", strings.Join(flagsSet.ToSlice(), "|tcp-"))
	// bitwise intersection should not yield 0, so intersection must not be empty
	filter := stringFormatter.Format("(tcp[tcpflags]&({0})!=0) or ({1})", ip4Filter, ip6Filter)

	return &filter, true
}

func (p *TCPFlagsFilterProvider) String() string {
	if filter, ok := p.Get(context.Background()); ok {
		return stringFormatter.Format("TCPFlagsFilter[{0}] => ({1})", *p.Raw, *filter)
	}
	return "TCPFlagsFilter[nil]"
}

func (p *TCPFlagsFilterProvider) Apply(
	ctx context.Context,
	srcFilter *string,
	mode pcap.PcapFilterMode,
) *string {
	return applyFilter(ctx, srcFilter, p, mode)
}

func newTCPFlagsFilterProvider(
	filter *pcap.PcapFilter,
	compatFilters pcap.PcapFilters,
) pcap.PcapFilterProvider {
	provider := &TCPFlagsFilterProvider{
		PcapFilter:  filter,
		PcapFilters: compatFilters,
	}
	return provider
}
