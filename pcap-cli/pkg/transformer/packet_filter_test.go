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
	"net/netip"
	"strconv"
	"testing"
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

func newPcapFilters() *pcapFilters {
	filters := NewPcapFilters()

	filters.AddL3Protos(L3_PROTO_IPv4, L3_PROTO_IPv6)
	filters.AddIPv4Ranges("169.254.0.0/16", "127.0.0.1/32")
	filters.AddIPv6Range("::1/128")

	filters.AddL4Protos(L4_PROTO_TCP, L4_PROTO_UDP, L4_PROTO_ICMP4, L4_PROTO_ICMP6)
	filters.AddTCPFlags(TCP_FLAG_SYN, TCP_FLAG_FIN, TCP_FLAG_RST)
	filters.AddPort(8022)

	return filters
}

func TestRejectTCPfilter(t *testing.T) {
	filters := newPcapFilters()

	srcPort := uint16(27584)
	dstPort := uint16(80)
	tcpFlags := tcpFlagNil | tcpAck | tcpFin

	t.Run("must-reject-TCP", func(t *testing.T) {
		if isTCPallowed(t, filters, tcpFlags, srcPort, dstPort) {
			t.Fatalf("must not allow TCP: [flags: 0b%s | ports: %d => %d]",
				strconv.FormatUint(uint64(tcpFlags), 2), srcPort, dstPort)
		}
	})
}

func TestRejectIPv4Filter(t *testing.T) {
	filters := newPcapFilters()

	srcIPv6, _ := netip.ParseAddr("169.254.8.1")
	srcPort := uint16(27584)
	dstIPv6, _ := netip.ParseAddr("169.254.169.254")
	dstPort := uint16(80)
	tcpFlags := tcpFlagNil | tcpAck | tcpFin

	t.Run("must-allow-IPv4", func(t *testing.T) {
		if !filters.AllowsIP(&srcIPv6) {
			t.Fatalf("must allow IPv4: %s", srcIPv6.String())
		}

		if !filters.AllowsIP(&dstIPv6) {
			t.Fatalf("must allow IPv4: %s", dstIPv6.String())
		}
	})

	t.Run("must-allow-TCP", func(t *testing.T) {
		if !filters.AllowsTCP() {
			t.Fatalf("must allow TCP")
		}
	})

	t.Run("must-reject-TCP-ports", func(t *testing.T) {
		if filters.AllowsL4Addr(&srcPort) {
			t.Fatalf("must not allow TCP port: %d", srcPort)
		}

		if filters.AllowsL4Addr(&dstPort) {
			t.Fatalf("must not allow TCP port: %d", dstPort)
		}
	})

	t.Run("must-allow-FIN+ACK-TCP-flag", func(t *testing.T) {
		if !filters.AllowsAnyTCPflags(&tcpFlags) {
			t.Fatalf("must allow TCP flag: 0b%s",
				strconv.FormatUint(uint64(tcpFlags), 2))
		}
	})
}

func TestAllowIPv6Filter(t *testing.T) {
	filters := newPcapFilters()

	srcIPv6, _ := netip.ParseAddr("::1")
	srcPort := uint16(8022)
	tcpFlags := tcpFlagNil | tcpRst

	t.Run("must-allow-IPv6", func(t *testing.T) {
		if !filters.AllowsIP(&srcIPv6) {
			t.Fatalf("must allow IPv6: %s", srcIPv6.String())
		}
	})

	t.Run("must-allow-TCP", func(t *testing.T) {
		if !filters.AllowsTCP() {
			t.Fatalf("must allow TCP")
		}
	})

	t.Run("must-allow-TCP-port", func(t *testing.T) {
		if !filters.AllowsL4Addr(&srcPort) {
			t.Fatalf("must allow TCP port: %d", srcPort)
		}
	})

	t.Run("must-allow-RST-TCP-flag", func(t *testing.T) {
		if !filters.AllowsAnyTCPflags(&tcpFlags) {
			t.Fatalf("must allow TCP flags: 0b%s",
				strconv.FormatUint(uint64(tcpFlags), 2))
		}
	})
}

func TestRejectIPv6Filter(t *testing.T) {
	filters := newPcapFilters()

	srcIPv6, _ := netip.ParseAddr("fddf:3978:feb1:d745::c001")
	srcPort := uint16(52552)
	dstIPv6, _ := netip.ParseAddr("2607:f8b0:4001:c08::cf")
	dstPort := uint16(443)
	tcpFlags := tcpFlagNil | tcpAck

	t.Run("must-reject-IPv6", func(t *testing.T) {
		if filters.AllowsIP(&srcIPv6) {
			t.Fatalf("must not allow: %s", srcIPv6.String())
		}

		if filters.AllowsIP(&dstIPv6) {
			t.Fatalf("must not allow: %s", dstIPv6.String())
		}
	})

	t.Run("must-allow-TCP", func(t *testing.T) {
		if !filters.AllowsTCP() {
			t.Fatalf("must allow TCP")
		}
	})

	t.Run("must-reject-TCP-ports", func(t *testing.T) {
		if filters.AllowsL4Addr(&srcPort) {
			t.Fatalf("must not allow TCP ports: %d", srcPort)
		}

		if filters.AllowsL4Addr(&dstPort) {
			t.Fatalf("must not allow TCP ports: %d", dstPort)
		}
	})

	t.Run("must-reject-ACK-TCP-flag", func(t *testing.T) {
		if filters.AllowsAnyTCPflags(&tcpFlags) {
			t.Fatalf("must not allow TCP flag: 0b%s",
				strconv.FormatUint(uint64(tcpFlags), 2))
		}
	})
}

func isTCPallowed(
	t *testing.T,
	filters *pcapFilters,
	tcpFlags uint8,
	srcPort, dstPort uint16,
) bool {
	isProtosFilterAvailable := filters.HasL4Protos()
	isTCPflagsFilterAvailable := filters.HasTCPflags()
	isL4AddrsFilterAvailable := filters.HasL4Addrs()

	if !isProtosFilterAvailable &&
		!isTCPflagsFilterAvailable &&
		!isL4AddrsFilterAvailable {
		t.Logf("nothing to veify")
		return true
	}

	if isProtosFilterAvailable && !filters.AllowsTCP() {
		return false
	}

	if isTCPflagsFilterAvailable {
		t.Logf("checking TCP flags: ob%s",
			strconv.FormatUint(uint64(tcpFlags), 2))
		if !filters.AllowsAnyTCPflags(&tcpFlags) {
			return false
		}
	}

	t.Logf("checking ports: (%t) %d => %d", isL4AddrsFilterAvailable, srcPort, dstPort)

	return !isL4AddrsFilterAvailable ||
		filters.AllowsAnyL4Addr(srcPort, dstPort)
}
