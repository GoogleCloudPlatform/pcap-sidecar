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

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	sf "github.com/wissance/stringFormatter"
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

func newPcapFilters(
	t *testing.T,
) *pcapFilters {
	t.Helper()

	filters := NewPcapFilters()

	filters.AddL3Protos(L3_PROTO_IPv4, L3_PROTO_IPv6)
	filters.AddIPv4Ranges("169.254.0.0/16", "127.0.0.1/32", "10.0.0.0/8")
	filters.AddIPv6Range("::1/128")

	filters.AddL4Protos(L4_PROTO_TCP, L4_PROTO_UDP, L4_PROTO_ICMP4, L4_PROTO_ICMP6)
	filters.AddTCPFlags(TCP_FLAG_SYN, TCP_FLAG_FIN, TCP_FLAG_RST)
	filters.AddPort(8022)

	return filters
}

func TestRejectTCPfilter(t *testing.T) {
	filters := newPcapFilters(t)

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
	filters := newPcapFilters(t)

	srcIPv4, _ := netip.ParseAddr("169.254.8.1")
	srcPort := uint16(27584)
	dstIPv4, _ := netip.ParseAddr("169.254.169.254")
	dstPort := uint16(80)
	tcpFlags := tcpFlagNil | tcpAck | tcpFin

	t.Run("must-allow-IPv4", func(t *testing.T) {
		t.Parallel()

		if !filters.AllowsIP(&srcIPv4) {
			t.Fatalf("must allow IPv4: %s", srcIPv4.String())
		}

		if !filters.AllowsIP(&dstIPv4) {
			t.Fatalf("must allow IPv4: %s", dstIPv4.String())
		}
	})

	t.Run("must-allow-TCP", func(t *testing.T) {
		t.Parallel()

		if !filters.AllowsTCP() {
			t.Fatalf("must allow TCP")
		}
	})

	t.Run("must-reject-TCP-ports", func(t *testing.T) {
		t.Parallel()

		if filters.AllowsL4Addr(&srcPort) {
			t.Fatalf("must not allow TCP port: %d", srcPort)
		}

		if filters.AllowsL4Addr(&dstPort) {
			t.Fatalf("must not allow TCP port: %d", dstPort)
		}
	})

	t.Run("must-allow-FIN+ACK-TCP-flag", func(t *testing.T) {
		t.Parallel()

		if !filters.AllowsAnyTCPflags(&tcpFlags) {
			t.Fatalf("must allow TCP flag: 0b%s",
				strconv.FormatUint(uint64(tcpFlags), 2))
		}
	})
}

func TestAllowIPv6Filter(t *testing.T) {
	filters := newPcapFilters(t)

	srcIPv6, _ := netip.ParseAddr("::1")
	srcPort := uint16(8022)
	tcpFlags := tcpFlagNil | tcpRst

	t.Run("must-allow-IPv6", func(t *testing.T) {
		t.Parallel()

		if !filters.AllowsIP(&srcIPv6) {
			t.Fatalf("must allow IPv6: %s", srcIPv6.String())
		}
	})

	t.Run("must-allow-TCP", func(t *testing.T) {
		t.Parallel()

		if !filters.AllowsTCP() {
			t.Fatalf("must allow TCP")
		}
	})

	t.Run("must-allow-TCP-port", func(t *testing.T) {
		t.Parallel()

		if !filters.AllowsL4Addr(&srcPort) {
			t.Fatalf("must allow TCP port: %d", srcPort)
		}
	})

	t.Run("must-allow-RST-TCP-flag", func(t *testing.T) {
		t.Parallel()

		if !filters.AllowsAnyTCPflags(&tcpFlags) {
			t.Fatalf("must allow TCP flags: 0b%s",
				strconv.FormatUint(uint64(tcpFlags), 2))
		}
	})
}

func TestRejectIPv6Filter(t *testing.T) {
	filters := newPcapFilters(t)

	srcIPv6, _ := netip.ParseAddr("fddf:3978:feb1:d745::c001")
	srcPort := uint16(52552)
	dstIPv6, _ := netip.ParseAddr("2607:f8b0:4001:c08::cf")
	dstPort := uint16(443)
	tcpFlags := tcpFlagNil | tcpAck

	t.Run("must-reject-IPv6", func(t *testing.T) {
		t.Parallel()

		if filters.AllowsIP(&srcIPv6) {
			t.Fatalf("must not allow: %s", srcIPv6.String())
		}

		if filters.AllowsIP(&dstIPv6) {
			t.Fatalf("must not allow: %s", dstIPv6.String())
		}
	})

	t.Run("must-allow-TCP", func(t *testing.T) {
		t.Parallel()

		if !filters.AllowsTCP() {
			t.Fatalf("must allow TCP")
		}
	})

	t.Run("must-reject-TCP-ports", func(t *testing.T) {
		t.Parallel()

		if filters.AllowsL4Addr(&srcPort) {
			t.Fatalf("must not allow TCP ports: %d", srcPort)
		}

		if filters.AllowsL4Addr(&dstPort) {
			t.Fatalf("must not allow TCP ports: %d", dstPort)
		}
	})

	t.Run("must-reject-ACK-TCP-flag", func(t *testing.T) {
		t.Parallel()

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
	t.Helper()

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

func toBooleanAssertion(
	t *testing.T,
	b bool,
) assert.BoolAssertionFunc {
	t.Helper()
	if b {
		return assert.True
	}
	return assert.False
}

func TestAllowsIPaddres(
	t *testing.T,
) {
	assertions := assert.New(t)

	for _, tt := range []struct {
		IP        string
		assertion assert.BoolAssertionFunc
		want      bool
	}{
		{
			IP:   "173.194.206.95",
			want: false,
		},
		{
			IP:   "18.204.150.154",
			want: false,
		},
		{
			IP:   "192.168.0.1",
			want: false,
		},
		{
			IP:   "10.0.1.1",
			want: true,
		},
		{
			IP:   "169.254.8.1",
			want: true,
		},
		{
			IP:   "169.254.9.1",
			want: true,
		},
		{
			IP:   "169.254.169.254",
			want: true,
		},
	} {
		IP, err := netip.ParseAddr(tt.IP)
		if assertions.NoError(err, sf.Format("invalid IP: {0}", tt.IP)) {
			t.Run(sf.Format("verify-if-IP-{0}-is-allowed", tt.IP),
				func(t *testing.T) {
					t.Parallel()
					filters := newPcapFilters(t)
					assertion := toBooleanAssertion(t, tt.want)
					got := filters.AllowsIP(&IP)
					assertion(t, got, sf.Format("{0}\n{1}", tt.IP, cmp.Diff(tt.want, got)))
				})
		}
	}
}

func TestHashSocket(
	t *testing.T,
) {
	f := NewPcapFilters()

	for _, tt := range []struct {
		name       string
		ipAndPort1 string
		ipAndPort2 string
	}{
		{
			name:       "IPv4",
			ipAndPort1: "127.0.0.1:55555",
			ipAndPort2: "10.10.10.10:443",
		},
		{
			name:       "IPv6",
			ipAndPort1: "[::1]:55555",
			ipAndPort2: "[2607:f8b0:4001:c08::cf]:443",
		},
	} {
		t.Run("2tuple", func(t *testing.T) {
			t.Parallel()
			a := assert.New(t)

			hash, hashOK := f.hashSocketFrom2tuples(tt.ipAndPort1, tt.ipAndPort2)
			reversedHash, reversedHashOK := f.hashSocketFrom2tuples(tt.ipAndPort2, tt.ipAndPort1)

			a.True(hashOK, sf.Format("{0} > {1}", tt.ipAndPort1, tt.ipAndPort2))
			a.True(reversedHashOK, sf.Format("{0} > {1}", tt.ipAndPort2, tt.ipAndPort1))

			t.Log(sf.Format("hash2tuples({0} > {1})={2}", tt.ipAndPort1, tt.ipAndPort2, *hash))
			t.Log(sf.Format("hash2tuples({0} > {1})={2}", tt.ipAndPort2, tt.ipAndPort1, *reversedHash))

			a.Equal(hash, reversedHash, sf.Format("hash 2tuples: {0}", cmp.Diff(*hash, *reversedHash)))

			addrPort1, addrPortErr1 := netip.ParseAddrPort(tt.ipAndPort1)
			addrPort2, addrPortErr2 := netip.ParseAddrPort(tt.ipAndPort2)

			if a.NoError(addrPortErr1) && a.NoError(addrPortErr2) {
				t.Run("AddrPort", func(t *testing.T) {
					t.Parallel()
					a := assert.New(t)

					addr1 := addrPort1.Addr()
					port1 := addrPort1.Port()

					addr2 := addrPort2.Addr()
					port2 := addrPort2.Port()

					hashAddrPort := f.hashSocketFromAddrsAndPorts(&addr1, &port1, &addr2, &port2)
					reversedAddrPortHash := f.hashSocketFromAddrsAndPorts(&addr2, &port2, &addr1, &port1)

					t.Log(sf.Format("hashAddrPort({0} > {1})={2}", addrPort1.String(), addrPort2.String(), *hashAddrPort))
					t.Log(sf.Format("hashAddrPort({0} > {1})={2}", addrPort2.String(), addrPort1.String(), *reversedAddrPortHash))

					a.Equal(hashAddrPort, reversedAddrPortHash, sf.Format("hash AddrPorts: {0}", cmp.Diff(*hash, *reversedHash)))

					t.Run("crosscheck", func(t *testing.T) {
						t.Parallel()
						a := assert.New(t)

						a.Equal(hash, hashAddrPort, sf.Format("hash: {0}", cmp.Diff(*hash, *reversedAddrPortHash)))
						a.Equal(reversedHash, reversedAddrPortHash, sf.Format("reversed hash: {0}", cmp.Diff(*hash, *reversedAddrPortHash)))
						a.Equal(hash, reversedAddrPortHash, sf.Format("hash: {0}", cmp.Diff(*hash, *reversedAddrPortHash)))
						a.Equal(hashAddrPort, reversedHash, sf.Format("reversed hash: {0}", cmp.Diff(*hashAddrPort, *reversedHash)))
					})
				})
			}

			t.Run("API", func(t *testing.T) {
				t.Parallel()

				a.True(f.DenySocket(tt.ipAndPort1, tt.ipAndPort2),
					sf.Format("failed to deny socket: [local={0} > remote={1}]", tt.ipAndPort1, tt.ipAndPort2))

				addr1 := addrPort1.Addr()
				port1 := addrPort1.Port()

				addr2 := addrPort2.Addr()
				port2 := addrPort2.Port()

				a.False(f.AllowsSocket(&addr1, &port1, &addr2, &port2),
					sf.Format("must deny socket: [{0} > {1}]", addrPort1.String(), addrPort2.String()))

				a.False(f.AllowsSocket(&addr2, &port2, &addr1, &port1),
					sf.Format("must deny reversed socket: [{0} > {1}]", addrPort1.String(), addrPort2.String()))
			})
		})
	}
}
