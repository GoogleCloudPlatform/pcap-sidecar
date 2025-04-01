package transformer

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

import (
	"strconv"
	"testing"

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
)

// TestParseTCPflags verifies the conversion from layers.TCP boolean flags to a uint8 bitmask.
func TestParseTCPflags(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		tcpLayer *layers.TCP
		want     uint8
	}{
		{
			name:     "no_flags",
			tcpLayer: &layers.TCP{},
			want:     tcpFlagNil,
		},
		{
			name:     "SYN_flag",
			tcpLayer: &layers.TCP{SYN: true},
			want:     tcpSyn,
		},
		{
			name:     "ACK_flag",
			tcpLayer: &layers.TCP{ACK: true},
			want:     tcpAck,
		},
		{
			name:     "PSH_flag",
			tcpLayer: &layers.TCP{PSH: true},
			want:     tcpPsh,
		},
		{
			name:     "FIN_flag",
			tcpLayer: &layers.TCP{FIN: true},
			want:     tcpFin,
		},
		{
			name:     "RST_flag",
			tcpLayer: &layers.TCP{RST: true},
			want:     tcpRst,
		},
		{
			name:     "URG_flag",
			tcpLayer: &layers.TCP{URG: true},
			want:     tcpUrg,
		},
		{
			name:     "ECE_flag",
			tcpLayer: &layers.TCP{ECE: true},
			want:     tcpEce,
		},
		{
			name:     "CWR_flag",
			tcpLayer: &layers.TCP{CWR: true},
			want:     tcpCwr,
		},
		{
			name:     "SYN_ACK_flags",
			tcpLayer: &layers.TCP{SYN: true, ACK: true},
			want:     tcpSynAck,
		},
		{
			name:     "FIN_ACK_flags",
			tcpLayer: &layers.TCP{FIN: true, ACK: true},
			want:     tcpFinAck,
		},
		{
			name:     "RST_ACK_flags",
			tcpLayer: &layers.TCP{RST: true, ACK: true},
			want:     tcpRstAck,
		},
		{
			name:     "PSH_ACK_flags",
			tcpLayer: &layers.TCP{PSH: true, ACK: true},
			want:     tcpPshAck,
		},
		{
			name:     "All_flags",
			tcpLayer: &layers.TCP{SYN: true, ACK: true, PSH: true, FIN: true, RST: true, URG: true, ECE: true, CWR: true},
			want:     tcpSyn | tcpAck | tcpPsh | tcpFin | tcpRst | tcpUrg | tcpEce | tcpCwr,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := parseTCPflags(tt.tcpLayer)
			assert.Equal(t, tt.want, got, "Expected flags 0b%s, got 0b%s", strconv.FormatUint(uint64(tt.want), 2), strconv.FormatUint(uint64(got), 2))
		})
	}
}

// TestIsEphemeralPort verifies the logic for checking if a port is within the ephemeral range.
func TestIsEphemeralPort(t *testing.T) {
	t.Parallel()
	eph := &PcapEmphemeralPorts{
		Min: 32768,
		Max: 65535,
	}

	tests := []struct {
		name string
		port uint16
		want bool
	}{
		{name: "below_range", port: 32767, want: false},
		{name: "exactly_min", port: 32768, want: true},
		{name: "inside_range", port: 40000, want: true},
		{name: "exactly_max", port: 65535, want: true},
		// Test case for port 65536 not applicable as uint16 overflows
		{name: "zero_port", port: 0, want: false},
		{name: "common_low_port", port: 80, want: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			portPtr := tt.port
			got := eph.isEphemeralPort(&portPtr)
			if tt.want {
				assert.True(t, got, "Port %d should be ephemeral in range %d-%d", tt.port, eph.Min, eph.Max)
			} else {
				assert.False(t, got, "Port %d should NOT be ephemeral in range %d-%d", tt.port, eph.Min, eph.Max)
			}
		})
	}
}

// TestIsEphemeralUDPPort verifies the wrapper for UDP ports.
func TestIsEphemeralUDPPort(t *testing.T) {
	t.Parallel()
	eph := &PcapEmphemeralPorts{
		Min: 32768,
		Max: 65535,
	}

	tests := []struct {
		name string
		port layers.UDPPort
		want bool
	}{
		{name: "below_range", port: 32767, want: false},
		{name: "exactly_min", port: 32768, want: true},
		{name: "inside_range", port: 50000, want: true},
		{name: "exactly_max", port: 65535, want: true},
		// Test case for port 65536 not applicable as uint16 overflows
		{name: "common_low_UDP_port", port: 53, want: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			portPtr := tt.port
			got := eph.isEphemeralUDPPort(&portPtr)
			if tt.want {
				assert.True(t, got, "UDP Port %d should be ephemeral in range %d-%d", tt.port, eph.Min, eph.Max)
			} else {
				assert.False(t, got, "UDP Port %d should NOT be ephemeral in range %d-%d", tt.port, eph.Min, eph.Max)
			}
		})
	}
}

// TestIsEphemeralTCPPort verifies the wrapper for TCP ports.
func TestIsEphemeralTCPPort(t *testing.T) {
	t.Parallel()
	eph := &PcapEmphemeralPorts{
		Min: 32768,
		Max: 65535,
	}

	tests := []struct {
		name string
		port layers.TCPPort
		want bool
	}{
		{name: "below_range", port: 32767, want: false},
		{name: "exactly_min", port: 32768, want: true},
		{name: "inside_range", port: 50000, want: true},
		{name: "exactly_max", port: 65535, want: true},
		// Test case for port 65536 not applicable as uint16 overflows
		{name: "common_low_TCP_port", port: 443, want: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			portPtr := tt.port
			got := eph.isEphemeralTCPPort(&portPtr)
			if tt.want {
				assert.True(t, got, "TCP Port %d should be ephemeral in range %d-%d", tt.port, eph.Min, eph.Max)
			} else {
				assert.False(t, got, "TCP Port %d should NOT be ephemeral in range %d-%d", tt.port, eph.Min, eph.Max)
			}
		})
	}
}

// TestIsConnectionTermination verifies if flags indicate a connection termination (FIN or RST).
func TestIsConnectionTermination(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		flags uint8
		want  bool
	}{
		{name: "no_flags", flags: tcpFlagNil, want: false},
		{name: "SYN_flag", flags: tcpSyn, want: false},
		{name: "ACK_flag", flags: tcpAck, want: false},
		{name: "PSH_flag", flags: tcpPsh, want: false},
		{name: "URG_flag", flags: tcpUrg, want: false},
		{name: "ECE_flag", flags: tcpEce, want: false},
		{name: "CWR_flag", flags: tcpCwr, want: false},
		{name: "SYN_ACK_flags", flags: tcpSynAck, want: false},
		{name: "PSH_ACK_flags", flags: tcpPshAck, want: false},
		{name: "FIN_flag_only", flags: tcpFin, want: true},
		{name: "RST_flag_only", flags: tcpRst, want: true},
		{name: "FIN_ACK_flags", flags: tcpFinAck, want: true},
		{name: "RST_ACK_flags", flags: tcpRstAck, want: true},
		{name: "FIN_RST_flags", flags: tcpFin | tcpRst, want: true},
		{name: "FIN_RST_ACK_flags", flags: tcpFinRstAck, want: true},
		{name: "all_flags", flags: tcpSyn | tcpAck | tcpPsh | tcpFin | tcpRst | tcpUrg | tcpEce | tcpCwr, want: true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			flagsPtr := tt.flags
			got := isConnectionTermination(&flagsPtr)
			if tt.want {
				assert.True(t, got, "Flags 0b%s should indicate connection termination", strconv.FormatUint(uint64(tt.flags), 2))
			} else {
				assert.False(t, got, "Flags 0b%s should NOT indicate connection termination", strconv.FormatUint(uint64(tt.flags), 2))
			}
		})
	}
}
