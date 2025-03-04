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

import "github.com/google/gopacket/layers"

func parseTCPflags(tcp *layers.TCP) uint8 {
	var setFlags uint8 = 0b00000000

	if tcp.SYN {
		setFlags = setFlags | tcpSyn
	}
	if tcp.ACK {
		setFlags = setFlags | tcpAck
	}
	if tcp.PSH {
		setFlags = setFlags | tcpPsh
	}
	if tcp.FIN {
		setFlags = setFlags | tcpFin
	}
	if tcp.RST {
		setFlags = setFlags | tcpRst
	}
	if tcp.URG {
		setFlags = setFlags | tcpUrg
	}
	if tcp.ECE {
		setFlags = setFlags | tcpEce
	}
	if tcp.CWR {
		setFlags = setFlags | tcpCwr
	}

	return setFlags
}

func (eph *PcapEmphemeralPorts) isEphemeralPort(port *uint16) bool {
	return *port >= eph.Min && *port <= eph.Max
}

func (eph *PcapEmphemeralPorts) isEphemeralUDPPort(udpPort *layers.UDPPort) bool {
	port := uint16(*udpPort)
	return eph.isEphemeralPort(&port)
}

func (eph *PcapEmphemeralPorts) isEphemeralTCPPort(tcpPort *layers.TCPPort) bool {
	port := uint16(*tcpPort)
	return eph.isEphemeralPort(&port)
}

func isConnectionTermination(tcpFlags *uint8) bool {
	return *tcpFlags&(tcpFin|tcpRst) != 0
}
