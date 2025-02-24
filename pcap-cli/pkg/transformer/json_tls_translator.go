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

//go:build json

package transformer

import (
	"context"
	"encoding/binary"
	"errors"

	"github.com/Jeffail/gabs/v2"
	"github.com/google/gopacket/layers"
	"golang.org/x/crypto/cryptobyte"
)

func (t *JSONPcapTranslator) translateTLSLayer_decodeClientHello(hs cryptobyte.String, TLS *gabs.Container) {
	ch := make(map[string]interface{}, 4)

	ch["type"] = "ClientHello"

	var clientHello cryptobyte.String
	hs.ReadUint24LengthPrefixed(&clientHello)

	var legacyVersion uint16
	clientHello.ReadUint16(&legacyVersion)
	ch["legacy_version"] = layers.TLSVersion(legacyVersion).String()

	// var random []byte
	// clientHello.ReadBytes(&random, 32)
	// ch.Set(random, "random")

	// var legacySessionID []byte
	// clientHello.ReadUint8LengthPrefixed((*cryptobyte.String)(&legacySessionID))
	// ch.Set(legacySessionID, "legacy_session_id")

	clientHello.Skip(33)

	var ciphersuitesBytes cryptobyte.String
	clientHello.ReadUint16LengthPrefixed(&ciphersuitesBytes)
	var ciphers []uint16
	for !ciphersuitesBytes.Empty() {
		var ciphersuite uint16
		ciphersuitesBytes.ReadUint16(&ciphersuite)
		ciphers = append(ciphers, ciphersuite)
	}
	ch["ciphers"] = ciphers

	var legacyCompressionMethods []uint8
	clientHello.ReadUint8LengthPrefixed((*cryptobyte.String)(&legacyCompressionMethods))
	ch["legacy_compression_methods"] = legacyCompressionMethods

	var extensionsBytes cryptobyte.String
	clientHello.ReadUint16LengthPrefixed(&extensionsBytes)

	var extensions []map[string]interface{}
	for !extensionsBytes.Empty() {
		var extType uint16
		extensionsBytes.ReadUint16(&extType)

		ext := make(map[string]interface{}, 3)
		ext["type"] = extType

		var extData cryptobyte.String
		extensionsBytes.ReadUint16LengthPrefixed(&extData)

		switch extType {
		default:
			ext["name"] = "UNKNOWN"
		case 0: // Server Name
			ext["name"] = "server_name"
			extData.Skip(5)
			ext["data"] = string(extData)
		case 16: // ALPN
			ext["name"] = "application_layer_protocol_negotiation"
			var alpnData cryptobyte.String
			extData.ReadUint16LengthPrefixed(&alpnData)
			var data []string
			for !alpnData.Empty() {
				var length uint8
				alpnData.ReadUint8(&length)
				var proto []byte
				alpnData.ReadBytes(&proto, int(length))
				data = append(data, string(proto))
			}
			ext["data"] = data
		}

		extensions = append(extensions, ext)
	}
	ch["extensions"] = extensions

	TLS.SetP(ch, "data.client_hello")
}

func (t *JSONPcapTranslator) decodeTLSRecords(it uint8, data []byte, TLS *gabs.Container) error {
	if len(data) < 5 {
		return errors.New("TLS record too short")
	}

	var h layers.TLSRecordHeader
	h.ContentType = layers.TLSType(data[0])
	h.Version = layers.TLSVersion(binary.BigEndian.Uint16(data[1:3]))
	h.Length = binary.BigEndian.Uint16(data[3:5])

	if h.ContentType.String() == "Unknown" {
		return errors.New("unknown TLS record type")
	}

	hl := 5 // header length
	tl := hl + int(h.Length)

	if len(data) < tl {
		return errors.New("TLS packet length mismatch")
	}

	switch h.ContentType {
	default:
		return errors.New("unknown TLS record type")
	case layers.TLSChangeCipherSpec, layers.TLSAlert, layers.TLSHandshake:
		b := data[hl:tl]
		hs := cryptobyte.String(b)
		var messageType uint8
		if !hs.ReadUint8(&messageType) {
			return errors.New("failed to decode TLS layer")
		}
		// `ClientHello` and `ApplicationData` are the only full layers we have access to;
		// see: https://github.com/google/gopacket/blob/v1.1.19/layers/tls.go#L136-L139
		// reason: when `gopacket` decodes `TLS`, it repaces content by the last layer parsed
		if messageType == 1 {
			t.translateTLSLayer_decodeClientHello(hs, TLS)
		}
	case layers.TLSApplicationData:
	}

	if len(data) == tl {
		return nil
	}
	return t.decodeTLSRecords(it+1, data[tl:], TLS)
}

func (t *JSONPcapTranslator) translateTLSLayer_RecordHeader(ctx context.Context, json *gabs.Container, recordHeader layers.TLSRecordHeader) {
	json.SetP(recordHeader.Version.String(), "version")
	json.SetP(recordHeader.ContentType.String(), "content_type")
	json.SetP(recordHeader.Length, "length")
}

func (t *JSONPcapTranslator) translateTLSLayer_ChangeCipherSpec(ctx context.Context, TLS *gabs.Container, tls *layers.TLS) {
	a, _ := TLS.ArrayOfSize(len(tls.ChangeCipherSpec), "change_cipher_spec")
	for i, changeCipherSpec := range tls.ChangeCipherSpec {
		o, _ := a.ObjectI(i)
		t.translateTLSLayer_RecordHeader(ctx, o, changeCipherSpec.TLSRecordHeader)
		o.Set(changeCipherSpec.Message.String(), "message")
	}
}

func (t *JSONPcapTranslator) translateTLSLayer_Handshake(ctx context.Context, TLS *gabs.Container, tls *layers.TLS) {
	a, _ := TLS.ArrayOfSize(len(tls.Handshake), "handshake")
	for i, handshake := range tls.Handshake {
		o, _ := a.ObjectI(i)
		t.translateTLSLayer_RecordHeader(ctx, o, handshake.TLSRecordHeader)
	}
}

func (t *JSONPcapTranslator) translateTLSLayer_AppData(ctx context.Context, TLS *gabs.Container, tls *layers.TLS) {
	a, _ := TLS.ArrayOfSize(len(tls.Handshake), "app_data")
	for i, appData := range tls.AppData {
		o, _ := a.ObjectI(i)
		t.translateTLSLayer_RecordHeader(ctx, o, appData.TLSRecordHeader)
	}
}
