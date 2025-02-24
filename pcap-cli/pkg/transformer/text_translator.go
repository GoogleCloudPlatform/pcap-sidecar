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

//go:build text

package transformer

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/pterm/pterm"
)

type (
	TextPcapTranslator struct {
		iface *PcapIface
	}

	textPcapTranslation struct {
		index   int // allows layers to be sorted on `String()` invocation
		builder *strings.Builder
	}

	textPcapTranslations struct {
		writer       io.Writer
		translations map[int]*textPcapTranslation
	}
)

var (
	textPcapSerialStyle = pterm.NewStyle(pterm.FgBlack, pterm.BgRed)
	textPcapHeaderStyle = pterm.NewStyle(pterm.FgBlack, pterm.BgCyan, pterm.Bold)
	textPcapDataStyle   = pterm.NewStyle(pterm.FgBlack, pterm.BgWhite, pterm.Bold)
)

func init() {
	translators.Store(TEXT, newTEXTPcapTranslator)
}

func (tt *textPcapTranslation) String() string {
	return tt.builder.String()
}

func (tt *textPcapTranslations) String() string {
	translations := (*tt).translations

	printer := pterm.BulletListPrinter{
		Bullet:      "•",
		TextStyle:   &pterm.ThemeDefault.BulletListTextStyle,
		BulletStyle: &pterm.ThemeDefault.BulletListBulletStyle,
		Items:       make([]pterm.BulletListItem, len(translations)),
	}

	for key, value := range translations {
		printer.Items[key] = pterm.BulletListItem{
			Level:       key,                           // Level 0 (top level)
			Text:        value.builder.String(),        // Text to display
			TextStyle:   pterm.NewStyle(pterm.FgWhite), // Text color
			BulletStyle: pterm.NewStyle(pterm.FgRed),   // Bullet color
		}
	}

	str, err := printer.Srender()
	if err == nil {
		return pterm.DefaultBox.Sprintln(str)
	}
	return ""
}

func (t *TextPcapTranslator) done(_ context.Context) {
	// not implemented
}

func (t *TextPcapTranslator) next(
	ctx context.Context,
	nic *PcapIface,
	serial *uint64,
	packet *gopacket.Packet,
) fmt.Stringer {
	text := new(strings.Builder)

	metadata := (*packet).Metadata()
	info := metadata.CaptureInfo

	// text.WriteString(ctx.Value(ContextID))
	text.WriteString(textPcapSerialStyle.Sprint(" ", *serial, " "))
	text.WriteString(" | [iface: ")
	text.WriteString(textPcapDataStyle.Sprint(" ", t.iface.Index, "/", t.iface.Name, " "))
	text.WriteString("] | [timestamp: ")
	text.WriteString(textPcapDataStyle.Sprint(" ", info.Timestamp.String(), " "))
	text.WriteString("]")

	// `next` returns the container to be used for merging all layers
	return &textPcapTranslations{translations: map[int]*textPcapTranslation{0: {0, text}}}
}

func (t *TextPcapTranslator) asTranslation(buffer fmt.Stringer) *textPcapTranslation {
	return buffer.(*textPcapTranslation)
}

func (t *TextPcapTranslator) translateEthernetLayer(ctx context.Context, eth *layers.Ethernet) fmt.Stringer {
	text := new(strings.Builder)

	text.WriteString(textPcapHeaderStyle.Sprint(" L2 "))
	text.WriteString(" | [")
	text.WriteString(textPcapDataStyle.Sprint(" ", eth.EthernetType.String(), " "))
	text.WriteString("] | [src: ")
	text.WriteString(textPcapDataStyle.Sprint(" ", eth.SrcMAC.String(), " "))
	text.WriteString("] | [dst: ")
	text.WriteString(textPcapDataStyle.Sprint(" ", eth.DstMAC.String(), " "))
	text.WriteString("]")

	return &textPcapTranslation{1, text}
}

func (t *TextPcapTranslator) translateIPv4Layer(ctx context.Context, ip4 *layers.IPv4) fmt.Stringer {
	// [TODO]: implement IPv4 layer translation
	return &textPcapTranslation{2, new(strings.Builder)}
}

func (t *TextPcapTranslator) translateIPv6Layer(ctx context.Context, ip6 *layers.IPv6) fmt.Stringer {
	// [TODO]: implement IPv6 layer translation
	return &textPcapTranslation{2, new(strings.Builder)}
}

func (t *TextPcapTranslator) translateUDPLayer(ctx context.Context, udp *layers.UDP) fmt.Stringer {
	// [TODO]: implement UDP layer translation
	return &textPcapTranslation{3, new(strings.Builder)}
}

func (t *TextPcapTranslator) translateTCPLayer(ctx context.Context, tcp *layers.TCP) fmt.Stringer {
	// [TODO]: implement TCP layer translation
	return &textPcapTranslation{3, new(strings.Builder)}
}

func (t *TextPcapTranslator) translateTLSLayer(ctx context.Context, tls *layers.TLS) fmt.Stringer {
	// [TODO]: implement TLS layer translation
	return &textPcapTranslation{4, new(strings.Builder)}
}

func (t *TextPcapTranslator) translateDNSLayer(ctx context.Context, dns *layers.DNS) fmt.Stringer {
	// [TODO]: implement DNS layer translation
	return &textPcapTranslation{4, new(strings.Builder)}
}

func (t *TextPcapTranslator) merge(ctx context.Context, tgt fmt.Stringer, src fmt.Stringer) (fmt.Stringer, error) {
	srcTranslation := t.asTranslation(src)
	switch typedObj := tgt.(type) {
	case *textPcapTranslations:
		// add reference to another layer translation
		(*typedObj).translations[srcTranslation.index] = srcTranslation
	case *textPcapTranslation:
		// 1st `merge` invocation might not actually be a map (`textPcapTranslations`)
		tgt = &textPcapTranslations{
			translations: map[int]*textPcapTranslation{
				typedObj.index:       typedObj,
				srcTranslation.index: srcTranslation,
			},
		}
	}
	return tgt, nil
}

func (t *TextPcapTranslator) finalize(ctx context.Context, iface *PcapIface, serial *uint64, p *gopacket.Packet, connTrack bool, packet fmt.Stringer) (fmt.Stringer, error) {
	return packet, nil
}

func (t *TextPcapTranslator) write(ctx context.Context, writer io.Writer, packet *fmt.Stringer) (int, error) {
	translations := (*packet).(*textPcapTranslations)
	translations.writer = writer
	return io.WriteString(writer, translations.String())
}

func newTEXTPcapTranslator(
	_ context.Context,
	_ bool,
	iface *PcapIface,
	_ *PcapEmphemeralPorts,
) PcapTranslator {
	return &TextPcapTranslator{iface: iface}
}

// [TODO]: remove samples when all layers translations are implemented
func (t *TextPcapTranslator) translate(packet *gopacket.Packet) error {
	p := *packet

	// Iterate over all layers, printing out each layer type
	fmt.Println("All packet layers:")
	for _, layer := range p.Layers() {
		fmt.Println("- ", layer.LayerType())
	}

	// Check for errors
	if err := p.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}
	return nil
}
