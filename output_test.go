// @license
// Copyright (C) 2026  Dinko Korunic
//
// SPDX-License-Identifier: MIT

package main

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

// mkEntry constructs a minimal statEntry for outputPlain tests.
func mkEntry(proto string, srcPort, dstPort uint16) statEntry {
	return statEntry{
		SrcIP:   netip.MustParseAddr("10.0.0.1"),
		DstIP:   netip.MustParseAddr("10.0.0.2"),
		Proto:   proto,
		SrcPort: srcPort,
		DstPort: dstPort,
		Packets: 1,
		Bytes:   100,
		Bitrate: 800.0,
	}
}

func TestOutputPlainIPsecESP(t *testing.T) {
	t.Parallel()

	// SPI = 0xA1B2C3D4 → src_port=0xA1B2, dst_port=0xC3D4
	out := outputPlain([]statEntry{mkEntry("IPSEC-ESP", 0xA1B2, 0xC3D4)}, false)

	for _, want := range []string{
		"proto: IPSEC-ESP",
		"src: 10.0.0.1",
		"dst: 10.0.0.2",
		"spi: 0xa1b2c3d4",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("outputPlain missing %q in:\n%s", want, out)
		}
	}
}

func TestOutputPlainIPsecAH(t *testing.T) {
	t.Parallel()

	out := outputPlain([]statEntry{mkEntry("IPSEC-AH", 0x1234, 0x5678)}, false)

	for _, want := range []string{
		"proto: IPSEC-AH",
		"spi: 0x12345678",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestOutputPlainGRE(t *testing.T) {
	t.Parallel()

	out := outputPlain([]statEntry{mkEntry("GRE", 0x0800, 0x0000)}, false)

	for _, want := range []string{
		"proto: GRE",
		"inner: IPv4",
		"flags: 0x0000",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestOutputPlainOSPF(t *testing.T) {
	t.Parallel()

	out := outputPlain([]statEntry{mkEntry("OSPFIGP", 1, 2)}, false)

	for _, want := range []string{
		"proto: OSPFIGP",
		"type: Hello",
		"v2",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestOutputPlainARP(t *testing.T) {
	t.Parallel()

	out := outputPlain([]statEntry{mkEntry("ARP", 1, 0)}, false)

	for _, want := range []string{
		"proto: ARP",
		"op: request",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestOutputPlainTCPUnchanged(t *testing.T) {
	t.Parallel()

	out := outputPlain([]statEntry{mkEntry("TCP", 12345, 80)}, false)

	for _, want := range []string{
		"proto: TCP",
		"src: 10.0.0.1:12345",
		"dst: 10.0.0.2:80",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestStatEntryJSON_ESP(t *testing.T) {
	t.Parallel()

	e := mkEntry("IPSEC-ESP", 0xA1B2, 0xC3D4)

	b, err := json.Marshal(&e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)

	for _, want := range []string{
		`"proto":"IPSEC-ESP"`,
		`"srcPort":41394`,  // 0xA1B2 — preserved
		`"dstPort":50132`,  // 0xC3D4 — preserved
		`"spi":2712847316`, // 0xA1B2C3D4
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in JSON:\n%s", want, s)
		}
	}
}

func TestStatEntryJSON_ARP(t *testing.T) {
	t.Parallel()

	e := mkEntry("ARP", 1, 0)

	b, err := json.Marshal(&e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)

	if !strings.Contains(s, `"arpOp":"request"`) {
		t.Errorf("missing arpOp in:\n%s", s)
	}
}

func TestStatEntryJSON_OSPF(t *testing.T) {
	t.Parallel()

	e := mkEntry("OSPFIGP", 1, 2)

	b, err := json.Marshal(&e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)

	for _, want := range []string{
		`"ospfType":"Hello"`,
		`"ospfVersion":2`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
}

func TestStatEntryJSON_GRE(t *testing.T) {
	t.Parallel()

	e := mkEntry("GRE", 0x0800, 0x1234)

	b, err := json.Marshal(&e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)

	for _, want := range []string{
		`"greInner":"IPv4"`,
		`"greFlags":4660`, // 0x1234
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in JSON:\n%s", want, s)
		}
	}
}

func TestOutputPlainAppProto(t *testing.T) {
	t.Parallel()

	e := mkEntry("TCP", 12345, 443)
	e.AppProto = "TLS"

	out := outputPlain([]statEntry{e}, false)

	for _, want := range []string{
		"proto: TCP",
		"l7: TLS",
		"src: 10.0.0.1:12345",
		"dst: 10.0.0.2:443",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestOutputPlainAppProtoEmptyOmitted(t *testing.T) {
	t.Parallel()

	e := mkEntry("TCP", 12345, 80)
	out := outputPlain([]statEntry{e}, false)

	if strings.Contains(out, "l7:") {
		t.Errorf("unexpected l7 field for unknown app proto:\n%s", out)
	}
}

func TestStatEntryJSON_AppProto(t *testing.T) {
	t.Parallel()

	e := mkEntry("UDP", 51200, 443)
	e.AppProto = "QUIC"

	b, err := json.Marshal(&e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)

	if !strings.Contains(s, `"appProto":"QUIC"`) {
		t.Errorf("missing appProto in JSON:\n%s", s)
	}
}

func TestStatEntryJSON_AppProtoOmittedWhenEmpty(t *testing.T) {
	t.Parallel()

	e := mkEntry("TCP", 12345, 80)

	b, err := json.Marshal(&e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)

	if strings.Contains(s, `"appProto"`) {
		t.Errorf("unexpected appProto field in TCP JSON:\n%s", s)
	}
}

func TestStatEntryJSON_TCPBackwardsCompat(t *testing.T) {
	t.Parallel()

	e := mkEntry("TCP", 12345, 80)

	b, err := json.Marshal(&e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)

	for _, mustNot := range []string{
		`"spi":`,
		`"arpOp":`,
		`"ospfType":`,
		`"greInner":`,
	} {
		if strings.Contains(s, mustNot) {
			t.Errorf("unexpected %q in TCP JSON:\n%s", mustNot, s)
		}
	}
}
