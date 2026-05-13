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

func TestFormatBitrate(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   float64
		want string
	}{
		{"zero", 0, "0.00 bps"},
		{"sub-Kbps", 500, "500.00 bps"},
		{"just below Kbps", 999.99, "999.99 bps"},
		{"exact Kbps boundary", 1000, "1.00 Kbps"},
		{"mid-Kbps", 1500, "1.50 Kbps"},
		{"exact Mbps boundary", 1e6, "1.00 Mbps"},
		{"mid-Mbps", 1.5e6, "1.50 Mbps"},
		{"exact Gbps boundary", 1e9, "1.00 Gbps"},
		{"mid-Gbps", 2.5e9, "2.50 Gbps"},
		{"exact Tbps boundary", 1e12, "1.00 Tbps"},
		{"mid-Tbps", 2.5e12, "2.50 Tbps"},
		// Above Tbps still renders as Tbps (no Pbps tier).
		{"above Tbps", 1.5e15, "1500.00 Tbps"},
	}

	for _, c := range cases {
		got := formatBitrate(c.in)
		if got != c.want {
			t.Errorf("%s: formatBitrate(%g) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}

func TestAppendHex16(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   uint16
		want string
	}{
		{"zero pads to four chars", 0x0000, "0000"},
		{"small value pads", 0x000F, "000f"},
		{"mid value lowercase", 0xABCD, "abcd"},
		{"all-bits-set", 0xFFFF, "ffff"},
		{"boundary 0x0100", 0x0100, "0100"},
	}

	for _, c := range cases {
		got := string(appendHex16(nil, c.in))
		if got != c.want {
			t.Errorf("%s: appendHex16(nil, 0x%04x) = %q, want %q", c.name, c.in, got, c.want)
		}
	}

	// Append-to-existing-buffer behaviour.
	buf := []byte("0x")
	got := string(appendHex16(buf, 0x1234))

	if got != "0x1234" {
		t.Errorf("append to existing buf: got %q, want %q", got, "0x1234")
	}
}

func TestBsliceToString(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   []int8
		want string
	}{
		{"empty slice", []int8{}, ""},
		{"all zero", []int8{0, 0, 0, 0}, ""},
		{"trailing zeros trimmed", []int8{'a', 'b', 'c', 0, 0, 0}, "abc"},
		{"single zero at start", []int8{0, 'a', 'b'}, ""},
		{"no terminator full length", []int8{'h', 'i', '!'}, "hi!"},
		{"15-char comm (no terminator)", []int8{'s', 'y', 's', 't', 'e', 'm', 'd', '-', 'j', 'o', 'u', 'r', 'n', 'a', 'l'}, "systemd-journal"},
	}

	for _, c := range cases {
		got := bsliceToString(c.in)
		if got != c.want {
			t.Errorf("%s: bsliceToString(%v) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}

// makeSortFixtures returns three statEntry rows with distinct sortable values.
func makeSortFixtures() []statEntry {
	a := mkEntry("TCP", 1, 2)
	a.SrcIP = netip.MustParseAddr("10.0.0.3")
	a.DstIP = netip.MustParseAddr("10.0.0.30")
	a.Bitrate = 800
	a.Packets = 8
	a.Bytes = 100

	b := mkEntry("TCP", 3, 4)
	b.SrcIP = netip.MustParseAddr("10.0.0.1")
	b.DstIP = netip.MustParseAddr("10.0.0.10")
	b.Bitrate = 1600
	b.Packets = 4
	b.Bytes = 200

	c := mkEntry("TCP", 5, 6)
	c.SrcIP = netip.MustParseAddr("10.0.0.2")
	c.DstIP = netip.MustParseAddr("10.0.0.20")
	c.Bitrate = 400
	c.Packets = 12
	c.Bytes = 50

	return []statEntry{a, b, c}
}

func TestBitrateSort(t *testing.T) {
	t.Parallel()

	s := makeSortFixtures()
	bitrateSort(s)

	want := []float64{1600, 800, 400}
	for i, w := range want {
		if s[i].Bitrate != w {
			t.Errorf("bitrateSort: index %d has Bitrate=%g, want %g", i, s[i].Bitrate, w)
		}
	}
}

func TestPacketSort(t *testing.T) {
	t.Parallel()

	s := makeSortFixtures()
	packetSort(s)

	want := []uint64{12, 8, 4}
	for i, w := range want {
		if s[i].Packets != w {
			t.Errorf("packetSort: index %d has Packets=%d, want %d", i, s[i].Packets, w)
		}
	}
}

func TestBytesSort(t *testing.T) {
	t.Parallel()

	s := makeSortFixtures()
	bytesSort(s)

	want := []uint64{200, 100, 50}
	for i, w := range want {
		if s[i].Bytes != w {
			t.Errorf("bytesSort: index %d has Bytes=%d, want %d", i, s[i].Bytes, w)
		}
	}
}

func TestSrcIPSort(t *testing.T) {
	t.Parallel()

	s := makeSortFixtures()
	srcIPSort(s)

	want := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	for i, w := range want {
		if s[i].SrcIP.String() != w {
			t.Errorf("srcIPSort: index %d has SrcIP=%s, want %s", i, s[i].SrcIP, w)
		}
	}
}

func TestDstIPSort(t *testing.T) {
	t.Parallel()

	s := makeSortFixtures()
	dstIPSort(s)

	want := []string{"10.0.0.10", "10.0.0.20", "10.0.0.30"}
	for i, w := range want {
		if s[i].DstIP.String() != w {
			t.Errorf("dstIPSort: index %d has DstIP=%s, want %s", i, s[i].DstIP, w)
		}
	}
}

func TestSortStability_EmptyAndSingle(t *testing.T) {
	t.Parallel()

	// Empty input must be a no-op for every sort.
	for _, fn := range []func([]statEntry){bitrateSort, packetSort, bytesSort, srcIPSort, dstIPSort} {
		var empty []statEntry

		fn(empty)

		if len(empty) != 0 {
			t.Errorf("sort grew empty slice to %d", len(empty))
		}
	}

	// Single-element input must remain unchanged.
	single := []statEntry{mkEntry("TCP", 80, 80)}
	bitrateSort(single)

	if len(single) != 1 {
		t.Errorf("single-element sort lost element: len=%d", len(single))
	}
}

func TestOutputPlainEmpty(t *testing.T) {
	t.Parallel()

	out := outputPlain(nil, false)
	if out != "" {
		t.Errorf("outputPlain(nil) = %q, want empty string", out)
	}

	out = outputPlain([]statEntry{}, false)
	if out != "" {
		t.Errorf("outputPlain([]) = %q, want empty string", out)
	}
}

func TestOutputPlainMultipleEntries(t *testing.T) {
	t.Parallel()

	entries := []statEntry{
		mkEntry("TCP", 80, 8080),
		mkEntry("UDP", 53, 5353),
	}

	out := outputPlain(entries, false)
	if strings.Count(out, "\n") != 2 {
		t.Errorf("expected 2 newlines for 2 entries, got %d in:\n%s",
			strings.Count(out, "\n"), out)
	}

	for _, want := range []string{"proto: TCP", "proto: UDP", "10.0.0.1:80", "10.0.0.1:53"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestOutputPlainICMPv4(t *testing.T) {
	t.Parallel()

	// Echo request: type=8, code=0; encoded in srcPort/dstPort.
	out := outputPlain([]statEntry{mkEntry("ICMPv4", 8, 0)}, false)

	for _, want := range []string{
		"proto: ICMPv4",
		"src: 10.0.0.1",
		"dst: 10.0.0.2",
		"type: 8",
		"code: 0",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}

	// Type/code must NOT be encoded as host:port.
	if strings.Contains(out, "10.0.0.1:8") {
		t.Errorf("ICMPv4 output incorrectly rendered host:port form:\n%s", out)
	}
}

func TestOutputPlainICMPv6(t *testing.T) {
	t.Parallel()

	// Neighbor Solicitation: type=135, code=0.
	out := outputPlain([]statEntry{mkEntry("IPv6-ICMP", 135, 0)}, false)

	for _, want := range []string{
		"proto: IPv6-ICMP",
		"type: 135",
		"code: 0",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestOutputPlainShowProcessInfo(t *testing.T) {
	t.Parallel()

	e := mkEntry("TCP", 12345, 80)
	e.Pid = 4242
	e.Comm = "nginx"
	e.CGroup = "/system.slice/nginx.service"

	out := outputPlain([]statEntry{e}, true)

	for _, want := range []string{
		"pid: 4242",
		"comm: nginx",
		"cgroup: /system.slice/nginx.service",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestOutputPlainShowProcessInfoOmitsZeroAndEmpty(t *testing.T) {
	t.Parallel()

	// Pid=0, Comm="", CGroup="" → each field omitted individually.
	e := mkEntry("TCP", 12345, 80)
	out := outputPlain([]statEntry{e}, true)

	for _, mustNot := range []string{"pid: ", "comm: ", "cgroup: "} {
		if strings.Contains(out, mustNot) {
			t.Errorf("unexpected %q in:\n%s", mustNot, out)
		}
	}

	// One field set must not pull in the others.
	e.Pid = 99
	out = outputPlain([]statEntry{e}, true)

	if !strings.Contains(out, "pid: 99") {
		t.Errorf("missing pid in:\n%s", out)
	}

	for _, mustNot := range []string{"comm: ", "cgroup: "} {
		if strings.Contains(out, mustNot) {
			t.Errorf("unexpected %q in:\n%s", mustNot, out)
		}
	}
}

func TestOutputPlainShowProcessInfoFalseSuppressesAll(t *testing.T) {
	t.Parallel()

	// Even when fields are populated, showProcessInfo=false must hide them.
	e := mkEntry("TCP", 12345, 80)
	e.Pid = 4242
	e.Comm = "nginx"
	e.CGroup = "/system.slice/nginx.service"

	out := outputPlain([]statEntry{e}, false)

	for _, mustNot := range []string{"pid: ", "comm: ", "cgroup: "} {
		if strings.Contains(out, mustNot) {
			t.Errorf("showProcessInfo=false leaked %q in:\n%s", mustNot, out)
		}
	}
}

func TestStatEntryJSON_TCPIncludesIPs(t *testing.T) {
	t.Parallel()

	// Default-path encoding must still emit srcIp / dstIp keys.
	e := mkEntry("TCP", 80, 443)

	b, err := json.Marshal(&e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)

	for _, want := range []string{
		`"srcIp":"10.0.0.1"`,
		`"dstIp":"10.0.0.2"`,
		`"proto":"TCP"`,
		`"srcPort":80`,
		`"dstPort":443`,
		`"bytes":100`,
		`"packets":1`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in JSON:\n%s", want, s)
		}
	}
}
