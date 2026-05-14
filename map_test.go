// @license
// Copyright (C) 2026  Dinko Korunic
//
// SPDX-License-Identifier: MIT

package main

import (
	"math"
	"net/netip"
	"testing"
)

// mkTcStatkey is a test helper that builds a tcStatkey from human-readable
// fields, hiding the nested anonymous structs that mirror the C union layout
// of in6_addr.
func mkTcStatkey(src, dst netip.Addr, srcPort, dstPort uint16, proto uint8) tcStatkey {
	var k tcStatkey

	k.Srcip.In6U.U6Addr8 = src.As16()
	k.Dstip.In6U.U6Addr8 = dst.As16()
	k.SrcPort = srcPort
	k.DstPort = dstPort
	k.Proto = proto

	return k
}

// mkTcFlowkey mirrors mkTcStatkey for the 5-tuple flowkey used to index the
// flow_app_proto map.
func mkTcFlowkey(src, dst netip.Addr, srcPort, dstPort uint16, proto uint8) tcFlowkey {
	var k tcFlowkey

	k.Srcip.In6U.U6Addr8 = src.As16()
	k.Dstip.In6U.U6Addr8 = dst.As16()
	k.SrcPort = srcPort
	k.DstPort = dstPort
	k.Proto = proto

	return k
}

func TestStatkeyToFlowkey(t *testing.T) {
	t.Parallel()

	src := netip.MustParseAddr("10.0.0.1")
	dst := netip.MustParseAddr("10.0.0.2")

	cases := []struct {
		name      string
		inProto   uint8
		wantProto uint8
	}{
		{"TCP passthrough", protoTCPNum, protoTCPNum},
		{"UDP passthrough", 17, 17},
		{"ICMPv4 passthrough", 1, 1},
		{"TCP retransmit remapped to TCP", protoTCPRetx, protoTCPNum},
		{"ARP synthetic passthrough", 254, 254},
	}

	for _, c := range cases {
		key := mkTcStatkey(src, dst, 4242, 80, c.inProto)
		// Set non-zero fields that should NOT carry over to flowkey.
		key.Pid = 999
		key.Cgroupid = 0xdeadbeef
		key.Comm = [16]int8{'a', 'b', 'c'}

		fk := statkeyToFlowkey(key)

		if fk.Proto != c.wantProto {
			t.Errorf("%s: Proto = %d, want %d", c.name, fk.Proto, c.wantProto)
		}

		if fk.Srcip.In6U.U6Addr8 != key.Srcip.In6U.U6Addr8 {
			t.Errorf("%s: Srcip not copied", c.name)
		}

		if fk.Dstip.In6U.U6Addr8 != key.Dstip.In6U.U6Addr8 {
			t.Errorf("%s: Dstip not copied", c.name)
		}

		if fk.SrcPort != 4242 || fk.DstPort != 80 {
			t.Errorf("%s: ports = (%d, %d), want (4242, 80)", c.name, fk.SrcPort, fk.DstPort)
		}

		// Pad must be zero: kernel compares map keys byte-for-byte.
		if fk.Pad != [3]uint8{} {
			t.Errorf("%s: Pad must be zero, got %v", c.name, fk.Pad)
		}
	}
}

func TestSumPerCPUValue(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		in          []tcStatvalue
		wantPackets uint64
		wantBytes   uint64
	}{
		{"nil slice", nil, 0, 0},
		{"empty slice", []tcStatvalue{}, 0, 0},
		{
			name:        "single CPU",
			in:          []tcStatvalue{{Packets: 10, Bytes: 1500}},
			wantPackets: 10,
			wantBytes:   1500,
		},
		{
			name: "four CPUs",
			in: []tcStatvalue{
				{Packets: 1, Bytes: 100},
				{Packets: 2, Bytes: 200},
				{Packets: 3, Bytes: 300},
				{Packets: 4, Bytes: 400},
			},
			wantPackets: 10,
			wantBytes:   1000,
		},
		{
			name: "some CPUs zero",
			in: []tcStatvalue{
				{Packets: 0, Bytes: 0},
				{Packets: 5, Bytes: 500},
				{Packets: 0, Bytes: 0},
			},
			wantPackets: 5,
			wantBytes:   500,
		},
	}

	for _, c := range cases {
		got := sumPerCPUValue(c.in)
		if got.Packets != c.wantPackets || got.Bytes != c.wantBytes {
			t.Errorf("%s: got {%d, %d}, want {%d, %d}",
				c.name, got.Packets, got.Bytes, c.wantPackets, c.wantBytes)
		}
	}
}

func TestInternComm(t *testing.T) {
	t.Parallel()

	const name = "nginx"

	var a, b [16]int8

	for i, c := range []byte(name) {
		a[i] = int8(c)
		b[i] = int8(c)
	}

	sa := internComm(a)
	sb := internComm(b)

	if sa != name {
		t.Errorf("internComm: got %q, want %q", sa, name)
	}

	if sa != sb {
		t.Errorf("internComm: equal inputs returned different strings %q != %q", sa, sb)
	}

	// Distinct input → distinct output; same input must hit the cache.
	var c [16]int8

	for i, ch := range []byte("redis") {
		c[i] = int8(ch)
	}

	sc := internComm(c)
	if sc != "redis" {
		t.Errorf("internComm: got %q, want %q", sc, "redis")
	}

	sc2 := internComm(c)
	if sc != sc2 {
		t.Errorf("internComm: second call returned different string %q != %q", sc, sc2)
	}

	// NULL terminator must be respected on intern as well.
	var zeroed [16]int8
	if got := internComm(zeroed); got != "" {
		t.Errorf("internComm(zero) = %q, want empty", got)
	}
}

func TestAddStatsPrimaryLookup(t *testing.T) {
	t.Parallel()

	src := netip.MustParseAddr("10.0.0.1")
	dst := netip.MustParseAddr("10.0.0.2")

	key := mkTcStatkey(src, dst, 51200, 443, 17) // UDP
	val := tcStatvalue{Packets: 5, Bytes: 1000}

	fk := mkTcFlowkey(src, dst, 51200, 443, 17)
	appByFlow := map[tcFlowkey]uint8{fk: appProtoQUIC}

	stats := addStats(nil, key, val, appByFlow, 1.0)
	if len(stats) != 1 {
		t.Fatalf("len(stats) = %d, want 1", len(stats))
	}

	e := stats[0]

	if e.AppProto != "QUIC" {
		t.Errorf("AppProto = %q, want %q", e.AppProto, "QUIC")
	}

	if e.Proto != "UDP" {
		t.Errorf("Proto = %q, want %q", e.Proto, "UDP")
	}

	if e.SrcIP != src || e.DstIP != dst {
		t.Errorf("IPs = (%s, %s), want (%s, %s)", e.SrcIP, e.DstIP, src, dst)
	}

	if !e.SrcIP.Is4() {
		t.Errorf("SrcIP not unmapped to v4: %s", e.SrcIP)
	}

	if e.Bytes != 1000 || e.Packets != 5 {
		t.Errorf("counters = (%d, %d), want (1000, 5)", e.Bytes, e.Packets)
	}

	// Bitrate = 8 * bytes / dur = 8000.
	if e.Bitrate != 8000 {
		t.Errorf("Bitrate = %g, want 8000", e.Bitrate)
	}
}

func TestAddStatsReverseDirectionTCP(t *testing.T) {
	t.Parallel()

	// Receive-direction key, but L7 cached under send-direction.
	local := netip.MustParseAddr("10.0.0.1")
	remote := netip.MustParseAddr("8.8.8.8")

	// Receive-direction key: 8.8.8.8:443 → 10.0.0.1:51200
	key := mkTcStatkey(remote, local, 443, 51200, protoTCPNum)
	val := tcStatvalue{Packets: 4, Bytes: 800}

	// Cache stored under send-direction key: 10.0.0.1:51200 → 8.8.8.8:443
	sendFK := mkTcFlowkey(local, remote, 51200, 443, protoTCPNum)
	appByFlow := map[tcFlowkey]uint8{sendFK: appProtoTLS}

	stats := addStats(nil, key, val, appByFlow, 1.0)
	if stats[0].AppProto != "TLS" {
		t.Errorf("reverse-direction lookup failed: AppProto = %q, want %q", stats[0].AppProto, "TLS")
	}
}

func TestAddStatsReverseDirectionTCPRetransmit(t *testing.T) {
	t.Parallel()

	// Retransmit (proto=253) must remap to TCP (6) before reverse lookup.
	local := netip.MustParseAddr("10.0.0.1")
	remote := netip.MustParseAddr("8.8.8.8")

	key := mkTcStatkey(remote, local, 22, 60000, protoTCPRetx)
	val := tcStatvalue{Packets: 1, Bytes: 64}

	// Cache stored under send-direction with TCP (6), not 253.
	sendFK := mkTcFlowkey(local, remote, 60000, 22, protoTCPNum)
	appByFlow := map[tcFlowkey]uint8{sendFK: appProtoSSH}

	stats := addStats(nil, key, val, appByFlow, 1.0)
	if stats[0].AppProto != "SSH" {
		t.Errorf("retransmit reverse-direction lookup failed: AppProto = %q, want %q", stats[0].AppProto, "SSH")
	}

	// And the row itself reports TCP-RETX as proto (not remapped for display).
	if stats[0].Proto != "TCP-RETX" {
		t.Errorf("Proto = %q, want TCP-RETX", stats[0].Proto)
	}
}

func TestAddStatsNoReverseForNonTCP(t *testing.T) {
	t.Parallel()

	// UDP miss must NOT trigger reverse lookup; both directions cached naturally.
	local := netip.MustParseAddr("10.0.0.1")
	remote := netip.MustParseAddr("8.8.8.8")

	key := mkTcStatkey(remote, local, 53, 51200, 17)
	val := tcStatvalue{Packets: 1, Bytes: 64}

	// Reverse cache entry exists, but UDP must NOT find it.
	reverseFK := mkTcFlowkey(local, remote, 51200, 53, 17)
	appByFlow := map[tcFlowkey]uint8{reverseFK: appProtoQUIC}

	stats := addStats(nil, key, val, appByFlow, 1.0)
	if stats[0].AppProto != "" {
		t.Errorf("UDP reverse-direction lookup leaked: AppProto = %q, want empty", stats[0].AppProto)
	}
}

func TestAddStatsMissNoCache(t *testing.T) {
	t.Parallel()

	key := mkTcStatkey(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), 80, 8080, protoTCPNum)
	val := tcStatvalue{Packets: 1, Bytes: 100}

	stats := addStats(nil, key, val, map[tcFlowkey]uint8{}, 1.0)
	if stats[0].AppProto != "" {
		t.Errorf("no-cache: AppProto = %q, want empty", stats[0].AppProto)
	}

	stats = addStats(nil, key, val, nil, 1.0)
	if stats[0].AppProto != "" {
		t.Errorf("nil-cache: AppProto = %q, want empty", stats[0].AppProto)
	}
}

func TestAddStatsBitrate(t *testing.T) {
	t.Parallel()

	key := mkTcStatkey(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), 1, 2, 6)

	// Half-second duration → bitrate doubles.
	stats := addStats(nil, key, tcStatvalue{Bytes: 1000}, nil, 0.5)
	if stats[0].Bitrate != 16000 {
		t.Errorf("Bitrate at 0.5s = %g, want 16000", stats[0].Bitrate)
	}

	// Zero bytes → zero bitrate, no division surprise.
	stats = addStats(nil, key, tcStatvalue{}, nil, 1.0)
	if stats[0].Bitrate != 0 {
		t.Errorf("zero-byte Bitrate = %g, want 0", stats[0].Bitrate)
	}

	// Bitrate must always be finite for finite inputs.
	if math.IsInf(stats[0].Bitrate, 0) || math.IsNaN(stats[0].Bitrate) {
		t.Errorf("non-finite bitrate for zero bytes: %g", stats[0].Bitrate)
	}
}

func TestAddStatsAppendsRatherThanReplaces(t *testing.T) {
	t.Parallel()

	key := mkTcStatkey(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), 1, 2, 6)
	val := tcStatvalue{Packets: 1, Bytes: 100}

	stats := []statEntry{{Proto: "marker"}}
	stats = addStats(stats, key, val, nil, 1.0)

	if len(stats) != 2 {
		t.Fatalf("len(stats) = %d, want 2", len(stats))
	}

	if stats[0].Proto != "marker" {
		t.Errorf("existing entry clobbered: %+v", stats[0])
	}
}

func TestAddStatsPidAndCGroupPassthrough(t *testing.T) {
	t.Parallel()

	// cgroupid=0 short-circuits cGroupToPath; no /sys/fs/cgroup dependency.
	key := mkTcStatkey(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), 1, 2, 6)
	key.Pid = 4242
	key.Cgroupid = 0

	for i, b := range []byte("curl") {
		key.Comm[i] = int8(b)
	}

	stats := addStats(nil, key, tcStatvalue{}, nil, 1.0)
	e := stats[0]

	if e.Pid != 4242 {
		t.Errorf("Pid = %d, want 4242", e.Pid)
	}

	if e.Comm != "curl" {
		t.Errorf("Comm = %q, want %q", e.Comm, "curl")
	}

	if e.CGroup != "" {
		t.Errorf("CGroup for id=0 must be empty, got %q", e.CGroup)
	}
}

func TestReadFlowAppProtoNilMap(t *testing.T) {
	t.Parallel()

	if got := readFlowAppProto(nil); got != nil {
		t.Errorf("readFlowAppProto(nil) = %v, want nil", got)
	}
}
