// @license
// Copyright (C) 2026  Dinko Korunic
//
// SPDX-License-Identifier: MIT

package main

import (
	"net/netip"
	"testing"
)

func TestOSPFTypeName(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   uint16
		want string
	}{
		{1, "Hello"},
		{2, "DBDesc"},
		{3, "LSReq"},
		{4, "LSUpd"},
		{5, "LSAck"},
		{0, "0"},
		{6, "6"},
		{255, "255"},
	}

	for _, c := range cases {
		got := ospfTypeName(c.in)
		if got != c.want {
			t.Errorf("ospfTypeName(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestARPOpName(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   uint16
		want string
	}{
		{1, "request"},
		{2, "reply"},
		{3, "rev-req"},
		{4, "rev-reply"},
		{0, "0"},
		{5, "5"},
	}

	for _, c := range cases {
		got := arpOpName(c.in)
		if got != c.want {
			t.Errorf("arpOpName(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestGREInnerName(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   uint16
		want string
	}{
		{0x0800, "IPv4"},
		{0x86DD, "IPv6"},
		{0x6558, "TransEth"},
		{0x8847, "MPLS"},
		{0x8848, "MPLS-MC"},
		{0x0806, "ARP"},
		{0x1234, "0x1234"},
	}

	for _, c := range cases {
		got := greInnerName(c.in)
		if got != c.want {
			t.Errorf("greInnerName(0x%04x) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestAppProtoToString(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   uint8
		want string
	}{
		{appProtoUnknown, ""},
		{appProtoHTTP, "HTTP"},
		{appProtoTLS, "TLS"},
		{appProtoQUIC, "QUIC"},
		{appProtoSSH, "SSH"},
		{appProtoRDP, "RDP"},
		{appProtoPostgres, "PostgreSQL"},
		{appProtoMQTT, "MQTT"},
		{appProtoWireGuard, "WireGuard"},
		{appProtoMemcached, "Memcached"},
		{99, ""},
		{255, ""},
	}

	for _, c := range cases {
		got := appProtoToString(c.in)
		if got != c.want {
			t.Errorf("appProtoToString(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestProtoToString(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   uint8
		want string
	}{
		{"HOPOPT (0)", 0, "HOPOPT"},
		{"ICMPv4", 1, "ICMPv4"},
		{"IGMP", 2, "IGMP"},
		{"TCP", 6, "TCP"},
		{"UDP", 17, "UDP"},
		{"GRE", 47, "GRE"},
		{"IPSEC-ESP", 50, "IPSEC-ESP"},
		{"IPSEC-AH", 51, "IPSEC-AH"},
		{"IPv6-ICMP", 58, "IPv6-ICMP"},
		{"OSPFIGP", 89, "OSPFIGP"},
		{"SCTP", 132, "SCTP"},
		{"TCP-RETX synthetic", 253, "TCP-RETX"},
		{"ARP synthetic", 254, "ARP"},
		{"Fragment (255)", 255, "Fragment"},
		// Unregistered values fall through to "Unknown".
		{"unassigned 7", 7, "Unknown"},
		{"unassigned 200", 200, "Unknown"},
		{"unassigned 252", 252, "Unknown"},
	}

	for _, c := range cases {
		got := protoToString(c.in)
		if got != c.want {
			t.Errorf("%s: protoToString(%d) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}

func TestBytesToAddr(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   [16]byte
		want string
		// is4 reports whether the result should be the 4-byte IPv4 form.
		is4 bool
	}{
		{
			name: "IPv4-mapped 192.168.1.1 unmaps to v4",
			in:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1},
			want: "192.168.1.1",
			is4:  true,
		},
		{
			name: "IPv4-mapped 10.0.0.2 unmaps to v4",
			in:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 2},
			want: "10.0.0.2",
			is4:  true,
		},
		{
			name: "all-zero stays as ::",
			in:   [16]byte{},
			want: "::",
			is4:  false,
		},
		{
			name: "native IPv6 link-local",
			in:   [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55},
			want: "fe80::211:22ff:fe33:4455",
			is4:  false,
		},
		{
			name: "IPv4-mapped 0.0.0.0 still unmaps (FFFF marker present)",
			in:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0},
			want: "0.0.0.0",
			is4:  true,
		},
	}

	for _, c := range cases {
		got := bytesToAddr(c.in)
		if got.String() != c.want {
			t.Errorf("%s: bytesToAddr(%v) = %s, want %s", c.name, c.in, got, c.want)
		}

		if got.Is4() != c.is4 {
			t.Errorf("%s: Is4() = %v, want %v (got %s)", c.name, got.Is4(), c.is4, got)
		}

		// Sanity: the result must round-trip through netip.ParseAddr.
		if _, err := netip.ParseAddr(got.String()); err != nil {
			t.Errorf("%s: result %q does not parse: %v", c.name, got, err)
		}
	}
}
