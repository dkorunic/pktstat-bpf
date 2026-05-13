// @license
// Copyright (C) 2026  Dinko Korunic
//
// SPDX-License-Identifier: MIT

package main

import "testing"

// L4 protocol numbers used by the sniff tests.
const (
	ipprotoTCP uint8 = 6
	ipprotoUDP uint8 = 17
)

// sniffAppProtoGo is the Go-language contract for the eBPF sniff_app_proto
// helper in bpf/counter_common.h. KEEP THESE TWO IMPLEMENTATIONS IDENTICAL.
//
// peek is the L4 payload's first bytes (up to L7_PEEK_LEN=12). l4proto is
// the L4 transport (IPPROTO_TCP for HTTP/TLS, IPPROTO_UDP for QUIC).
// Returns one of the appProto* constants.
func sniffAppProtoGo(peek []byte, l4proto uint8) uint8 {
	if len(peek) < 5 {
		return appProtoUnknown
	}

	w := uint32(peek[0])<<24 | uint32(peek[1])<<16 | uint32(peek[2])<<8 | uint32(peek[3])
	b4 := peek[4]

	if l4proto == ipprotoTCP { //nolint:nestif
		// HTTP method / response / h2c preface. 5-byte disambiguation reduces
		// false positives compared with a bare 4-byte prefix.
		switch w {
		case 0x47455420, 0x50555420, 0x50524920: // "GET ", "PUT ", "PRI "
			return appProtoHTTP
		case 0x504F5354: // "POST"
			if b4 == ' ' {
				return appProtoHTTP
			}
		case 0x48454144: // "HEAD"
			if b4 == ' ' {
				return appProtoHTTP
			}
		case 0x4F505449: // "OPTI"
			if b4 == 'O' {
				return appProtoHTTP
			}
		case 0x44454C45: // "DELE"
			if b4 == 'T' {
				return appProtoHTTP
			}
		case 0x50415443: // "PATC"
			if b4 == 'H' {
				return appProtoHTTP
			}
		case 0x434F4E4E: // "CONN"
			if b4 == 'E' {
				return appProtoHTTP
			}
		case 0x54524143: // "TRAC"
			if b4 == 'E' {
				return appProtoHTTP
			}
		case 0x48545450: // "HTTP"
			if b4 == '/' {
				return appProtoHTTP
			}
		}

		// TLS record header: ContentType ∈ {0x14..0x17}, ProtocolVersion
		// major=0x03, minor ∈ {0x00..0x04}. Catches handshake and mid-stream.
		if (peek[0] == 0x14 || peek[0] == 0x15 || peek[0] == 0x16 || peek[0] == 0x17) &&
			peek[1] == 0x03 && peek[2] <= 0x04 {
			return appProtoTLS
		}
	}

	if l4proto == ipprotoUDP {
		// QUIC long header form + RFC 9000 fixed bit + known version.
		if peek[0]&0xC0 == 0xC0 {
			v := uint32(peek[1])<<24 | uint32(peek[2])<<16 |
				uint32(peek[3])<<8 | uint32(peek[4])
			switch v {
			case 0x00000001, 0x6B3343CF, 0x00000000:
				return appProtoQUIC
			}
		}
	}

	return appProtoUnknown
}

func TestSniffAppProtoHTTP(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   []byte
	}{
		{"GET", []byte("GET / HTTP/1.1\r\n")},
		{"POST", []byte("POST /api HTTP/1.1\r\n")},
		{"PUT", []byte("PUT /x HTTP/1.1\r\n")},
		{"HEAD", []byte("HEAD / HTTP/1.1\r\n")},
		{"DELETE", []byte("DELETE /x HTTP/1.1\r\n")},
		{"OPTIONS", []byte("OPTIONS * HTTP/1.1\r\n")},
		{"PATCH", []byte("PATCH /x HTTP/1.1\r\n")},
		{"CONNECT", []byte("CONNECT host:443 HTTP/1.1\r\n")},
		{"TRACE", []byte("TRACE /x HTTP/1.1\r\n")},
		{"Response", []byte("HTTP/1.1 200 OK\r\n")},
		{"H2cPreface", []byte("PRI * HTTP/2.0\r\n\r\nSM")},
	}

	for _, c := range cases {
		got := sniffAppProtoGo(c.in[:min(12, len(c.in))], ipprotoTCP)
		if got != appProtoHTTP {
			t.Errorf("%s: got %d, want HTTP (%d)", c.name, got, appProtoHTTP)
		}
	}
}

func TestSniffAppProtoTLS(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   []byte
	}{
		{"TLS1.0 Handshake", []byte{0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xFC, 0x03, 0x03, 0x00}},
		{"TLS1.2 ClientHello", []byte{0x16, 0x03, 0x03, 0x00, 0xC8, 0x01, 0x00, 0x00, 0xC4, 0x03, 0x03, 0xAA}},
		{"TLS1.3 ServerHello (record v1.2)", []byte{0x16, 0x03, 0x03, 0x00, 0x7A, 0x02, 0x00, 0x00, 0x76, 0x03, 0x03, 0xBB}},
		{"TLS1.3 ApplicationData", []byte{0x17, 0x03, 0x03, 0x04, 0x1C, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA}},
		{"TLS Alert", []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{"TLS ChangeCipherSpec", []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
	}

	for _, c := range cases {
		got := sniffAppProtoGo(c.in, ipprotoTCP)
		if got != appProtoTLS {
			t.Errorf("%s: got %d, want TLS (%d)", c.name, got, appProtoTLS)
		}
	}
}

func TestSniffAppProtoQUIC(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   []byte
	}{
		{"QUICv1 Initial", []byte{0xC3, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{"QUICv2 Initial", []byte{0xC3, 0x6B, 0x33, 0x43, 0xCF, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{"QUIC VersionNeg", []byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{"QUIC long header fixed bit, high type bits", []byte{0xFF, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
	}

	for _, c := range cases {
		got := sniffAppProtoGo(c.in, ipprotoUDP)
		if got != appProtoQUIC {
			t.Errorf("%s: got %d, want QUIC (%d)", c.name, got, appProtoQUIC)
		}
	}
}

func TestSniffAppProtoNegatives(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		in      []byte
		l4proto uint8
	}{
		{"SSH banner", []byte("SSH-2.0-OpenSSH_8\r\n"), ipprotoTCP},
		{"Random binary TCP", []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x12, 0x34, 0x56, 0x78}, ipprotoTCP},
		{"Truncated <5 bytes", []byte{0x16, 0x03, 0x03, 0x00}, ipprotoTCP},
		{"TLS bytes seen on UDP", []byte{0x16, 0x03, 0x03, 0x00, 0xC8, 0x01, 0x00, 0x00, 0xC4, 0x03, 0x03, 0xAA}, ipprotoUDP},
		{"HTTP bytes seen on UDP", []byte("GET / HTTP/1.1\r\n"), ipprotoUDP},
		{"DNS query (TCP-prefixed)", []byte{0x00, 0x1A, 0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}, ipprotoTCP},
		{"NTP packet on UDP", []byte{0x1B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, ipprotoUDP},
		{"QUIC short header (not detected directly)", []byte{0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, ipprotoUDP},
		{"QUIC long header with unknown version", []byte{0xC0, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, ipprotoUDP},
	}

	for _, c := range cases {
		got := sniffAppProtoGo(c.in, c.l4proto)
		if got != appProtoUnknown {
			t.Errorf("%s: got %d, want UNKNOWN", c.name, got)
		}
	}
}
