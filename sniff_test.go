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
// the L4 transport (IPPROTO_TCP for HTTP/TLS, IPPROTO_UDP for DTLS/QUIC).
// Returns one of the appProto* constants.
func sniffAppProtoGo(peek []byte, l4proto uint8) uint8 { //nolint:gocyclo
	if len(peek) < 5 {
		return appProtoUnknown
	}

	w := uint32(peek[0])<<24 | uint32(peek[1])<<16 | uint32(peek[2])<<8 | uint32(peek[3])
	b4 := peek[4]

	if l4proto == ipprotoTCP { //nolint:nestif
		// HTTP method/response/h2c preface; 5-byte check cuts false positives.
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
		case 0x5353482D: // "SSH-" — SSH version banner (SSH-2.0-*, SSH-1.5-*, …)
			return appProtoSSH
		}

		// TLS record: type ∈ {0x14..0x17}, major=0x03, minor ∈ {0x00..0x04}.
		if (peek[0] == 0x14 || peek[0] == 0x15 || peek[0] == 0x16 || peek[0] == 0x17) &&
			peek[1] == 0x03 && peek[2] <= 0x04 {
			return appProtoTLS
		}

		// RDP: TPKT v3 (03 00) + COTP CR/CC (E0/D0) at byte 5; only initial handshake.
		if peek[0] == 0x03 && peek[1] == 0x00 && len(peek) >= 6 &&
			(peek[5] == 0xE0 || peek[5] == 0xD0) {
			return appProtoRDP
		}

		// Memcached binary: magic 0x80/0x81, opcode <= 0x26 (std+SASL), data_type=0.
		if len(peek) >= 6 && (peek[0] == 0x80 || peek[0] == 0x81) &&
			peek[1] <= 0x26 && peek[5] == 0x00 {
			return appProtoMemcached
		}

		if len(peek) >= 8 {
			w2 := uint32(peek[4])<<24 | uint32(peek[5])<<16 | uint32(peek[6])<<8 | uint32(peek[7])

			// PostgreSQL: bytes[4:8] = v3.0 magic + len in [8, 16MiB), or SSL/GSS magic.
			if (w2 == 0x00030000 && w > 7 && w < 0x01000000) ||
				w2 == 0x04D2162F || w2 == 0x04D2162E {
				return appProtoPostgres
			}

			// MQTT CONNECT: 0x10 + rem-len<128 + name "MQTT" (v3.1.1/5.0) or "MQIsdp" (v3.1).
			if peek[0] == 0x10 && (peek[1]&0x80) == 0 && peek[2] == 0x00 &&
				b4 == 'M' && peek[5] == 'Q' &&
				((peek[3] == 0x04 && peek[6] == 'T' && peek[7] == 'T') ||
					(peek[3] == 0x06 && peek[6] == 'I' && peek[7] == 's' && len(peek) > 10 && peek[10] == 0x03)) {
				return appProtoMQTT
			}
		}
	}

	if l4proto == ipprotoUDP {
		// DTLS record: TLS content types, major=0xFE, minor=0xFF (1.0) or 0xFD (1.2).
		if (peek[0] == 0x14 || peek[0] == 0x15 || peek[0] == 0x16 || peek[0] == 0x17) &&
			peek[1] == 0xFE && (peek[2] == 0xFF || peek[2] == 0xFD) {
			return appProtoTLS
		}

		// QUIC long header (bit 7) + RFC 9000 fixed bit (bit 6).
		// v=1 QUICv1, 0x6B3343CF QUICv2, 0 = version-negotiation sentinel.
		if peek[0]&0xC0 == 0xC0 {
			v := uint32(peek[1])<<24 | uint32(peek[2])<<16 |
				uint32(peek[3])<<8 | uint32(peek[4])
			switch v {
			case 0x00000001, 0x6B3343CF, 0x00000000:
				return appProtoQUIC
			}
		}

		// WireGuard: LE type 1/2/3 (handshake/response/cookie); type 4 excluded.
		if w == 0x01000000 || w == 0x02000000 || w == 0x03000000 {
			return appProtoWireGuard
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
		name    string
		in      []byte
		l4proto uint8
	}{
		{"TLS1.0 Handshake", []byte{0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xFC, 0x03, 0x03, 0x00}, ipprotoTCP},
		{"TLS1.2 ClientHello", []byte{0x16, 0x03, 0x03, 0x00, 0xC8, 0x01, 0x00, 0x00, 0xC4, 0x03, 0x03, 0xAA}, ipprotoTCP},
		{"TLS1.3 ServerHello (record v1.2)", []byte{0x16, 0x03, 0x03, 0x00, 0x7A, 0x02, 0x00, 0x00, 0x76, 0x03, 0x03, 0xBB}, ipprotoTCP},
		{"TLS1.3 ApplicationData", []byte{0x17, 0x03, 0x03, 0x04, 0x1C, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA}, ipprotoTCP},
		{"TLS Alert", []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00}, ipprotoTCP},
		{"TLS ChangeCipherSpec", []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, ipprotoTCP},
		{"DTLS1.0 Handshake", []byte{0x16, 0xFE, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, ipprotoUDP},
		{"DTLS1.2 Handshake", []byte{0x16, 0xFE, 0xFD, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC8}, ipprotoUDP},
		{"DTLS1.0 Alert", []byte{0x15, 0xFE, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}, ipprotoUDP},
		{"DTLS1.2 ApplicationData", []byte{0x17, 0xFE, 0xFD, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00}, ipprotoUDP},
		{"DTLS1.2 ChangeCipherSpec", []byte{0x14, 0xFE, 0xFD, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, ipprotoUDP},
	}

	for _, c := range cases {
		got := sniffAppProtoGo(c.in, c.l4proto)
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
		{"Random binary TCP", []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x12, 0x34, 0x56, 0x78}, ipprotoTCP},
		{"Truncated <5 bytes", []byte{0x16, 0x03, 0x03, 0x00}, ipprotoTCP},
		{"TLS bytes seen on UDP", []byte{0x16, 0x03, 0x03, 0x00, 0xC8, 0x01, 0x00, 0x00, 0xC4, 0x03, 0x03, 0xAA}, ipprotoUDP},
		{"HTTP bytes seen on UDP", []byte("GET / HTTP/1.1\r\n"), ipprotoUDP},
		{"DNS query (TCP-prefixed)", []byte{0x00, 0x1A, 0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}, ipprotoTCP},
		{"NTP packet on UDP", []byte{0x1B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, ipprotoUDP},
		{"QUIC short header (not detected directly)", []byte{0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, ipprotoUDP},
		{"QUIC long header with unknown version", []byte{0xC0, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, ipprotoUDP},
		{"DTLS bytes on TCP (not TLS — major 0xFE != 0x03)", []byte{0x16, 0xFE, 0xFD, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC8}, ipprotoTCP},
		{"DTLS with unknown minor on UDP", []byte{0x16, 0xFE, 0xFC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, ipprotoUDP},
		// Wrong-transport rejections for new protocols.
		{"SSH on UDP", []byte("SSH-2.0-OpenSSH_8\r\n"), ipprotoUDP},
		{"RDP on UDP", []byte{0x03, 0x00, 0x00, 0x2B, 0x26, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, ipprotoUDP},
		{"PostgreSQL on UDP", []byte{0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, ipprotoUDP},
		{"MQTT on UDP", []byte{0x10, 0x23, 0x00, 0x04, 0x4D, 0x51, 0x54, 0x54, 0x04, 0x02, 0x00, 0x3C}, ipprotoUDP},
		{"WireGuard type 1 on TCP", []byte{0x01, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00}, ipprotoTCP},
		// WireGuard type 4 (transport data) is intentionally not detected.
		{"WireGuard transport data on UDP", []byte{0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, ipprotoUDP},
		// Memcached: invalid magic, out-of-range opcode.
		{"Memcached unknown magic", []byte{0x82, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03}, ipprotoTCP},
		{"Memcached opcode out of range", []byte{0x80, 0x30, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03}, ipprotoTCP},
		// MQTT: 2-byte remaining-length (bit 7 set) not detected.
		{"MQTT 2-byte remaining length", []byte{0x10, 0x80, 0x01, 0x04, 0x4D, 0x51, 0x54, 0x54, 0x04, 0x02, 0x00, 0x3C}, ipprotoTCP},
		// MQTT 3.1: name-len=6 but bytes[6:8] != "Is" — must not match.
		{"MQTT 3.1 protocol name mismatch", []byte{0x10, 0x2C, 0x00, 0x06, 0x4D, 0x51, 0x58, 0x59, 0x03, 0x02, 0x00, 0x00}, ipprotoTCP},
		// Memcached binary magic bytes only match on TCP, not UDP.
		{"Memcached binary on UDP", []byte{0x80, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03}, ipprotoUDP},
		// Memcached opcode 0x27 is the first value above the accepted range.
		{"Memcached opcode at boundary 0x27", []byte{0x80, 0x27, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, ipprotoTCP},
		// PostgreSQL version 3.0: length field = 0 (< 8) must not match.
		{"PostgreSQL version 3.0 invalid length", []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, ipprotoTCP},
		// MQTT 3.1: correct "MQIsdp" name but protocol level byte (byte 10) != 0x03.
		{"MQTT 3.1 wrong protocol level", []byte{0x10, 0x2C, 0x00, 0x06, 0x4D, 0x51, 0x49, 0x73, 0x64, 0x70, 0x04, 0x02}, ipprotoTCP},
		// Memcached binary: valid magic and opcode, but data_type (byte 5) != 0x00.
		{"Memcached non-zero data_type", []byte{0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, ipprotoTCP},
	}

	for _, c := range cases {
		got := sniffAppProtoGo(c.in, c.l4proto)
		if got != appProtoUnknown {
			t.Errorf("%s: got %d, want UNKNOWN", c.name, got)
		}
	}
}

func TestSniffAppProtoSSH(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   []byte
	}{
		{"SSHv2 client banner", []byte("SSH-2.0-OpenSSH_8.4\r\n")},
		{"SSHv2 server banner", []byte("SSH-2.0-dropbear_2022.83\r\n")},
		{"SSHv1 legacy banner", []byte("SSH-1.5-1.2.27\r\n")},
	}

	for _, c := range cases {
		got := sniffAppProtoGo(c.in[:min(12, len(c.in))], ipprotoTCP)
		if got != appProtoSSH {
			t.Errorf("%s: got %d, want SSH (%d)", c.name, got, appProtoSSH)
		}
	}
}

func TestSniffAppProtoRDP(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   []byte
	}{
		// TPKT(03 00 00 len) + COTP CR (e0) or CC (d0) at byte 5.
		{"RDP Connection Request", []byte{0x03, 0x00, 0x00, 0x2B, 0x26, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{"RDP Connection Confirm", []byte{0x03, 0x00, 0x00, 0x0B, 0x06, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
	}

	for _, c := range cases {
		got := sniffAppProtoGo(c.in, ipprotoTCP)
		if got != appProtoRDP {
			t.Errorf("%s: got %d, want RDP (%d)", c.name, got, appProtoRDP)
		}
	}
}

func TestSniffAppProtoPostgres(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   []byte
	}{
		// StartupMessage: length(4) + protocol version 3.0 at bytes 4-7.
		{"PostgreSQL v3 StartupMessage", []byte{0x00, 0x00, 0x00, 0x65, 0x00, 0x03, 0x00, 0x00, 0x75, 0x73, 0x65, 0x72}},
		// SSL request: 8-byte message, magic 0x04D2162F at bytes 4-7.
		{"PostgreSQL SSL request", []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xD2, 0x16, 0x2F, 0x00, 0x00, 0x00, 0x00}},
		// GSS encryption request: magic 0x04D2162E at bytes 4-7.
		{"PostgreSQL GSS request", []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xD2, 0x16, 0x2E, 0x00, 0x00, 0x00, 0x00}},
	}

	for _, c := range cases {
		got := sniffAppProtoGo(c.in, ipprotoTCP)
		if got != appProtoPostgres {
			t.Errorf("%s: got %d, want PostgreSQL (%d)", c.name, got, appProtoPostgres)
		}
	}
}

func TestSniffAppProtoMQTT(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   []byte
	}{
		// MQTT 3.1.1 CONNECT: hdr=0x10, rl=0x23, name-len=0x0004, "MQTT", level=0x04.
		{"MQTT 3.1.1 CONNECT", []byte{0x10, 0x23, 0x00, 0x04, 0x4D, 0x51, 0x54, 0x54, 0x04, 0x02, 0x00, 0x3C}},
		// MQTT 5.0 uses the same "MQTT" name but protocol level = 0x05.
		{"MQTT 5.0 CONNECT", []byte{0x10, 0x1D, 0x00, 0x04, 0x4D, 0x51, 0x54, 0x54, 0x05, 0x02, 0x00, 0x3C}},
		// MQTT 3.1 uses "MQIsdp" (6-byte name, length = 0x0006).
		{"MQTT 3.1 CONNECT", []byte{0x10, 0x2C, 0x00, 0x06, 0x4D, 0x51, 0x49, 0x73, 0x64, 0x70, 0x03, 0x02}},
	}

	for _, c := range cases {
		got := sniffAppProtoGo(c.in, ipprotoTCP)
		if got != appProtoMQTT {
			t.Errorf("%s: got %d, want MQTT (%d)", c.name, got, appProtoMQTT)
		}
	}
}

func TestSniffAppProtoWireGuard(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   []byte
	}{
		// Type 1 = Handshake Initiation: LE uint32 = {0x01,0x00,0x00,0x00}.
		{"WireGuard Handshake Initiation", []byte{0x01, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00}},
		// Type 2 = Handshake Response.
		{"WireGuard Handshake Response", []byte{0x02, 0x00, 0x00, 0x00, 0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x00}},
		// Type 3 = Cookie Reply.
		{"WireGuard Cookie Reply", []byte{0x03, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00}},
	}

	for _, c := range cases {
		got := sniffAppProtoGo(c.in, ipprotoUDP)
		if got != appProtoWireGuard {
			t.Errorf("%s: got %d, want WireGuard (%d)", c.name, got, appProtoWireGuard)
		}
	}
}

func TestSniffAppProtoMemcached(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   []byte
	}{
		// Binary request: magic=0x80, opcode=GET(0x00), key-len=3, extras-len=0.
		{"Memcached GET request", []byte{0x80, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03}},
		// Binary request: opcode=SET(0x01), extras-len=8 (flags+expiry).
		{"Memcached SET request", []byte{0x80, 0x01, 0x00, 0x03, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13}},
		// Binary response: magic=0x81, opcode=GET(0x00), extras-len=4 (flags).
		{"Memcached GET response", []byte{0x81, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09}},
		// SASL boundary: 0x20 (List Mechs) and 0x26 (Step), accepted endpoints.
		{"Memcached SASL List Mechs (opcode 0x20)", []byte{0x80, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{"Memcached SASL Step (opcode 0x26)", []byte{0x80, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
	}

	for _, c := range cases {
		got := sniffAppProtoGo(c.in, ipprotoTCP)
		if got != appProtoMemcached {
			t.Errorf("%s: got %d, want Memcached (%d)", c.name, got, appProtoMemcached)
		}
	}
}
