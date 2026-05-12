// @license
// Copyright (C) 2024  Dinko Korunic
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

//go:build ignore

#pragma once

#define s6_addr in6_u.u6_addr8
#define s6_addr16 in6_u.u6_addr16
#define s6_addr32 in6_u.u6_addr32
#define inet_num sk.__sk_common.skc_num

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define TC_ACT_UNSPEC -1
#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_ICMPV6 58

#define OK 1
#define NOK 0
#define ALLOW_PKT 1
#define ALLOW_SK 1

#define TASK_COMM_LEN 16
#define MAX_ENTRIES 131072

// IPv6 extension header protocol numbers
#define IPPROTO_HOPOPTS 0
#define IPPROTO_ROUTING 43
#define IPPROTO_FRAGMENT 44
#define IPPROTO_DSTOPTS 60

// ARP EtherType (RFC 826).
#define ETH_P_ARP 0x0806

// VLAN tag EtherTypes (802.1Q single, 802.1ad outer).
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8

// IP protocols decoded beyond TCP/UDP/ICMP.
#define IPPROTO_GRE 47
#define IPPROTO_ESP 50
#define IPPROTO_AH 51
#define IPPROTO_OSPF 89

// Synthetic statkey.proto values (254 IANA-reserved, 253 unassigned).
// 254=ARP (L2-only). 253=TCP retransmission.
#define PROTO_ARP_FAKE 254
#define PROTO_TCP_RETX 253

// GRE flag bits (RFC 2784/2890). Stored in dst_port by parse_gre.
#define GRE_FLAG_CHECKSUM 0x8000
#define GRE_FLAG_KEY 0x2000
#define GRE_FLAG_SEQUENCE 0x1000

// L7 app-proto identifiers stored as values in flow_app_proto. Mirror in
// helpers.go (appProto*). Keep these in lockstep with the Go side.
#define APP_PROTO_UNKNOWN 0
#define APP_PROTO_HTTP    1
#define APP_PROTO_TLS     2
#define APP_PROTO_QUIC    3

// Bytes peeked from the L4 payload for L7 signature matching. 12 is the
// minimum that covers QUIC (1 form byte + 4 version bytes + slack) and gives
// HTTP/TLS the 5-byte disambiguation window described in
// docs/superpowers/specs/2026-05-12-l7-protocol-detection-design.md.
#define L7_PEEK_LEN 12

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
