# L7 Protocol Detection (HTTP / TLS / QUIC) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add identification-only L7 detection for HTTP, TLS, and QUIC in eBPF across all four capture modes (TC, XDP, KProbes, CGroup-SKB) and surface the result as a new `L7` column in plain/TUI output and an `app_proto` field in JSON.

**Architecture:** Two-map split. The existing `pkt_count` map is unchanged. A new `flow_app_proto` LRU hash keyed by 5-tuple stores one canonical L7 label per flow. Detection runs on the eBPF hot path (port-agnostic, peeks 12 bytes of L4 payload, runs a shared `sniff_app_proto` helper) and writes to `flow_app_proto`. Userspace reads both maps and joins on 5-tuple at output time.

**Tech Stack:** C (libbpf, kernel ≥4.10 BTF, kernel ≥5.9 for XDP / ≥6.6 for TCX), Go 1.22+, cilium/ebpf, rivo/tview, peterbourgon/ff/v4, go-task build orchestrator.

**Reference spec:** `docs/superpowers/specs/2026-05-12-l7-protocol-detection-design.md`

**Commit conventions (this repo):** Imperative subject under ~70 chars, no body required for small changes. Recent examples: `Fix cgroup cache clobber, reduce TUI allocs, tighten interfaces`, `Add ARP, ESP, AH, GRE, OSPF protocol support`. Tasks below include commit messages following this style.

**Do not run `task generate` or `task build` until the relevant eBPF C code is in place** — premature generation will overwrite `*_bpfel.{go,o}` with stale content and stale-bind userspace.

---

## Task 1: Add Go-side app_proto constants and `appProtoToString` helper

**Files:**
- Modify: `helpers.go` (append after `greInnerName`)
- Modify: `helpers_test.go` (append at end)

- [ ] **Step 1: Write the failing test**

Append to `helpers_test.go`:

```go
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
```

- [ ] **Step 2: Run test, verify it fails to compile**

Run: `go test -run TestAppProtoToString ./...`
Expected: build failure — `undefined: appProtoUnknown`, `undefined: appProtoToString`.

- [ ] **Step 3: Implement constants and helper in `helpers.go`**

Append to `helpers.go` (after `greInnerName`, before `bytesToAddr`):

```go
// L7 app-proto identifiers. Must match the APP_PROTO_* #defines in
// bpf/counter.h. Stored as uint8 values in the flow_app_proto BPF map.
const (
	appProtoUnknown uint8 = 0
	appProtoHTTP    uint8 = 1
	appProtoTLS     uint8 = 2
	appProtoQUIC    uint8 = 3
)

// appProtoNames maps the app-proto enum to display strings. Unknown
// returns "" so callers can suppress the column / JSON field naturally.
var appProtoNames = [...]string{
	appProtoUnknown: "",
	appProtoHTTP:    "HTTP",
	appProtoTLS:     "TLS",
	appProtoQUIC:    "QUIC",
}

// appProtoToString returns the display name for an L7 app-proto identifier.
// Out-of-range values return "" so they are omitted from output uniformly.
func appProtoToString(p uint8) string {
	if int(p) >= len(appProtoNames) {
		return ""
	}

	return appProtoNames[p]
}
```

- [ ] **Step 4: Run test, verify it passes**

Run: `go test -run TestAppProtoToString ./...`
Expected: `PASS`.

- [ ] **Step 5: Commit**

```bash
git add helpers.go helpers_test.go
git commit -m "Add appProtoToString helper and app-proto constants"
```

---

## Task 2: Add `AppProto` field to `statEntry`

**Files:**
- Modify: `types.go:30-42`

- [ ] **Step 1: Add the field**

Edit `types.go`, replacing the `statEntry` struct definition with:

```go
type statEntry struct {
	SrcIP    netip.Addr `json:"srcIp"`
	DstIP    netip.Addr `json:"dstIp"`
	Proto    string     `json:"proto"`
	Comm     string     `json:"comm,omitempty"`
	CGroup   string     `json:"cgroup,omitempty"`
	AppProto string     `json:"appProto,omitempty"`
	Bytes    uint64     `json:"bytes"`
	Packets  uint64     `json:"packets"`
	Bitrate  float64    `json:"bitrate"`
	Pid      int32      `json:"pid,omitempty"`
	SrcPort  uint16     `json:"srcPort"`
	DstPort  uint16     `json:"dstPort"`
}
```

(`AppProto` placed with the other string fields; `betteralign` may reorder slightly during `task fmt`, which is fine.)

- [ ] **Step 2: Verify the package still builds**

Run: `go build ./...`
Expected: succeeds with no errors.

- [ ] **Step 3: Run existing tests to confirm nothing regressed**

Run: `go test ./...`
Expected: all existing tests still pass. The `TestStatEntryJSON_TCPBackwardsCompat` test specifically checks that no unexpected JSON fields appear — `appProto` is `omitempty`, so an empty `AppProto` doesn't break it.

- [ ] **Step 4: Commit**

```bash
git add types.go
git commit -m "Add AppProto field to statEntry"
```

---

## Task 3: Add Go contract sniffer + golden-byte tests

The C `sniff_app_proto` is verified only by the kernel verifier at load time and can't be unit-tested from Go. This Task creates a Go port (in `_test.go` only) plus golden-byte cases. The Go port and the C implementation must stay byte-identical; the test is the contract.

**Files:**
- Create: `sniff_test.go`

- [ ] **Step 1: Write the failing tests and Go contract sniffer**

Create `sniff_test.go`:

```go
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

	if l4proto == ipprotoTCP {
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
```

- [ ] **Step 2: Run tests, verify they pass**

Run: `go test -run TestSniffAppProto ./...`
Expected: all four `TestSniffAppProto*` tests pass.

- [ ] **Step 3: Commit**

```bash
git add sniff_test.go
git commit -m "Add Go contract sniffer and L7 detection golden tests"
```

---

## Task 4: Add C-side app_proto constants and L7_PEEK_LEN

**Files:**
- Modify: `bpf/counter.h` (after the synthetic-proto block near the end)

- [ ] **Step 1: Add the constants**

Append to `bpf/counter.h` (before the `likely`/`unlikely` macros at line 75–76):

```c
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
```

- [ ] **Step 2: Commit**

```bash
git add bpf/counter.h
git commit -m "Add APP_PROTO_* constants and L7_PEEK_LEN to counter.h"
```

---

## Task 5: Add `flowkey` struct and `flow_app_proto` map

**Files:**
- Modify: `bpf/counter_common.h` (after `pkt_count` definition at line 51)

- [ ] **Step 1: Add the type and map**

Insert into `bpf/counter_common.h`, immediately after the closing brace of the `pkt_count SEC(".maps")` declaration (i.e. after line 51) and before the `sockinfo` typedef:

```c
// Process-agnostic 5-tuple key for the flow_app_proto cache. PID/cgroup are
// intentionally absent — L7 protocol is a property of the flow, not the
// process. Trailing pad is explicit so layout is stable across compilers.
typedef struct flowkey_t {
  struct in6_addr srcip;
  struct in6_addr dstip;
  __u16 src_port;
  __u16 dst_port;
  __u8  proto;
  __u8  _pad[3];
} flowkey;

// flow_app_proto caches the detected L7 app-proto per 5-tuple. NOT per-CPU:
// detection is rare-write/heavy-read and we want one canonical answer per
// flow visible to every CPU. Sized via the same MAX_ENTRIES knob as
// pkt_count (applyMaxEntries patches both at load time).
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, flowkey);
  __type(value, __u8);
} flow_app_proto SEC(".maps");
```

- [ ] **Step 2: Commit**

```bash
git add bpf/counter_common.h
git commit -m "Add flowkey struct and flow_app_proto BPF map"
```

---

## Task 6: Implement `sniff_app_proto` in C

**Files:**
- Modify: `bpf/counter_common.h` (after the `parse_ospf` block at line 134)

- [ ] **Step 1: Add `sniff_app_proto`**

Insert into `bpf/counter_common.h`, immediately before the `parse_arp` definition (line ~136), keeping it grouped with the other small protocol parsers:

```c
// sniff_app_proto identifies HTTP, TLS, or QUIC from a pre-read L7 payload
// prefix. Pure logic over a fixed-size buffer — no memory access, no map
// calls. The caller is responsible for filling `buf` from packet payload
// (direct access in TC/XDP/CGroup-SKB) or kernel skb (bpf_probe_read_kernel
// in KProbes). Keep byte-identical with sniffAppProtoGo in sniff_test.go.
static inline __attribute__((always_inline)) __u8
sniff_app_proto(const __u8 *buf, __u32 peek_len, __u8 l4_proto) {
  if (unlikely(peek_len < 5)) {
    return APP_PROTO_UNKNOWN;
  }

  __u32 w = ((__u32)buf[0] << 24) | ((__u32)buf[1] << 16) |
            ((__u32)buf[2] << 8) | (__u32)buf[3];
  __u8 b4 = buf[4];

  if (l4_proto == IPPROTO_TCP) {
    switch (w) {
    case 0x47455420: // "GET "
    case 0x50555420: // "PUT "
    case 0x50524920: // "PRI "
      return APP_PROTO_HTTP;
    case 0x504F5354: // "POST"
      if (b4 == ' ') return APP_PROTO_HTTP;
      break;
    case 0x48454144: // "HEAD"
      if (b4 == ' ') return APP_PROTO_HTTP;
      break;
    case 0x4F505449: // "OPTI"
      if (b4 == 'O') return APP_PROTO_HTTP;
      break;
    case 0x44454C45: // "DELE"
      if (b4 == 'T') return APP_PROTO_HTTP;
      break;
    case 0x50415443: // "PATC"
      if (b4 == 'H') return APP_PROTO_HTTP;
      break;
    case 0x434F4E4E: // "CONN"
      if (b4 == 'E') return APP_PROTO_HTTP;
      break;
    case 0x54524143: // "TRAC"
      if (b4 == 'E') return APP_PROTO_HTTP;
      break;
    case 0x48545450: // "HTTP"
      if (b4 == '/') return APP_PROTO_HTTP;
      break;
    }

    // TLS record: type ∈ {0x14..0x17}, major=0x03, minor ∈ {0x00..0x04}.
    if ((buf[0] == 0x14 || buf[0] == 0x15 || buf[0] == 0x16 ||
         buf[0] == 0x17) &&
        buf[1] == 0x03 && buf[2] <= 0x04) {
      return APP_PROTO_TLS;
    }
  }

  if (l4_proto == IPPROTO_UDP) {
    // QUIC long header form (bit 7) + RFC 9000 fixed bit (bit 6).
    if ((buf[0] & 0xC0) == 0xC0) {
      __u32 v = ((__u32)buf[1] << 24) | ((__u32)buf[2] << 16) |
                ((__u32)buf[3] << 8) | (__u32)buf[4];
      if (v == 0x00000001 || v == 0x6B3343CF || v == 0x00000000) {
        return APP_PROTO_QUIC;
      }
    }
  }

  return APP_PROTO_UNKNOWN;
}
```

- [ ] **Step 2: Commit**

```bash
git add bpf/counter_common.h
git commit -m "Add sniff_app_proto C helper for HTTP/TLS/QUIC detection"
```

---

## Task 7: Implement `detect_and_cache_l7` (direct-access path)

**Files:**
- Modify: `bpf/counter_common.h` (after `sniff_app_proto` from Task 6)

- [ ] **Step 1: Add the direct-access wrapper**

Append immediately after `sniff_app_proto`:

```c
// detect_and_cache_l7 fills flow_app_proto for the flow described by `key`
// using direct packet access. Called from process_ip4/process_ip6 in the
// TCP/UDP cases. `transport` points to the L4 header; `l4_hdr_len` is its
// computed byte length (TCP doff*4, UDP 8). Bounds-checks against data_end.
//
// Skips the sniff when the flow is already cached, so the per-packet cost
// after the first detected packet is one map lookup.
static inline __attribute__((always_inline)) void
detect_and_cache_l7(void *transport, void *data_end,
                    __u8 l4_proto, __u32 l4_hdr_len, const statkey *key) {
  flowkey fk = {};
  fk.srcip = key->srcip;
  fk.dstip = key->dstip;
  fk.src_port = key->src_port;
  fk.dst_port = key->dst_port;
  fk.proto = key->proto;

  if (bpf_map_lookup_elem(&flow_app_proto, &fk) != NULL) {
    return;
  }

  void *payload = transport + l4_hdr_len;
  if (unlikely(payload + L7_PEEK_LEN > data_end)) {
    return;
  }

  __u8 buf[L7_PEEK_LEN];
  __builtin_memcpy(buf, payload, L7_PEEK_LEN);

  __u8 app = sniff_app_proto(buf, L7_PEEK_LEN, l4_proto);
  if (app != APP_PROTO_UNKNOWN) {
    bpf_map_update_elem(&flow_app_proto, &fk, &app, BPF_ANY);
  }
}
```

- [ ] **Step 2: Commit**

```bash
git add bpf/counter_common.h
git commit -m "Add detect_and_cache_l7 direct-access wrapper"
```

---

## Task 8: Implement `detect_and_cache_l7_skb` (skb-form path)

**Files:**
- Modify: `bpf/counter_common.h` (after `detect_and_cache_l7` from Task 7)

- [ ] **Step 1: Add the skb-form wrapper**

Append immediately after `detect_and_cache_l7`:

```c
// detect_and_cache_l7_skb is the skb-form counterpart for KProbes. Reads the
// L7 peek via bpf_probe_read_kernel (sk_buff payload is kernel memory).
// `payload_off` is the byte offset from skb->head to the L7 payload start
// (caller computes from transport_header + L4 hdr len).
//
// noinline: an inlined version of the body trips the same "R3 !read_ok"
// verifier issue on kernel 6.12 that process_l4_skb works around. Keep
// noinline unless re-tested across all supported kernels.
static __attribute__((noinline)) void
detect_and_cache_l7_skb(struct sk_buff *skb, __u32 payload_off,
                        __u8 l4_proto, const statkey *key) {
  flowkey fk = {};
  fk.srcip = key->srcip;
  fk.dstip = key->dstip;
  fk.src_port = key->src_port;
  fk.dst_port = key->dst_port;
  fk.proto = key->proto;

  if (bpf_map_lookup_elem(&flow_app_proto, &fk) != NULL) {
    return;
  }

  unsigned char *head = (unsigned char *)BPF_CORE_READ(skb, head);

  __u8 buf[L7_PEEK_LEN];
  if (bpf_probe_read_kernel(buf, sizeof(buf), head + payload_off) != 0) {
    return;
  }

  __u8 app = sniff_app_proto(buf, L7_PEEK_LEN, l4_proto);
  if (app != APP_PROTO_UNKNOWN) {
    bpf_map_update_elem(&flow_app_proto, &fk, &app, BPF_ANY);
  }
}
```

- [ ] **Step 2: Commit**

```bash
git add bpf/counter_common.h
git commit -m "Add detect_and_cache_l7_skb noinline kprobe wrapper"
```

---

## Task 9: Wire `detect_and_cache_l7` into `process_ip4` and `process_ip6`

**Files:**
- Modify: `bpf/counter_common.h:198-216` (TCP/UDP cases in `process_ip4`)
- Modify: `bpf/counter_common.h:273-291` (TCP/UDP cases in `process_ip6`)

- [ ] **Step 1: Wire TCP case in `process_ip4`**

In `process_ip4`, replace the existing TCP case (currently lines ~199-207):

```c
  case IPPROTO_TCP: {
    struct tcphdr *tcp = transport;
    if (unlikely((void *)tcp + sizeof(*tcp) > data_end)) {
      return NOK;
    }
    key->src_port = bpf_ntohs(tcp->source);
    key->dst_port = bpf_ntohs(tcp->dest);
    break;
  }
```

with:

```c
  case IPPROTO_TCP: {
    struct tcphdr *tcp = transport;
    if (unlikely((void *)tcp + sizeof(*tcp) > data_end)) {
      return NOK;
    }
    key->src_port = bpf_ntohs(tcp->source);
    key->dst_port = bpf_ntohs(tcp->dest);

    // doff is the TCP data offset in 32-bit words; <5 is malformed.
    __u8 doff = tcp->doff;
    if (likely(doff >= 5)) {
      detect_and_cache_l7(transport, data_end, IPPROTO_TCP,
                          (__u32)doff * 4, key);
    }
    break;
  }
```

- [ ] **Step 2: Wire UDP case in `process_ip4`**

In `process_ip4`, replace the existing UDP case (currently lines ~208-216) with:

```c
  case IPPROTO_UDP: {
    struct udphdr *udp = transport;
    if (unlikely((void *)udp + sizeof(*udp) > data_end)) {
      return NOK;
    }
    key->src_port = bpf_ntohs(udp->source);
    key->dst_port = bpf_ntohs(udp->dest);
    detect_and_cache_l7(transport, data_end, IPPROTO_UDP,
                        (__u32)sizeof(*udp), key);
    break;
  }
```

- [ ] **Step 3: Wire TCP case in `process_ip6`**

In `process_ip6`, replace the existing TCP case (currently lines ~274-282) with the same pattern:

```c
  case IPPROTO_TCP: {
    struct tcphdr *tcp = transport;
    if (unlikely((void *)tcp + sizeof(*tcp) > data_end)) {
      return NOK;
    }
    key->src_port = bpf_ntohs(tcp->source);
    key->dst_port = bpf_ntohs(tcp->dest);

    __u8 doff = tcp->doff;
    if (likely(doff >= 5)) {
      detect_and_cache_l7(transport, data_end, IPPROTO_TCP,
                          (__u32)doff * 4, key);
    }
    break;
  }
```

- [ ] **Step 4: Wire UDP case in `process_ip6`**

In `process_ip6`, replace the existing UDP case (currently lines ~283-291) with:

```c
  case IPPROTO_UDP: {
    struct udphdr *udp = transport;
    if (unlikely((void *)udp + sizeof(*udp) > data_end)) {
      return NOK;
    }
    key->src_port = bpf_ntohs(udp->source);
    key->dst_port = bpf_ntohs(udp->dest);
    detect_and_cache_l7(transport, data_end, IPPROTO_UDP,
                        (__u32)sizeof(*udp), key);
    break;
  }
```

- [ ] **Step 5: Commit**

```bash
git add bpf/counter_common.h
git commit -m "Wire L7 detection into process_ip4 and process_ip6"
```

---

## Task 10: Wire `detect_and_cache_l7_skb` into KProbes UDP hooks (QUIC)

**Files:**
- Modify: `bpf/kprobe.bpf.c:80-132` (`ip_send_skb`, `ip6_send_skb`)
- Modify: `bpf/kprobe.bpf.c:134-156` (`skb_consume_udp`)

For UDP, the existing hooks already have skb access and call `process_udp_send`/`process_udp_recv` which set `key->src_port`/`key->dst_port` from the udphdr. We add a `detect_and_cache_l7_skb` call right after the existing `update_val` call.

The payload offset is `skb->transport_header + sizeof(struct udphdr)`.

- [ ] **Step 1: Wire `ip_send_skb`**

In `bpf/kprobe.bpf.c`, locate the `ip_send_skb` function (around line 80) and replace its body's `update_val(&key, msglen);` line and what follows with:

```c
  update_val(&key, msglen);

  __u16 th_off = BPF_CORE_READ(skb, transport_header);
  detect_and_cache_l7_skb(skb, (__u32)th_off + (__u32)sizeof(struct udphdr),
                          IPPROTO_UDP, &key);

  return 0;
```

- [ ] **Step 2: Wire `ip6_send_skb`**

In `bpf/kprobe.bpf.c`, locate the `ip6_send_skb` function (around line 107) and replace its body's `update_val(&key, msglen);` line and what follows with:

```c
  update_val(&key, msglen);

  __u16 th_off = BPF_CORE_READ(skb, transport_header);
  detect_and_cache_l7_skb(skb, (__u32)th_off + (__u32)sizeof(struct udphdr),
                          IPPROTO_UDP, &key);

  return 0;
```

- [ ] **Step 3: Wire `skb_consume_udp`**

In `skb_consume_udp` (around line 134), replace `update_val(&key, len);` and what follows with:

```c
  update_val(&key, len);

  __u16 th_off = BPF_CORE_READ(skb, transport_header);
  detect_and_cache_l7_skb(skb, (__u32)th_off + (__u32)sizeof(struct udphdr),
                          IPPROTO_UDP, &key);

  return 0;
```

- [ ] **Step 4: Commit**

```bash
git add bpf/kprobe.bpf.c
git commit -m "Wire QUIC detection into KProbes UDP hooks"
```

---

## Task 11: Wire TCP-payload detection into KProbes IP hooks

The TCP-side KProbes (`tcp_sendmsg`/`tcp_cleanup_rbuf`) lack accessible skb payload. Detection runs instead from `ip_local_out`/`ip_rcv`/`ip6_local_out`/`ipv6_rcv`, which fire for *all* outgoing/incoming IP packets and already have full skb access. Today they short-circuit on non-ESP/AH/GRE/OSPF via `process_l4_skb`. We add a parallel TCP/UDP branch that ONLY writes `flow_app_proto`, never `pkt_count` — `tcp_sendmsg` and the UDP hooks remain the sole writers to `pkt_count`.

**Files:**
- Modify: `bpf/kprobe.bpf.c:287-340` (`ip_local_out`, `ip6_local_out`)
- Modify: `bpf/kprobe.bpf.c:342-397` (`ip_rcv`, `ipv6_rcv`)

The 5-tuple needed for the flow lookup must come from the skb directly because `process_l4_skb` only fills it for ESP/AH/GRE/OSPF. We introduce a new helper, `extract_tcp_flowkey_skb`, that fills a `statkey` with srcip/dstip/src_port/dst_port/proto for a TCP packet (or a UDP packet that didn't go through the dedicated UDP hooks — covers transit routing).

- [ ] **Step 1: Add the TCP-side skb 5-tuple extractor to `counter_common.h`**

Append to `bpf/counter_common.h`, immediately after `detect_and_cache_l7_skb`:

```c
// extract_l4_flowkey_skb fills `key` (srcip, dstip, src_port, dst_port,
// proto) from an skb that has an IPv4 or IPv6 + TCP/UDP header chain.
// Returns the byte offset from skb->head at which the L7 payload begins,
// or 0 if the skb isn't TCP/UDP / isn't well-formed for our purposes.
// Used by the kprobe-side TCP/UDP L7 detection in ip_local_out/ip_rcv.
static __attribute__((noinline)) __u32
extract_l4_flowkey_skb(struct sk_buff *skb, statkey *key) {
  unsigned char *head = (unsigned char *)BPF_CORE_READ(skb, head);
  __u16 nh_off = BPF_CORE_READ(skb, network_header);
  __u16 th_off = BPF_CORE_READ(skb, transport_header);
  __u16 proto_be = BPF_CORE_READ(skb, protocol);

  __u8 ip_proto;
  __u32 l4_hdr_len;

  switch (bpf_ntohs(proto_be)) {
  case ETH_P_IP: {
    struct iphdr *iphdr = (struct iphdr *)(head + nh_off);
    ip_proto = BPF_CORE_READ(iphdr, protocol);
    if (ip_proto != IPPROTO_TCP && ip_proto != IPPROTO_UDP) {
      return 0;
    }
    __be32 sa = BPF_CORE_READ(iphdr, saddr);
    __be32 da = BPF_CORE_READ(iphdr, daddr);
    MAP_V4_IN_V6(key->srcip, sa);
    MAP_V4_IN_V6(key->dstip, da);
    break;
  }
  case ETH_P_IPV6: {
    struct ipv6hdr *iphdr = (struct ipv6hdr *)(head + nh_off);
    ip_proto = BPF_CORE_READ(iphdr, nexthdr);
    if (ip_proto != IPPROTO_TCP && ip_proto != IPPROTO_UDP) {
      return 0;
    }
    BPF_CORE_READ_INTO(&key->srcip, iphdr, saddr);
    BPF_CORE_READ_INTO(&key->dstip, iphdr, daddr);
    break;
  }
  default:
    return 0;
  }

  if (ip_proto == IPPROTO_TCP) {
    struct tcphdr *tcp = (struct tcphdr *)(head + th_off);
    key->src_port = bpf_ntohs(BPF_CORE_READ(tcp, source));
    key->dst_port = bpf_ntohs(BPF_CORE_READ(tcp, dest));
    __u8 doff = BPF_CORE_READ_BITFIELD_PROBED(tcp, doff);
    if (unlikely(doff < 5)) {
      return 0;
    }
    l4_hdr_len = (__u32)doff * 4;
  } else {
    struct udphdr *udp = (struct udphdr *)(head + th_off);
    key->src_port = bpf_ntohs(BPF_CORE_READ(udp, source));
    key->dst_port = bpf_ntohs(BPF_CORE_READ(udp, dest));
    l4_hdr_len = (__u32)sizeof(*udp);
  }

  key->proto = ip_proto;
  return (__u32)th_off + l4_hdr_len;
}
```

- [ ] **Step 2: Add a common helper for the per-hook wiring**

Append immediately after `extract_l4_flowkey_skb`:

```c
// sniff_tcp_udp_skb performs the full L7 detect-and-cache cycle for a TCP
// or UDP packet observed at one of the IP-layer kprobes (ip_local_out/
// ip_rcv/ip6_local_out/ipv6_rcv). It does NOT touch pkt_count — counters
// remain the responsibility of tcp_sendmsg/tcp_cleanup_rbuf for TCP and
// the existing UDP hooks for UDP. Safe to call unconditionally; returns
// immediately if the skb isn't TCP/UDP.
static inline __attribute__((always_inline)) void
sniff_tcp_udp_skb(struct sk_buff *skb) {
  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  __u32 payload_off = extract_l4_flowkey_skb(skb, &key);
  if (payload_off == 0) {
    return;
  }

  detect_and_cache_l7_skb(skb, payload_off, key.proto, &key);
}
```

- [ ] **Step 3: Wire into the four IP-layer kprobes**

In `bpf/kprobe.bpf.c`, find each of `ip_local_out`, `ip6_local_out`, `ip_rcv`, `ipv6_rcv` (lines ~287, ~315, ~344, ~372). In each function, add the new call as the **last** statement before `return 0;`. Example for `ip_local_out`:

```c
SEC("kprobe/ip_local_out")
int BPF_KPROBE(ip_local_out, struct net *net, struct sock *sk,
               struct sk_buff *skb) {
  if (unlikely(!skb)) {
    return 0;
  }

  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  pid_t pid = bpf_get_current_pid_tgid() >> 32;

  size_t msglen = process_l4_skb(skb, &key, pid);
  if (unlikely(msglen == 0)) {
    // process_l4_skb short-circuits non-ESP/AH/GRE/OSPF traffic; for TCP
    // and UDP we still want L7 detection (writes only flow_app_proto).
    sniff_tcp_udp_skb(skb);
    return 0;
  }

  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
  }
  key.cgroupid = get_current_cgroup_id();

  update_val(&key, msglen);

  return 0;
}
```

Apply the same `sniff_tcp_udp_skb(skb);` insertion to the remaining three hooks. For `ip6_local_out` (around line 315), the final body becomes:

```c
SEC("kprobe/ip6_local_out")
int BPF_KPROBE(ip6_local_out, struct net *net, struct sock *sk,
               struct sk_buff *skb) {
  if (unlikely(!skb)) {
    return 0;
  }

  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  pid_t pid = bpf_get_current_pid_tgid() >> 32;

  size_t msglen = process_l4_skb(skb, &key, pid);
  if (unlikely(msglen == 0)) {
    sniff_tcp_udp_skb(skb);
    return 0;
  }

  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
  }
  key.cgroupid = get_current_cgroup_id();

  update_val(&key, msglen);

  return 0;
}
```

For `ip_rcv` (around line 344):

```c
SEC("kprobe/ip_rcv")
int BPF_KPROBE(ip_rcv, struct sk_buff *skb, struct net_device *dev,
               struct packet_type *pt, struct net_device *orig_dev) {
  if (unlikely(!skb)) {
    return 0;
  }

  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  pid_t pid = bpf_get_current_pid_tgid() >> 32;

  size_t msglen = process_l4_skb(skb, &key, pid);
  if (unlikely(msglen == 0)) {
    sniff_tcp_udp_skb(skb);
    return 0;
  }

  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
  }
  key.cgroupid = get_current_cgroup_id();

  update_val(&key, msglen);

  return 0;
}
```

For `ipv6_rcv` (around line 372):

```c
SEC("kprobe/ipv6_rcv")
int BPF_KPROBE(ipv6_rcv, struct sk_buff *skb, struct net_device *dev,
               struct packet_type *pt, struct net_device *orig_dev) {
  if (unlikely(!skb)) {
    return 0;
  }

  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  pid_t pid = bpf_get_current_pid_tgid() >> 32;

  size_t msglen = process_l4_skb(skb, &key, pid);
  if (unlikely(msglen == 0)) {
    sniff_tcp_udp_skb(skb);
    return 0;
  }

  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
  }
  key.cgroupid = get_current_cgroup_id();

  update_val(&key, msglen);

  return 0;
}
```

- [ ] **Step 4: Commit**

```bash
git add bpf/counter_common.h bpf/kprobe.bpf.c
git commit -m "Wire HTTP/TLS detection into KProbes IP-layer hooks"
```

---

## Task 12: Regenerate eBPF Go bindings

**Files:**
- Auto-modified: `tc_x86_bpfel.{go,o}`, `tc_arm64_bpfel.{go,o}`, `xdp_*`, `kprobe_*`, `cgroup_skb_*`, `cgroup_*` — all under the repo root.

- [ ] **Step 1: Verify clang is available**

Run: `clang --version`
Expected: clang 14 or later. If missing, install per CLAUDE.md guidance.

- [ ] **Step 2: Regenerate**

Run: `task generate`
Expected: regenerates `*_bpfel.go` and `*_bpfel.o` for amd64 and arm64. Should print no errors.

- [ ] **Step 3: Verify the generated Go types**

Run: `grep -l 'FlowAppProto' *_bpfel.go`
Expected: matches in `tc_x86_bpfel.go`, `tc_arm64_bpfel.go`, `xdp_x86_bpfel.go`, `xdp_arm64_bpfel.go`, `kprobe_x86_bpfel.go`, `kprobe_arm64_bpfel.go`, `cgroup_skb_x86_bpfel.go`, `cgroup_skb_arm64_bpfel.go` — but NOT in `cgroup_x86_bpfel.go` / `cgroup_arm64_bpfel.go` (cgroup.bpf.c doesn't include counter_common.h).

Also verify: `grep -l 'tcFlowkey\|xdpFlowkey\|kprobeFlowkey\|cgroupSkbFlowkey' *_bpfel.go` matches.

- [ ] **Step 4: Verify the package still compiles (it shouldn't yet — that's fine)**

Run: `go build ./...`
Expected: should still succeed at this point. The new generated types exist; nothing references them yet, so compilation passes.

- [ ] **Step 5: Run the test suite to confirm no regressions**

Run: `go test ./...`
Expected: all tests pass. (Tests don't yet exercise flow_app_proto, but nothing should be broken.)

- [ ] **Step 6: Commit generated files**

```bash
git add *_bpfel.go *_bpfel.o
git commit -m "Regenerate eBPF Go bindings for flow_app_proto map"
```

---

## Task 13: Add canonical `tcFlowkey` type and `readFlowAppProto`

**Files:**
- Modify: `map.go:24-30` (imports — already correct)
- Modify: `map.go` (append helper after `addStats`)

The `map.go` pattern is: every per-mode generated package has structurally identical types, so we pick one (TC) as canonical and use it everywhere. Same approach for the new `tcFlowkey`.

- [ ] **Step 1: Add `readFlowAppProto` to `map.go`**

Append to `map.go` (after `addStats`):

```go
// readFlowAppProto loads the entire flow_app_proto map into a Go map keyed
// by the canonical tcFlowkey type. Iteration uses the same iterator path as
// listMapIterate; the map is small (rare writes, one entry per detected
// flow) and not per-CPU, so BatchLookup is overkill. Returns nil on error;
// callers treat that the same as an empty map (all entries get
// app_proto = "" / unknown).
func readFlowAppProto(m *ebpf.Map) map[tcFlowkey]uint8 {
	if m == nil {
		return nil
	}

	out := make(map[tcFlowkey]uint8, m.MaxEntries()/8) // most flows go un-detected

	var k tcFlowkey
	var v uint8

	iter := m.Iterate()
	for iter.Next(&k, &v) {
		out[k] = v
	}

	// Iteration aborted under churn is non-fatal for L7 labels — the worst
	// case is a few rows missing AppProto until the next refresh.
	_ = iter.Err()

	return out
}

// statkeyToFlowkey derives the canonical 5-tuple flowkey from a tcStatkey.
// Drops PID, comm, and cgroupid — L7 protocol is a property of the flow.
func statkeyToFlowkey(k tcStatkey) tcFlowkey {
	return tcFlowkey{
		Srcip:   k.Srcip,
		Dstip:   k.Dstip,
		SrcPort: k.SrcPort,
		DstPort: k.DstPort,
		Proto:   k.Proto,
	}
}
```

- [ ] **Step 2: Verify the package compiles**

Run: `go build ./...`
Expected: succeeds. (`tcFlowkey`, `Srcip`, `Dstip`, `SrcPort`, `DstPort`, `Proto` fields are generated by bpf2go in Task 12.)

- [ ] **Step 3: Commit**

```bash
git add map.go
git commit -m "Add readFlowAppProto and statkeyToFlowkey helpers"
```

---

## Task 14: Thread `flow_app_proto` join through `processMap`

**Files:**
- Modify: `map.go:128-280` (signatures of `listMap`, `listMapBatch`, `listMapIterate`, `addStats`)
- Modify: `output.go:74-79` (signature of `processMap`)
- Modify: `main.go:264-265` (call site of `processMap`)
- Modify: `tui.go:220` (call site of `processMap`)

- [ ] **Step 1: Update `addStats` to attach `AppProto`**

In `map.go`, replace the `addStats` function with:

```go
// addStats appends a new statEntry constructed from a tcStatkey/tcStatvalue
// pair. appProtoByFlow may be nil; lookup returns the zero value (unknown)
// in that case, producing AppProto: "".
func addStats(stats []statEntry, key tcStatkey, val tcStatvalue,
	appProtoByFlow map[tcFlowkey]uint8, dur float64,
) []statEntry {
	stats = append(stats, statEntry{
		SrcIP:    bytesToAddr(key.Srcip.In6U.U6Addr8),
		DstIP:    bytesToAddr(key.Dstip.In6U.U6Addr8),
		Proto:    protoToString(key.Proto),
		AppProto: appProtoToString(appProtoByFlow[statkeyToFlowkey(key)]),
		SrcPort:  key.SrcPort,
		DstPort:  key.DstPort,
		Bytes:    val.Bytes,
		Packets:  val.Packets,
		Bitrate:  8 * float64(val.Bytes) / dur,
		Pid:      key.Pid,
		Comm:     internComm(key.Comm),
		CGroup:   cGroupToPath(key.Cgroupid),
	})

	return stats
}
```

- [ ] **Step 2: Update `listMapBatch` to accept and forward the join map**

In `map.go`, replace the `listMapBatch` signature and the `addStats` call inside:

```go
func listMapBatch(m *ebpf.Map, appProtoByFlow map[tcFlowkey]uint8,
	start time.Time, buf []statEntry,
) ([]statEntry, error) {
```

and change the call inside the for-loop:

```go
			stats = addStats(stats, keys[i], sumPerCPUValue(perCPU), appProtoByFlow, dur)
```

- [ ] **Step 3: Update `listMapIterate` to accept and forward the join map**

```go
func listMapIterate(m *ebpf.Map, appProtoByFlow map[tcFlowkey]uint8,
	start time.Time, buf []statEntry,
) ([]statEntry, error) {
```

and update its addStats call:

```go
		stats = addStats(stats, key, sumPerCPUValue(val), appProtoByFlow, dur)
```

- [ ] **Step 4: Update `listMap` to accept the L7 map and read it**

```go
func listMap(m *ebpf.Map, l7 *ebpf.Map, start time.Time,
	buf []statEntry,
) ([]statEntry, error) {
	checkBatchMapSupportOnce.Do(func() {
		// ... unchanged body ...
	})

	appProtoByFlow := readFlowAppProto(l7)

	if haveBatchMapSupport {
		return listMapBatch(m, appProtoByFlow, start, buf)
	}

	return listMapIterate(m, appProtoByFlow, start, buf)
}
```

- [ ] **Step 5: Update `processMap` signature in `output.go`**

Replace the function signature and body:

```go
func processMap(m *ebpf.Map, l7 *ebpf.Map, start time.Time,
	sortFunc func([]statEntry), buf []statEntry,
) ([]statEntry, error) {
	stats, err := listMap(m, l7, start, buf)
	sortFunc(stats)

	return stats, err
}
```

- [ ] **Step 6: Update the `processMap` call site in `main.go` (line ~265)**

Threading `flow_app_proto` through requires capturing it from each mode's object set. For now, pass `nil` so existing tests/code still compile; Task 17 wires the real map. The replacement:

```go
		m, err := processMap(pktCount, l7Map, startTime, bitrateSort, nil)
```

Add a `var l7Map *ebpf.Map` declaration near the existing `var pktCount *ebpf.Map` line (~94):

```go
	// Set below from whichever mode-specific BPF object is loaded.
	var pktCount *ebpf.Map
	var l7Map *ebpf.Map
```

- [ ] **Step 7: Update the `processMap` call site in `tui.go` (line ~220)**

In `updateStatsTable`, change the signature to accept an `l7` map, and forward it:

```go
func updateStatsTable(app *tview.Application, table *tview.Table, tableSortIdx *atomic.Int32,
	pktCount *ebpf.Map, l7 *ebpf.Map, startTime time.Time, done <-chan struct{},
) {
```

and at the call site inside the for-loop:

```go
		snapshot, _ := processMap(pktCount, l7, startTime, sortFuncs[tableSortIdx.Load()], statsBufs[bufIdx])
```

Also update `drawTUI` (line ~69) to accept and forward `l7`:

```go
func drawTUI(pktCount *ebpf.Map, l7 *ebpf.Map, startTime time.Time) {
	// ... existing body ...

	go updateStatsTable(app, statsTable, &tableSortIdx, pktCount, l7, startTime, done)
```

And update the `drawTUI` call site in `main.go` (~line 240):

```go
		drawTUI(pktCount, l7Map, startTime)
```

- [ ] **Step 8: Verify package compiles**

Run: `go build ./...`
Expected: succeeds.

- [ ] **Step 9: Run all tests**

Run: `go test ./...`
Expected: all tests pass. Existing tests pass nil for unrelated parameters; `addStats` handles nil map via Go's nil-map semantics (lookup returns zero value).

- [ ] **Step 10: Commit**

```bash
git add map.go output.go main.go tui.go
git commit -m "Thread flow_app_proto join through processMap and TUI"
```

---

## Task 15: Add `L7` column to `outputPlain` + JSON tests

**Files:**
- Modify: `output.go:171-283` (`outputPlain`)
- Modify: `output_test.go` (append new tests)

- [ ] **Step 1: Write the failing test**

Append to `output_test.go`:

```go
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
	// AppProto left empty

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
```

- [ ] **Step 2: Run tests, verify the plain-text ones fail**

Run: `go test -run 'TestOutputPlainAppProto|TestStatEntryJSON_AppProto' ./...`
Expected:
- `TestOutputPlainAppProto` FAILS (no `l7: TLS` substring yet).
- `TestStatEntryJSON_AppProto` PASSES already (struct tag is sufficient — confirmed in Task 2).
- `TestOutputPlainAppProtoEmptyOmitted` PASSES (no rendering of `l7:` exists yet).
- `TestStatEntryJSON_AppProtoOmittedWhenEmpty` PASSES (`omitempty` tag handles this).

- [ ] **Step 3: Implement the `L7` column in `outputPlain`**

In `output.go`, locate the line in `outputPlain` that writes `proto`:

```go
		sb.WriteString(", proto: ")
		sb.WriteString(v.Proto)
```

Insert immediately after (before the `switch v.Proto {`):

```go
		if v.AppProto != "" {
			sb.WriteString(", l7: ")
			sb.WriteString(v.AppProto)
		}
```

- [ ] **Step 4: Run tests, verify they pass**

Run: `go test -run 'TestOutputPlainAppProto|TestStatEntryJSON_AppProto' ./...`
Expected: all 4 pass.

- [ ] **Step 5: Run the full test suite**

Run: `go test ./...`
Expected: all tests pass, including the existing `TestOutputPlain*` and `TestStatEntryJSON_*` tests.

- [ ] **Step 6: Commit**

```bash
git add output.go output_test.go
git commit -m "Render L7 column in outputPlain and JSON"
```

---

## Task 16: Add `L7` column to the TUI

**Files:**
- Modify: `tui.go:179-198` (headers list)
- Modify: `tui.go:275-347` (per-row cell-fill block)

- [ ] **Step 1: Add the `l7` header column**

In `updateStatsTable`, replace the `headers := []string{ ... }` block (around lines 179-191) with:

```go
	headers := []string{
		"bitrate", // column 0
		"packets", // column 1
		"bytes",   // column 2
		"proto",   // column 3
		"l7",      // column 4
		"src",     // column 5
		"dst",     // column 6
		"type",    // column 7
		"code",    // column 8
		"pid",     // column 9, only kprobes and cgroup
		"comm",    // column 10, only kprobes and cgroup
		"cgroup",  // column 11, only kprobes and cgroup
	}

	// Drop pid/comm/cgroup columns when not in --kprobes / --cgroup mode.
	if !*useKProbes && *useCGroup == "" {
		headers = headers[:9]
	}
```

- [ ] **Step 2: Renumber the per-row cell assignments**

In the per-row body (currently lines 275–346), every column index above 3 shifts by +1. Mechanically:

- `row[0]` (bitrate), `row[1]` (packets), `row[2]` (bytes), `row[3]` (proto) — unchanged.
- New `row[4].Text = v.AppProto` — set this once, immediately after `row[3].Text = v.Proto`.
- Old `row[4]`/`row[5]`/`row[6]`/`row[7]` become `row[5]`/`row[6]`/`row[7]`/`row[8]`.
- Old `row[8]`/`row[9]`/`row[10]` (pid/comm/cgroup) become `row[9]`/`row[10]`/`row[11]`.

Apply the renumbering inside the entire `for i, v := range snapshot { ... }` block. Concretely, replace the entire body from `row[0].Text = formatBitrate(v.Bitrate)` down through the `showProcInfo` block with:

```go
				row[0].Text = formatBitrate(v.Bitrate)
				row[1].Text = strconv.FormatUint(v.Packets, 10)
				row[2].Text = strconv.FormatUint(v.Bytes, 10)
				row[3].Text = v.Proto
				row[4].Text = v.AppProto

				switch v.Proto {
				case protoICMPv4, protoICMPv6:
					addrBuf = v.SrcIP.AppendTo(addrBuf[:0])
					row[5].Text = string(addrBuf)
					addrBuf = v.DstIP.AppendTo(addrBuf[:0])
					row[6].Text = string(addrBuf)
					row[7].Text = strconv.Itoa(int(v.SrcPort))
					row[8].Text = strconv.Itoa(int(v.DstPort))
				case protoESP, protoAH:
					addrBuf = v.SrcIP.AppendTo(addrBuf[:0])
					row[5].Text = string(addrBuf)
					addrBuf = v.DstIP.AppendTo(addrBuf[:0])
					row[6].Text = string(addrBuf)
					spi := uint32(v.SrcPort)<<16 | uint32(v.DstPort)
					addrBuf = append(addrBuf[:0], '0', 'x')
					addrBuf = strconv.AppendUint(addrBuf, uint64(spi), 16)
					row[7].Text = string(addrBuf)
					row[8].Text = ""
				case protoGRE:
					addrBuf = v.SrcIP.AppendTo(addrBuf[:0])
					row[5].Text = string(addrBuf)
					addrBuf = v.DstIP.AppendTo(addrBuf[:0])
					row[6].Text = string(addrBuf)
					row[7].Text = greInnerName(v.SrcPort)
					addrBuf = append(addrBuf[:0], '0', 'x')
					addrBuf = appendHex16(addrBuf, v.DstPort)
					row[8].Text = string(addrBuf)
				case protoOSPF:
					addrBuf = v.SrcIP.AppendTo(addrBuf[:0])
					row[5].Text = string(addrBuf)
					addrBuf = v.DstIP.AppendTo(addrBuf[:0])
					row[6].Text = string(addrBuf)
					row[7].Text = ospfTypeName(v.SrcPort)
					addrBuf = append(addrBuf[:0], 'v')
					addrBuf = strconv.AppendUint(addrBuf, uint64(v.DstPort), 10)
					row[8].Text = string(addrBuf)
				case protoARP:
					addrBuf = v.SrcIP.AppendTo(addrBuf[:0])
					row[5].Text = string(addrBuf)
					addrBuf = v.DstIP.AppendTo(addrBuf[:0])
					row[6].Text = string(addrBuf)
					row[7].Text = arpOpName(v.SrcPort)
					row[8].Text = ""
				default:
					addrBuf = v.SrcIP.AppendTo(addrBuf[:0])
					addrBuf = append(addrBuf, ':')
					addrBuf = strconv.AppendUint(addrBuf, uint64(v.SrcPort), 10)
					row[5].Text = string(addrBuf)

					addrBuf = v.DstIP.AppendTo(addrBuf[:0])
					addrBuf = append(addrBuf, ':')
					addrBuf = strconv.AppendUint(addrBuf, uint64(v.DstPort), 10)
					row[6].Text = string(addrBuf)

					row[7].Text = ""
					row[8].Text = ""
				}

				if showProcInfo {
					pidStr := ""
					if v.Pid > 0 {
						pidStr = strconv.FormatInt(int64(v.Pid), 10)
					}

					row[9].Text = pidStr
					row[10].Text = v.Comm
					row[11].Text = v.CGroup
				}
```

- [ ] **Step 3: Verify the package compiles**

Run: `go build ./...`
Expected: succeeds.

- [ ] **Step 4: Commit**

```bash
git add tui.go
git commit -m "Add L7 column to TUI between proto and src"
```

---

## Task 17: Load `flow_app_proto` per mode in `main.go`

**Files:**
- Modify: `main.go:96-231` (the switch over capture modes)

- [ ] **Step 1: Assign `l7Map` from each mode's object set**

In `main.go`, inside the switch over capture modes, locate each `pktCount = ...` assignment and add a parallel `l7Map = ...` line. Apply:

For `case *useCGroup != "":` (around line 113):
```go
		pktCount = objsCgroupSkb.PktCount
		l7Map = objsCgroupSkb.FlowAppProto
```

For `case *useKProbes:` (around line 152):
```go
		pktCount = objsKprobe.PktCount
		l7Map = objsKprobe.FlowAppProto
```

For `case *useXDP:` (around line 208):
```go
		pktCount = objsXDP.PktCount
		l7Map = objsXDP.FlowAppProto
```

For the `default:` (TC) branch (around line 228):
```go
		pktCount = objsTC.PktCount
		l7Map = objsTC.FlowAppProto
```

- [ ] **Step 2: Patch `flow_app_proto` size in `applyMaxEntries`**

In `main.go`, update the maps list in `applyMaxEntries` (around line 338):

```go
	for _, name := range [...]string{"pkt_count", "sock_info", "flow_app_proto"} {
```

- [ ] **Step 3: Verify the package compiles**

Run: `go build ./...`
Expected: succeeds.

- [ ] **Step 4: Verify the binary runs (sanity)**

Run: `./pktstat-bpf --version`
Expected: prints version info without crashing. (Does not load any eBPF program.)

- [ ] **Step 5: Commit**

```bash
git add main.go
git commit -m "Load flow_app_proto map per capture mode"
```

---

## Task 18: Final verification — build, lint, smoke test

**Files:** none modified in this Task — verification only.

- [ ] **Step 1: Format the codebase**

Run: `task fmt`
Expected: `gci` + `gofumpt` + `betteralign` succeed. Any formatting changes applied are expected (e.g., `betteralign` may reorder `statEntry` fields).

If `task fmt` modifies files, stage and commit them:

```bash
git add -u
git commit -m "Apply task fmt"
```

- [ ] **Step 2: Lint**

Run: `task lint`
Expected: golangci-lint completes; same pre-existing issue count as recorded in `MEMORY.md` (≤7 issues), no new findings.

If new lint findings appear that are clearly attributable to this work, fix them with another commit.

- [ ] **Step 3: Build**

Run: `task build`
Expected: `pktstat-bpf` binary produced without errors. The binary embeds the regenerated eBPF objects.

- [ ] **Step 4: Smoke test in TC mode**

Run (in a shell with elevated privileges):
```bash
sudo ./pktstat-bpf -i <interface> --timeout 10s --json | head -50
```

Expected: JSON entries are emitted; some entries on port 443 should carry `"appProto":"TLS"` (assuming there is ambient TLS traffic), and entries on port 80 may carry `"appProto":"HTTP"`. UDP/443 may carry `"appProto":"QUIC"` when there is HTTP/3 traffic. Entries with no detected L7 should NOT have an `appProto` field (omitempty).

If no traffic on the interface is HTTP/TLS/QUIC, generate some:
```bash
curl -s https://example.com >/dev/null      # TLS
curl -s --http3-only https://cloudflare.com  # QUIC, requires curl with HTTP/3
curl -s http://example.com >/dev/null       # plaintext HTTP
```

- [ ] **Step 5: Smoke test in XDP mode**

Run: `sudo ./pktstat-bpf --xdp -i <interface> --timeout 10s --json | head -50`
Expected: same — `appProto` populates correctly on detected flows.

- [ ] **Step 6: Smoke test in KProbes mode**

Run: `sudo ./pktstat-bpf --kprobes --timeout 10s --json | head -50`
Expected: `appProto` populates on TCP flows (HTTP/TLS detected via the IP-layer kprobe sniff) and on UDP flows (QUIC detected via the UDP-layer kprobes).

- [ ] **Step 7: Smoke test in CGroup mode**

Run (requires cgroup v2):
```bash
sudo ./pktstat-bpf --cgroup /sys/fs/cgroup --timeout 10s --json | head -50
```
Expected: `appProto` populates correctly.

- [ ] **Step 8: Verify the TUI**

Run: `sudo ./pktstat-bpf -i <interface> --tui`
Expected: the `l7` column appears between `proto` and `src`. Traffic with detectable L7 shows `HTTP`/`TLS`/`QUIC`; unknown rows show empty cell. Quit with `q`.

- [ ] **Step 9: Done**

No commit in this Task — verification only. If `task fmt` produced changes in Step 1, those were already committed.

---

## Summary

This plan implements identification-only L7 protocol detection across all four eBPF capture modes via:

1. A new `flow_app_proto` LRU hash that maps 5-tuple → app-proto enum (1 byte).
2. A shared `sniff_app_proto` helper with HTTP / TLS / QUIC signatures, called from two thin wrappers: direct-access (`detect_and_cache_l7` for TC/XDP/CGroup-SKB) and skb-form (`detect_and_cache_l7_skb` for KProbes), with the latter `noinline` for kernel-6.12 verifier compatibility.
3. Userspace plumbing through `readFlowAppProto` → `addStats` → `statEntry.AppProto`, surfaced as an `L7` column in plain/TUI output and an `appProto` JSON field (omitted when empty).
4. A Go contract sniffer in `sniff_test.go` with golden bytes, locked byte-identically to the C implementation.
