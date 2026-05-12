# L7 protocol detection (HTTP / TLS / QUIC) — design

Status: design, awaiting plan
Date: 2026-05-12
Scope: identification-only L7 detection across all four capture modes (TC, XDP, KProbes, CGroup-SKB)

## Goals

1. Identify each TCP/UDP flow as HTTP, TLS, QUIC, or unknown.
2. Work in every capture mode (TC, XDP, KProbes, CGroup-SKB).
3. Inspect any port (no allow-list of well-known ports).
4. Produce one canonical L7 label per flow, not per packet.
5. Surface results as a new `L7` column in plain/TUI output and as a JSON `app_proto` field.

## Non-goals

- SNI / Host / ALPN extraction.
- JA3 / JA4 fingerprinting.
- HTTP/2 over TLS detection (encrypted; not feasible without ALPN extraction).
- QUIC short-header packet detection outside the flow cache.
- Direction canonicalization in `flow_app_proto` — both directions write the same value, accepted as small duplication.
- DPI for non-TCP/UDP transports.

## Architecture

Two BPF maps:

- `pkt_count` (existing) — per-CPU LRU hash, key = `statkey`, value = `statvalue`. Unchanged.
- `flow_app_proto` (new) — LRU hash (not per-CPU), key = `flowkey`, value = `__u8` (app-proto enum).

`flow_app_proto` is read-mostly and rarely written (one write per flow, on the first detected packet), so per-CPU is unnecessary and would split the canonical value across CPUs.

Userspace reads both maps, builds `map[flowkey]uint8` from `flow_app_proto`, then joins it onto `pkt_count` rows by 5-tuple while producing `statEntry` records.

### Data flow

```
TC/XDP/CGroup-SKB ─► process_ip4/ip6 ─► (detect_and_cache_l7) ─► flow_app_proto
                                     └► update_val ─────────────► pkt_count

KProbes (TCP)    ─► tcp_sendmsg/tcp_cleanup_rbuf ─► update_val ──► pkt_count
                 ─► ip_local_out/ip_rcv (extended) ─► (detect_and_cache_l7_skb) ─► flow_app_proto

KProbes (UDP)    ─► ip_send_skb/ip6_send_skb/skb_consume_udp
                       ├─► update_val ──────────────────────────► pkt_count
                       └─► detect_and_cache_l7_skb ──────────────► flow_app_proto
```

Detection and per-PID accounting are deliberately decoupled: they write to different maps and may run at different hooks. This is why detection in KProbes mode lives at `ip_local_out`/`ip_rcv` (which have the assembled skb) rather than at `tcp_sendmsg` (which exposes only userspace iovecs and would require `bpf_copy_from_user` + sleepable kprobes).

## New data structures

`bpf/counter.h`:

```c
#define APP_PROTO_UNKNOWN 0
#define APP_PROTO_HTTP    1
#define APP_PROTO_TLS     2
#define APP_PROTO_QUIC    3
#define L7_PEEK_LEN       12
```

`bpf/counter_common.h`:

```c
typedef struct flowkey_t {
  struct in6_addr srcip;
  struct in6_addr dstip;
  __u16 src_port;
  __u16 dst_port;
  __u8  proto;
  __u8  _pad[3];
} flowkey;

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, flowkey);
  __type(value, __u8);
} flow_app_proto SEC(".maps");
```

Padding to 4 bytes makes the layout stable across compilers. `MAX_ENTRIES` is the existing runtime-patchable constant (`applyMaxEntries`); a single knob sizes both maps.

## Detection signatures

All three live in a single inline function:

```c
static inline __attribute__((always_inline)) __u8
sniff_app_proto(const __u8 *buf, __u32 peek_len, __u8 l4_proto);
```

The function operates on a pre-read buffer. Callers handle the memory access (direct packet access for TC/XDP/CGroup-SKB, `bpf_probe_read_kernel` for KProbes).

### HTTP (TCP)

First 4 payload bytes ∈ {
`"GET "`, `"POST"`, `"HEAD"`, `"PUT "`, `"OPTI"`, `"DELE"`, `"PATC"`, `"CONN"`, `"TRAC"`, `"HTTP"`, `"PRI "`
}. Covers:

- HTTP/1.x request methods.
- HTTP/1.x responses (`HTTP/1.0`, `HTTP/1.1`).
- h2c preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`).

False-positive risk is low because random binary TCP payloads rarely start with these exact ASCII tetrads.

### TLS (TCP)

- `buf[0] ∈ {0x14, 0x15, 0x16, 0x17}` — ChangeCipherSpec / Alert / Handshake / ApplicationData.
- `buf[1] == 0x03` — TLS major version.
- `buf[2] <= 0x04` — SSL 3.0 / TLS 1.0–1.3.

Catches both new handshakes and packets joining mid-stream.

### QUIC (UDP)

- `(buf[0] & 0xC0) == 0xC0` — long-header form bit + RFC 9000 fixed bit.
- 32-bit version field `buf[1..4]` (big-endian) ∈ {`0x00000001` (QUICv1), `0x6B3343CF` (QUICv2), `0x00000000` (Version Negotiation)}.

Short-header QUIC packets are not matched directly; they hit the flow cache once the Initial packet has labeled the flow.

## eBPF callsite changes

### Shared helpers (counter_common.h)

```c
// Direct-access path. Builds a flowkey from `key`, looks up flow_app_proto;
// on miss, peeks L7_PEEK_LEN bytes from `transport + l4_hdr_len`, runs
// sniff_app_proto, stores result on detection.
static inline __attribute__((always_inline)) void
detect_and_cache_l7(void *transport, void *data_end,
                    __u8 l4_proto, __u32 l4_hdr_len,
                    const statkey *key);

// skb-form variant. Uses bpf_probe_read_kernel for the peek. noinline for
// the same R3-read_ok verifier reason as process_l4_skb on kernel 6.12.
static __attribute__((noinline)) void
detect_and_cache_l7_skb(struct sk_buff *skb, __u32 payload_off,
                        __u8 l4_proto, const statkey *key);
```

Both:

1. Compose `flowkey` from `statkey` (drop comm/pid/cgroupid).
2. `bpf_map_lookup_elem(&flow_app_proto, &flowkey)` — return if hit.
3. Peek `L7_PEEK_LEN` bytes (direct access vs probe_read).
4. `sniff_app_proto(buf, n, l4_proto)`.
5. On non-zero result, `bpf_map_update_elem(&flow_app_proto, &flowkey, &app, BPF_ANY)`.

### Wiring per mode

| Hook | File | Change |
|---|---|---|
| `process_ip4`, `process_ip6` (TCP / UDP cases) | counter_common.h | Add `detect_and_cache_l7` call after ports are set. Computes `l4_hdr_len` from `tcp->doff*4` or `sizeof(udphdr)`. |
| `ip_local_out`, `ip_rcv`, `ip6_local_out`, `ipv6_rcv` | kprobe.bpf.c | Existing behavior is preserved: `process_l4_skb` still short-circuits on non-ESP/AH/GRE/OSPF and `pkt_count` is updated only for those. New behavior added in parallel: when the IP proto is TCP or UDP, also call `detect_and_cache_l7_skb`. The new call writes only to `flow_app_proto`, never to `pkt_count` — preventing double-counting against `tcp_sendmsg` / `tcp_cleanup_rbuf` / UDP hooks. |
| `ip_send_skb`, `ip6_send_skb`, `skb_consume_udp` | kprobe.bpf.c | Add `detect_and_cache_l7_skb` call after the existing UDP processing (QUIC detection). |
| `tcp_sendmsg`, `tcp_cleanup_rbuf` | kprobe.bpf.c | Unchanged. Payload not accessible here. |
| `tc.bpf.c`, `xdp.bpf.c`, `cgroup_skb.bpf.c` | — | Unchanged. They flow through `process_eth` → `process_ip4`/`process_ip6`. |

### Verifier considerations

- Direct-access path: bounds-check `transport + l4_hdr_len + L7_PEEK_LEN <= data_end` before reading.
- skb path: `bpf_probe_read_kernel(buf, L7_PEEK_LEN, ...)` is safe; verifier counts the call as a single read regardless of length.
- All loops inside `sniff_app_proto` are unrolled or branch-only (no variable iteration).
- `detect_and_cache_l7_skb` is `noinline` to avoid the R3 read_ok issue documented in `process_l4_skb`.

## Userland changes

### types.go

```go
type statEntry struct {
  // ... existing fields ...
  AppProto string `json:"appProto,omitempty"`
}
```

### map.go

- Add canonical `tcFlowkey` type alongside `tcStatkey` / `tcStatvalue` (same justification: all per-mode generated packages declare structurally identical `flowkey` because they all include `counter_common.h`).
- Add `readFlowAppProto(m *ebpf.Map) map[tcFlowkey]uint8` — one iteration into a Go map.
- `processMap` signature gains a second `*ebpf.Map` for `flow_app_proto`. For each `pkt_count` row, derive a `tcFlowkey` from the row's `statkey` and look up the app-proto.
- `BatchLookup` path for `flow_app_proto` falls back to iterator identically to `pkt_count`.

### helpers.go

```go
var appProtoNames = [...]string{
  APP_PROTO_UNKNOWN: "",
  APP_PROTO_HTTP:    "HTTP",
  APP_PROTO_TLS:     "TLS",
  APP_PROTO_QUIC:    "QUIC",
}

func appProtoToString(p uint8) string {
  if int(p) >= len(appProtoNames) {
    return ""
  }
  return appProtoNames[p]
}
```

Constants `APP_PROTO_*` mirror the C `#define`s.

### output.go

- Plain text: new `L7` column between `PROTO` and `SRC PORT`. Empty string when unknown.
- JSON: existing `MarshalJSON` override does not need changes — it only manipulates port-packed pseudo-protocols. The new `app_proto` field is emitted by default `json.Marshal` via the struct tag.
- Column-width math in `outputPlain` adjusted for the new column.

### tui.go

- New column header `L7`, populated from `statEntry.AppProto`.

### main.go

- Loads `flow_app_proto` from each mode's `ebpf.Collection`:
  - TC mode: `tcObjects.FlowAppProto`
  - XDP mode: `xdpObjects.FlowAppProto`
  - KProbes mode: `kprobeObjects.FlowAppProto`
  - CGroup mode: `cgroupSkbObjects.FlowAppProto`
- Passes the `*ebpf.Map` to `drawTUI`, `outputPlain`, `outputJSON` alongside `pktCount`.

### gen.go

No change. `bpf2go` automatically discovers the new map.

## Testing

- `helpers_test.go`: add `TestAppProtoToString` covering known values + out-of-range.
- New `sniff_test.go`: Go port of `sniff_app_proto`'s logic, fed with captured-real-traffic golden bytes:
  - HTTP/1.1 request: `GET / HTTP/1.1\r\n`
  - HTTP/1.1 response: `HTTP/1.1 200 OK\r\n`
  - h2c preface: `PRI * HTTP/2.0\r\n\r\n`
  - TLS 1.2 ClientHello first 12 bytes
  - TLS 1.3 ApplicationData first 12 bytes
  - QUICv1 Initial first 12 bytes (long header, version 0x00000001)
  - Negative cases: random binary, SSH banner (`SSH-2.0-...`), DNS query, NTP packet
  The C implementation and the Go test port must stay byte-identical; the test is the contract for both.
- `output_test.go`: extend `outputPlain` and JSON cases with a populated `flow_app_proto` join map; assert the `L7` column appears and `app_proto` field is present/omitted as expected.
- eBPF C code remains validated only by the kernel verifier at load time (consistent with existing project policy).

## Open questions

None. All design choices have been confirmed:

- Identification only — no metadata extraction (SNI, method, version).
- Two-map design with userspace join.
- Port-agnostic inspection.
- New `L7` column in plain/TUI; `app_proto` field in JSON.
- All four capture modes covered.
- Approach A (shared detector, two callsites).
