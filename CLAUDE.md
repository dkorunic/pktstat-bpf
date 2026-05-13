# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build System

This project uses [go-task](https://taskfile.dev) (`Taskfile.yml`) as the build orchestrator.

```sh
task build          # fmt + compile (CGO_ENABLED=0, PGO, stripped, version vars injected)
task build-debug    # fmt + compile with race detector (CGO_ENABLED=1)
task lint           # fmt + golangci-lint v2 (timeout 5m)
task lint-nil       # fmt + nilaway
task fmt            # gci + gofumpt + betteralign (Go sources)
task fmt-bpf        # clang-format on bpf/*.c / bpf/*.h (requires clang-format v15+)
task generate       # go generate (recompile eBPF C → Go; requires clang)
task modernize      # gopls modernize -fix -test ./...
task update         # go get -u && go mod tidy
task release        # goreleaser release --clean -p 4
```

Plain `go build` also works for the Go userland (pre-compiled eBPF objects are committed). The default `task` runs `update` then `build`.

## Testing

```sh
GOTMPDIR=/root/tmp go test ./...                       # run all Go unit tests
GOTMPDIR=/root/tmp go test -run TestOSPFTypeName ./... # run a single test
```

Tests live in three files:
- `helpers_test.go` — protocol decoder helpers (`ospfTypeName`, `arpOpName`, `greInnerName`).
- `output_test.go` — `outputPlain` / `MarshalJSON` formatting for protocols that pack metadata into port fields (ESP/AH SPI, ARP opcode, OSPF type/version, GRE inner protocol/flags). Has an `init()` that pre-points `useKProbes` and `useCGroup` to false/empty so `outputPlain` doesn't deref nil flag pointers.
- `sniff_test.go` — `sniffAppProtoGo`, a byte-for-byte Go mirror of the BPF `sniff_app_proto` C function. `TestSniffAppProtoPositives` / `TestSniffAppProtoNegatives` validate L7 signature matching. Any change to the BPF sniffer must be reflected here.

The eBPF C code has no Go-side tests — it is validated only by the kernel verifier at load time.

## Architecture Overview

pktstat-bpf is a Linux eBPF packet statistics tool with two layers:

**eBPF layer (C, in `bpf/`):**
- `bpf/counter.h` — protocol constants: `ETH_P_*`, `IPPROTO_*`, `PROTO_ARP_FAKE` (254), `PROTO_TCP_RETX` (253), `APP_PROTO_*` L7 identifiers (0–9), `L7_PEEK_LEN` (12), `MAX_ENTRIES` (131072). **The `APP_PROTO_*` values must stay in lockstep with the `appProto*` Go constants in `helpers.go`.**
- `bpf/counter_common.h` — shared types and helpers used by all counter programs: `statkey` / `statvalue` / `flowkey` structs; the `pkt_count` map (`BPF_MAP_TYPE_LRU_PERCPU_HASH`) and `flow_app_proto` map (`BPF_MAP_TYPE_LRU_HASH`, 5-tuple → `uint8` app-proto); IPv4-mapped-IPv6 encoding; ARP/ESP/AH/GRE/OSPF parsers; `sniff_app_proto` (pure-logic L7 byte-pattern matcher); `detect_and_cache_l7` (TC/XDP direct packet access path); `detect_and_cache_l7_skb` / `extract_tcp_flowkey_skb` / `sniff_tcp_skb` (KProbe skb path); runtime-patchable globals (`cgrpfs_magic`, `arp_enabled`).
- `bpf/tc.bpf.c` — TC (TCX ingress+egress) counter program.
- `bpf/xdp.bpf.c` — XDP (ingress only) counter program.
- `bpf/kprobe.bpf.c` — per-process TCP/UDP/ICMP/IP-layer KProbes with PID + CGroup tracking; uses `process_l4_skb` and `sniff_tcp_skb` from `counter_common.h`.
- `bpf/cgroup_skb.bpf.c` — CGroup SKB ingress/egress + `inet_sock_create` / `inet_sock_release` for PID attribution.
- `bpf/cgroup.bpf.c` — raw tracepoint on `cgroup_mkdir` that pushes new cgroup path events to userspace via a perf buffer; shared by KProbes and CGroup modes.

**Userland layer (Go, root package `main`):**
- `gen.go` — `//go:generate` directives invoke `bpf2go` for each `.bpf.c` × {amd64, arm64}, producing `tc_`, `xdp_`, `kprobe_`, `cgroupSkb`, and `cgroup` prefixed `*_{x86,arm64}_bpfel.{go,o}` files. Note: `bpf2go -target amd64` writes files with the `_x86_` suffix.
- `main.go` — entry point; selects capture mode, loads only the eBPF object(s) needed for that mode, wires up links, runs TUI or CLI loop. `loadAndPatchSpec` applies `applyCgrpfsMagic`, `applyMaxEntries`, `applyArpEnabled` uniformly.
- `probe.go` — `startTC`, `startXDP`, `startKProbes`, `startCgroup`, `startCGroupTrace`: attach eBPF programs and gate on `features.HaveProgramType`.
- `map.go` — reads `pkt_count` (prefers `BatchLookup` ≥5.6, falls back to iterator) and `flow_app_proto` (`readFlowAppProto` dispatches to `readFlowAppProtoBatch` / `readFlowAppProtoIter`). `statkeyToFlowkey` builds the 5-tuple `tcFlowkey` from a `tcStatkey` (remapping proto 253→6 for retransmits). `addStats` performs a primary lookup then a reverse-direction fallback for TCP rows when the flow was cached from the opposite kprobe direction.
- `cgroup.go` — `cgroup-id → path` cache populated by walking `/sys/fs/cgroup` and consuming `cgroup_mkdir` perf events.
- `output.go` — `processMap`, sort functions, `outputPlain`/`outputJSON`, bitrate formatting, and the `MarshalJSON` override that decodes protocol-packed port fields into named JSON keys.
- `tui.go` — rivo/tview TUI refreshed on `--refresh` interval. Column `l7` (index 4) shows the `AppProto` field.
- `flags.go` — flag parsing via `peterbourgon/ff/v4`; exposes package-level pointers (`useXDP`, `useKProbes`, `useCGroup`, `maxEntries`, `noARP`, …).
- `types.go` — `statEntry` (per-flow stats, includes `AppProto string`) and `kprobeHook`.
- `helpers.go` — `bytesToAddr`, `protoToString` (with `protoNames` table), `findFirstEtherIface`, protocol-decoder helpers `ospfTypeName`/`arpOpName`/`greInnerName`, and the `appProto*` constants + `appProtoToString` for L7 display.
- `init.go` — version variables (`GitTag`, `GitCommit`, `GitDirty`, `BuildTime`) injected at link time.
- `sniff_test.go` — Go mirror of `sniff_app_proto`; must be kept byte-identical with the BPF C implementation.

### Cross-cutting patterns

- **Canonical map types**. `map.go` reads `pkt_count` using `tcStatkey`/`tcStatvalue` even in XDP/KProbes/CGroup modes. All five generated object packages declare structurally identical Go structs because they all include `bpf/counter_common.h`, so a single iteration path serves every mode. Keep these structs in sync if you ever split the C header.
- **Per-CPU read collapse**. `pkt_count` is `BPF_MAP_TYPE_LRU_PERCPU_HASH`: every lookup returns `possibleCPUs` slots. `sumPerCPUValue` aggregates them — don't read raw slots into a scalar without summing.
- **L7 detection dual implementation**. `sniff_app_proto` in `bpf/counter_common.h` and `sniffAppProtoGo` in `sniff_test.go` must remain byte-identical. The BPF path (TC/XDP) uses `detect_and_cache_l7` with direct packet access; the KProbe path uses `detect_and_cache_l7_skb` + `bpf_probe_read_kernel`. Both write to `flow_app_proto` under `BPF_NOEXIST` — concurrent writers for the same flow always produce the same value so races are harmless.
- **flow_app_proto map**. `BPF_MAP_TYPE_LRU_HASH` (non-per-CPU), keyed by `tcFlowkey` (5-tuple: srcip/dstip/src_port/dst_port/proto + 3-byte explicit pad). `applyMaxEntries` patches it alongside `pkt_count` and `sock_info`. In KProbes mode, L7 is cached from either the send (`ip_local_out`) or receive (`ip_rcv`) path; `addStats` in `map.go` tries the reverse-direction key on a miss to reconcile this.
- **Load-time BPF variable patching**. Before `LoadAndAssign`, `main.go` rewrites BPF `volatile const` globals via `spec.Variables[...]`:
  - `applyCgrpfsMagic` — selects cgroup-v1 vs v2 code path; verifier folds the unused branch.
  - `applyMaxEntries` — overrides `pkt_count`, `sock_info`, and `flow_app_proto` map sizes from `--max-entries`.
  - `applyArpEnabled` — disables ARP capture in TC/XDP when `--no-arp` is set.
- **Mode precedence**. When multiple capture-mode flags are passed, `main.go`'s switch picks the first match in order `--cgroup > --kprobes > --xdp > TC (default)` and logs a warning; it does not error.

## Capture Modes

Four mutually-exclusive modes selected at runtime:

| Flag | Mode | Kernel req |
|------|------|-----------|
| *(default)* | TC (TCX ingress + egress) | ≥6.6 |
| `--xdp` | XDP (ingress only, no egress stats) | ≥5.9 |
| `--kprobes` | KProbes + PID/CGroup tracking | ≥4.10 + BTF |
| `--cgroup <path>` | CGroup SKB + PID tracking | ≥4.10 + BTF |

Notable runtime knobs: `--xdp_mode {auto,generic,native,offload}`, `--max-entries N` (overrides BPF map size), `--no-arp` (skips ARP dispatch in TC/XDP), `--tui` / `-g` (interactive), `--json`, `--timeout`, `--refresh`.

## Code Style & Tooling

- **Formatter chain**: `gci` (import grouping) → `gofumpt` (strict gofmt) → `betteralign` (struct field alignment). Run `task fmt` before committing.
- **Linter**: `golangci-lint` v2 with `default: all` minus the linters listed in `.golangci.yml` (cyclop, depguard, dupl, exhaustruct, forbidigo, funlen, gochecknoglobals, gocognit, lll, varnamelen, wrapcheck). Run `task lint`. The branch carries ~32 pre-existing lint warnings that are not expected to grow.
- **No CGO** in production builds (`CGO_ENABLED=0`, set in `Taskfile.yml`). CGO is only re-enabled for `task build-debug` (race detector).
- **eBPF code generation**: only needed when changing `bpf/*.c` or `bpf/*.h`. Requires `clang` and the arch-specific BTF headers under `contrib/{amd64,arm64}/vmlinux.h` (gitignored locally — fetch or symlink before running `task generate`). After regeneration, commit both `*_bpfel.go` and `*_bpfel.o` for both architectures.
- **Modernize**: `task modernize` runs the gopls modernize analyzer with `-fix -test`.
- **`task fmt-bpf` is broken** on machines with clang-format < v15 (the `.clang-format` file uses v15+ subfield syntax). Skip it; `task generate` and `task build` are the meaningful validation gates for BPF C changes.

## eBPF Gotchas

- `process_l4_skb` and `extract_tcp_flowkey_skb` (skb-form parsers in `counter_common.h`) must be `__attribute__((noinline))`. On kernel 6.12 the inlined form trips `R3 !read_ok` verifier errors when called from multi-arg kprobes like `ip_local_out`.
- `detect_and_cache_l7_skb` must also be `__attribute__((noinline))` for the same reason — keep it `noinline` unless re-tested across all supported kernels.
- `detect_and_cache_l7` (the TC/XDP direct-access path) must be `__attribute__((always_inline))`. Direct packet access pointers (`PTR_TO_PACKET` / `PTR_TO_PACKET_END`) cannot cross BPF-to-BPF call boundaries — the verifier loses their type information when passed as arguments to a `noinline` sub-program.
- `pkt_count` is per-CPU and LRU; iteration via `BPF_MAP_TYPE_LRU_PERCPU_HASH` can return `ebpf.ErrIterationAborted` under churn. `main.go` treats that as a soft error and prints "output may be incomplete".
- `flow_app_proto` is `BPF_MAP_TYPE_LRU_HASH` (non-per-CPU). Its `tcFlowkey` has an explicit 3-byte `_pad` field — the kernel compares map keys byte-for-byte, so the pad must always be zero. Go struct literals leave unset fields at zero; be careful with any manual key construction.
- XDP detaches may reset the NIC on exit on some drivers — README recommends running under `screen`/`tmux`. Don't expect a clean interface state if you Ctrl-C during high traffic.
- `bpf2go -target amd64` writes `*_x86_bpfel.{go,o}`, not `*_amd64_bpfel.*`. The `gen.go` directives and produced filenames are the source of truth.
