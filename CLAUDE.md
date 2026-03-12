# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build System

This project uses [go-task](https://taskfile.dev) (`Taskfile.yml`) as the build orchestrator.

```sh
task build          # fmt + compile (CGO_ENABLED=0, PGO, stripped)
task build-debug    # fmt + compile with race detector (CGO_ENABLED=1)
task lint           # fmt + golangci-lint
task fmt            # gci + gofumpt + betteralign (Go sources)
task fmt-bpf        # clang-format on bpf/*.c / bpf/*.h
task generate       # go generate (recompile eBPF C → Go; requires clang)
task update         # go get -u && go mod tidy
```

Plain `go build` also works for the Go userland (pre-compiled eBPF objects are committed).

## Architecture Overview

pktstat-bpf is a Linux eBPF packet statistics tool. It has two layers:

**eBPF layer (C, in `bpf/`):**
- `bpf/tc.bpf.c` — packet/byte counting via TC (TCX ingress+egress).
- `bpf/xdp.bpf.c` — packet/byte counting via XDP (ingress only).
- `bpf/kprobe.bpf.c` — per-process TCP/UDP/ICMP stats via KProbes with PID/CGroup tracking.
- `bpf/cgroup_skb.bpf.c` — packet/byte counting via CGroup SKB hooks.
- `bpf/cgroup.bpf.c` — raw tracepoint on `cgroup_mkdir` to push new CGroup path events to userspace via perf buffer; shared by both KProbes and CGroup modes.

**Userland layer (Go, root package `main`):**
- `gen.go` — `//go:generate` directives that invoke `bpf2go` to compile each `.bpf.c` for `amd64` and `arm64`, producing `tc_`, `xdp_`, `kprobe_`, `cgroupskb_`, and `cgroup_` prefixed `*_{x86,arm64}_bpfel.{go,o}` files (bpf2go maps `-target amd64` → `x86` in filenames).
- `main.go` — program entry: loads both eBPF objects, resolves interface, selects capture mode (TC / XDP / KProbes / CGroup), runs TUI or CLI loop.
- `probe.go` — `startTC`, `startXDP`, `startKProbes`, `startCgroup`, `startCGroupTrace`: attach eBPF programs to hooks.
- `map.go` — reads `PktCount` eBPF LRU hash map; prefers `BatchLookup` (kernel ≥5.6), falls back to iterator.
- `cgroup.go` — builds and maintains a `cgroup-id → path` cache by walking `/sys/fs/cgroup` and consuming perf events from `cgroup.bpf.c`.
- `output.go` — `processMap`, sort functions (`bitrateSort`, etc.), `outputPlain`/`outputJSON`, bitrate formatting.
- `tui.go` — rivo/tview TUI, refreshed on `--refresh` interval.
- `flags.go` — flag parsing via `peterbourgon/ff/v4`; sets package-level pointers used throughout.
- `types.go` — `statEntry` (per-flow stats struct) and `kprobeHook`.
- `helpers.go` — `bytesToAddr`, `protoToString`, `findFirstEtherIface`.
- `init.go` — version variables (`GitTag`, `GitCommit`, …) injected at link time.

## Capture Modes

Four mutually-exclusive modes selected at runtime:

| Flag | Mode | Kernel req |
|------|------|-----------|
| *(default)* | TC (TCX ingress + egress) | ≥6.6 |
| `--xdp` | XDP (ingress only, no egress stats) | ≥5.9 |
| `--kprobes` | KProbes + PID/CGroup tracking | ≥4.10 + BTF |
| `--cgroup <path>` | CGroup SKB + PID tracking | ≥4.10 + BTF |

## Code Style & Tooling

- **Formatter chain**: `gci` (import grouping) → `gofumpt` (strict gofmt) → `betteralign` (struct field alignment). Run `task fmt` before committing.
- **Linter**: `golangci-lint` v2 with `default: all` minus a handful of disabled linters listed in `.golangci.yml`. Run `task lint`.
- **No CGO** in production builds (`CGO_ENABLED=0`). CGO is only re-enabled for the race-detector build.
- **eBPF code generation**: only needed when changing `bpf/*.c` or `bpf/*.h`. Requires `clang` and the arch-specific BTF headers under `contrib/`. Run `task generate` then commit the updated `*_bpfel.{go,o}` files.
- The `contrib/` directory contains vendored kernel BTF/vmlinux headers split by architecture (`amd64/`, `arm64/`).
