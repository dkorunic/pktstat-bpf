# AGENTS.md

## Setup & Build

```sh
task build          # fmt + compile (CGO_ENABLED=0, PGO, stripped, version vars)
task build-debug    # fmt + compile with -race (CGO_ENABLED=1)
task test           # go test ./...
GOTMPDIR=/root/tmp go test -run TestXxx ./...  # single test
task lint           # fmt + golangci-lint v2
task fmt            # gci + gofumpt + betteralign (commit prerequisite)
task generate       # go generate (recompile eBPF C → Go; requires clang)
```

`task generate` recompile's eBPF C → `*_bpfel.go` + `*_bpfel.o` for both amd64/arm64. **Always commit both Go and .o files for both architectures** after regenerating. Requires `contrib/{amd64,arm64}/vmlinux.h` (gitignored locally — fetch or symlink before running).

## Architecture

Two layers: **eBPF (C, `bpf/`)** + **userland (Go, `main`)**. Four mutually-exclusive capture modes (precedence: `--cgroup > --kprobes > --xdp > TC default).

- `bpf/counter_common.h` — shared core: types, maps, protocol parsers, `sniff_app_proto`, all used by every BPF program.
- `map.go` — single iteration path for all modes via `tcStatkey`/`tcStatvalue` (all generated objects share struct layout).
- `cgroup.go` — `cgroup-id → path` cache via perf reader + `/sys/fs/cgroup` walk.
- `output.go` — `processMap`, sorters, `MarshalJSON` decodes protocol-packed port fields into named keys.

## Must-Know Gotchas

- **`sniff_test.go`** is the Go mirror of `bpf/counter_common.h` `sniff_app_proto`. Any BPF sniffer change must be reflected byte-identically here. Same for `helpers_test.go` ↔ BPF protocol decoders.
- **L7 constants** (`APP_PROTO_*` in `bpf/counter.h`) must stay in lockstep with `appProto*` Go constants in `helpers.go`.
- **Inline attributes in BPF**: `detect_and_cache_l7` (TC/XDP path) must be `always_inline` (packet pointers can't cross call boundaries). `detect_and_cache_l7_skb`, `process_l4_skb`, `extract_tcp_flowkey_skb` must be `noinline` (6.12+ verifier).
- **`pkt_count`** is `BPF_MAP_TYPE_LRU_PERCPU_HASH` — always sum per-CPU slots. Iteration may return `ErrIterationAborted` under churn (soft error).
- **`flow_app_proto` key pad field** (`tcFlowkey._pad`, 3 bytes) must be zero — kernel compares keys byte-for-byte.
- **`bpf2go -target amd64`** produces `*_x86_bpfel.*`, not `*_amd64_bpfel.*`.
- **XDP NIC reset on detach** — run under `screen`/`tmux`.
- **Map struct sync** — `map.go` reads `pkt_count` using `tcStatkey`/`tcStatvalue` across all modes. If you split `counter_common.h`, keep these structs identical.
- Load-time BPF variable patching (`applyCgrpfsMagic`, `applyMaxEntries`, `applyArpEnabled`) happens in `main.go` before `LoadAndAssign` via `spec.Variables`.
- `output_test.go` has an `init()` that sets `useKProbes`/`useCGroup` flags to nil/false — don't remove it without understanding the deref path.

## Style

- Formatter: `gci → gofumpt → betteralign`. Run `task fmt` before committing.
- Linting: `golangci-lint` v2 with `default: all` minus linters in `.golangci.yml`. ~32 pre-existing warnings tolerated.
- No CGO in production. PGO enabled in release builds.

## Full Flag Reference

`--tui`/`-g` TUI · `--json` JSON output · `--kprobes` KProbes mode · `--cgroup <path>` CGroup mode · `--xdp` XDP mode · `--xdp_mode {auto,generic,native,offload}` · `--iface <name>` · `--refresh <d>` · `--timeout <d>` · `--max-entries N` · `--no-arp` · `--version`
