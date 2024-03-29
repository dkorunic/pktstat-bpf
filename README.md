# pktstat-bpf

[![GitHub license](https://img.shields.io/github/license/dkorunic/pktstat-bpf)](https://github.com/dkorunic/pktstat-bpf/blob/master/LICENSE)
[![GitHub release](https://img.shields.io/github/release/dkorunic/pktstat-bpf)](https://github.com/dkorunic/pktstat-bpf/releases/latest)

![](gopher.png)

## About

pktstat-bpf is a work in progress simple replacement for ncurses-based [pktstat](https://github.com/dleonard0/pktstat), using eBPF ([extended Berkeley Packet Filter](https://prototype-kernel.readthedocs.io/en/latest/bpf/)) program for TC (Traffic Control) system with TCX attaching (fd-based tc BPF attach API). It requires at minimum Linux kernel v6.6 or more recent. Alternatively it can also use [XDP](https://github.com/xdp-project/xdp-tutorial) (eXpress Data Path) system but this will disable egress statistics since XDP works only in ingress path. XDP mode supports even older kernels, starting with Linux kernel v4.8.

Using TC or XDP will allow packet statistics gathering even under high traffic conditions, typically several million packets per second even on an average server.

At the end of the execution program will display per-IP and per-protocol (IPv4, IPv6, TCP, UDP, ICMPv4 and ICMPv6) statistics sorted by per-connection bps, packets and (source-IP:port, destination-IP:port) tuples.

Program consists of the [eBPF code in C](counter.c) and the pure-Go userland Golang program that parses and outputs final IP/port/protocol/bitrate statistics. Go part of the program uses [cillium/ebpf](https://github.com/cilium/ebpf) to load and run eBPF program.

![Demo](demo.gif)

## Requirements

Sniffing traffic and loading TC or XDP eBPF program typically requires root privileges or CAP_BPF [capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html):

```shell
$ setcap CAP_BPF=eip pktstat-bpf
```

Typically BPF JIT (Just in Time compiler) should be enabled for best performance:

```shell
echo 1 > /proc/sys/net/core/bpf_jit_enable
```

Additionally in case of XDP, not all NIC drivers support **Native XDP** (XDP program is loaded by NIC driver with XDP support as part of initial receive path and most common 10G drivers already support this) or even **Offloaded XDP** (XDP program loads directly on NIC with hardware XDP support and executes without using CPU), causing kernel to fallback on **Generic XDP** with reduced performance. Generic XDP does not require any special support from NIC drivers, but such XDP happens much later in the networking stack.

A list of XDP compatible drivers follows:

- [xdp-project XDP driver list](https://github.com/xdp-project/xdp-project/blob/master/areas/drivers/README.org)
- [IO Visor XDP driver list](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md#xdp)

## Usage

```shell
NAME
  pktstat-bpf

FLAGS
  -?, --help               display help
  -j, --json               if true, output in JSON format
  -x, --xdp                if true, use XDP instead of TC (this disables egress statistics)
      --version            display program version
  -i, --iface STRING       interface to read from (default: anpi5)
      --xdp_mode STRING    XDP attach mode (auto, generic, native or offload; native and offload require NIC driver support) (default: auto)
  -t, --timeout DURATION   timeout for packet capture (default: 1h0m0s)
```

It is possible to specify interface with `--iface`.

Timeout `--timeout` will stop execution after a specified time, but it is also possible to interrupt program with Ctrl C, SIGTERM or SIGINT.

With `--json` it is possible to get traffic statistics in JSON format.

With `--xdp` program will switch from TC eBPF mode to XDP eBPF mode, working in even more high-performance mode however this will disable all egress statistics. On program exit it is also possible to get an interface reset, so it is best to use this program inside of [screen](https://www.gnu.org/software/screen/) or [tmux](https://github.com/tmux/tmux).

Additionally it is possible to change XDP attach mode with `--xdp_mode` from `auto` (best-effort between native and generic) to `native` or `offload`, for NIC drivers that support XDP or even NICs that have hardware XDP support.
