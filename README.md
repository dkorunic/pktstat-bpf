# pktstat-bpf

[![GitHub license](https://img.shields.io/github/license/dkorunic/pktstat-bpf)](https://github.com/dkorunic/pktstat-bpf/blob/master/LICENSE)
[![GitHub release](https://img.shields.io/github/release/dkorunic/pktstat-bpf)](https://github.com/dkorunic/pktstat-bpf/releases/latest)

![](gopher.png)

## About

pktstat-bpf is a simple replacement for ncurses-based [pktstat](https://github.com/dleonard0/pktstat), using Linux eBPF ([extended Berkeley Packet Filter](https://prototype-kernel.readthedocs.io/en/latest/bpf/)) program, allowing packet statistics gathering even under **very high traffic volume** conditions, typically several million packets per second even on an average server. In this scenario (high volume, DoS attacks etc.) typically both regular PCAP or AF_PACKET solutions start being unreliable due to increasing packet loss.

By default it uses **TC** (Traffic Control) eBPF hooks with TCX attaching and that requires at minimum Linux kernel **v6.6** for both ingress and egress traffic statistics. Alternatively it can switch to [XDP](https://github.com/xdp-project/xdp-tutorial) (eXpress Data Path) hook but with a consequence of **losing egress statistics** since **XDP** works only in ingress path. XDP mode supports older kernels, starting with Linux kernel v4.8, but XDP program to network interface attaching call requires Linux kernel **v5.9**. As always, some distributions might have backported patches (notable example is Red Hat Enterprise Linux kernel) and XDP/TC eBPF program might work on older kernels too.

At the end of the execution program will display per-IP and per-protocol statistics sorted by per-connection bps, packets and (source-IP:port, destination-IP:port) tuples.

Program consists of the [eBPF code in C](counter.c) and the pure-Go userland Golang program that parses and outputs final IP/port/protocol/bitrate statistics. Go part of the program uses wonderful [cillium/ebpf](https://github.com/cilium/ebpf) library to load and run eBPF program, interfacing with eBPF map.

![Demo](demo.gif)

## Requirements

Loading eBPF program typically requires root privileges, but it is also possible to run rootless and set specific CAP_BPF and CAP_NET_ADMIN [capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html):

```shell
$ setcap CAP_BPF,CAP_NET_ADMIN=eip pktstat-bpf
```

Typically BPF JIT (Just in Time compiler) should be enabled for best performance:

```shell
echo 1 > /proc/sys/net/core/bpf_jit_enable
```

In case of XDP, not all NIC drivers support **Native XDP** (XDP program is loaded by NIC driver with XDP support as part of initial receive path and most common 10G drivers already support this) or even **Offloaded XDP** (XDP program loads directly on NIC with hardware XDP support and executes without using CPU), causing kernel to fallback on **Generic XDP** with reduced performance. Generic XDP does not require any special support from NIC drivers, but such XDP happens much later in the networking stack and in such case performance is more or less equivalent to TC hooks.

The following table maps features, requirements and expected performance for described modes:

| Capture type                                     | Ingress | Egress | Performance    | Kernel required | SmartNIC required |
| ------------------------------------------------ | ------- | ------ | -------------- | --------------- | ----------------- |
| [PCAP](https://github.com/dkorunic/pktstat)      | Yes     | Yes    | Low            | Any             | No                |
| [AF_PACKET](https://github.com/dkorunic/pktstat) | Yes     | Yes    | Medium         | Any             | No                |
| TC                                               | Yes     | Yes    | **High**       | v6.6            | No                |
| XDP Generic                                      | Yes     | **No** | **High**       | v5.9            | No                |
| XDP Native                                       | Yes     | **No** | **Very high**  | v5.9            | No                |
| XDP Offloaded                                    | Yes     | **No** | **Wire speed** | v5.9            | **Yes**           |

A list of XDP compatible drivers follows (and it is not necessarily up-to-date):

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
