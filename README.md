# pktstat-bpf

[![GitHub license](https://img.shields.io/github/license/dkorunic/pktstat-bpf)](https://github.com/dkorunic/pktstat-bpf/blob/master/LICENSE)
[![GitHub release](https://img.shields.io/github/release/dkorunic/pktstat-bpf)](https://github.com/dkorunic/pktstat-bpf/releases/latest)

![](gopher.jpg)

(Go language Gopher flying on a eBPF bee and carrying a switch, created by Microsoft Designer DALL-E 3)

## About

pktstat-bpf is a simple replacement for ncurses/libpcap-based [pktstat](https://github.com/dleonard0/pktstat), using Linux eBPF ([extended Berkeley Packet Filter](https://prototype-kernel.readthedocs.io/en/latest/bpf/)) program, allowing packet statistics gathering even under **very high traffic volume** conditions, typically several million packets per second even on an average server. In this scenario (high volume, DoS attacks etc.) typically regular packet capture solutions start being unreliable due to increasing packet loss.

By default it uses **TC** (Traffic Control) eBPF hooks with TCX attaching requiring at minimum Linux kernel **v6.6** for both ingress and egress traffic statistics for TCP, UDP, ICMPv4 and ICMPv6. It can also switch to even faster [XDP](https://github.com/xdp-project/xdp-tutorial) (eXpress Data Path) hook but with a consequence of **losing egress statistics** since **XDP** works only in ingress path. XDP mode due to XDP program to network interface attaching calls requires at minimum Linux kernel **v5.9**. Some distributions might have backported XDP/TC patches (notable example is Red Hat Enterprise Linux kernel) and eBPF program might work on older kernels too.

Alternatively it can use **KProbes** to monitor TCP, UDP, ICMPv4 and ICMPv6 communication throughout all containers, K8s pods, translations and forwards and display process ID as well as process name, if the traffic was being sent or delivered to userspace application. KProbes traditionally work the slowest, being closest to the userspace -- but they bring sometimes useful process information.

At the end of the execution program will display per-IP and per-protocol statistics sorted by per-connection bps, packets and (source-IP:port, destination-IP:port) tuples.

Program consists of the [eBPF code in C](counter.c) and the pure-Go userland Golang program that parses and outputs final IP/port/protocol/bitrate statistics. Go part of the program uses wonderful [cillium/ebpf](https://github.com/cilium/ebpf) library to load and run eBPF program, interfacing with eBPF map.

![Demo](demo.gif)

## Requirements

Loading eBPF program typically requires root privileges and in our specific case pointer arithmetics in eBPF code causes [eBPF verifier](https://docs.kernel.org/bpf/verifier.html) to explicitly deny non-root use.

Typically BPF JIT (Just in Time compiler) should be enabled for best performance:

```shell
echo 1 > /proc/sys/net/core/bpf_jit_enable
```

In case of XDP, not all NIC drivers support **Native XDP** (XDP program is loaded by NIC driver with XDP support as part of initial receive path and most common 10G drivers already support this) or even **Offloaded XDP** (XDP program loads directly on NIC with hardware XDP support and executes without using CPU), causing kernel to fallback on **Generic XDP** with reduced performance. Generic XDP does not require any special support from NIC drivers, but such XDP happens much later in the networking stack and in such case performance is more or less equivalent to TC hooks.

The following table maps features, requirements and expected performance for described modes:

| Capture type                                        | Ingress | Egress | Performance    | Process tracking | Kernel required | SmartNIC required |
| --------------------------------------------------- | ------- | ------ | -------------- | ---------------- | --------------- | ----------------- |
| Generic [PCAP](https://github.com/dkorunic/pktstat) | Yes     | Yes    | Low            | No               | Any             | No                |
| [AF_PACKET](https://github.com/dkorunic/pktstat)    | Yes     | Yes    | Medium         | No               | v2.2            | No                |
| KProbes                                             | Yes     | Yes    | Medium+        | **Yes**          | v2.6            | No                |
| TC                                                  | Yes     | Yes    | **High**       | No               | v6.6            | No                |
| XDP Generic                                         | Yes     | **No** | **High**       | No               | v5.9            | No                |
| XDP Native                                          | Yes     | **No** | **Very high**  | No               | v5.9            | No                |
| XDP Offloaded                                       | Yes     | **No** | **Wire speed** | No               | v5.9            | **Yes**           |

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
  -k, --kprobes            if true, use KProbes for per-proces TCP/UDP statistics
  -g, --tui                if true, enable TUI
      --version            display program version
  -i, --iface STRING       interface to read from (default: eth0)
      --xdp_mode STRING    XDP attach mode (auto, generic, native or offload; native and offload require NIC driver support) (default: auto)
  -r, --refresh DURATION   refresh interval in TUI (default: 1s)
  -t, --timeout DURATION   timeout for packet capture in CLI (default: 10m0s)
```

It is possible to specify interface with `--iface`.

Timeout `--timeout` will stop execution after a specified time, but it is also possible to interrupt program with Ctrl C, SIGTERM or SIGINT.

With `--tui` program will switch to a very simple TUI primarily for continous monitoring purpose. Use arrow keys to browse statistics table and keys 'q' or 'x' to exit.

With `--json` it is possible to get traffic statistics in JSON format.

With `--xdp` program will switch from TC eBPF mode to XDP eBPF mode, working in even more high-performance mode however this will disable all egress statistics. On program exit it is also possible to get an interface reset, so it is best to use this program inside of [screen](https://www.gnu.org/software/screen/) or [tmux](https://github.com/tmux/tmux).

Additionally it is possible to change XDP attach mode with `--xdp_mode` from `auto` (best-effort between native and generic) to `native` or `offload`, for NIC drivers that support XDP or even NICs that have hardware XDP support.

With `--kprobes` program will switch to Kprobe mode and track TCP and UDP traffic per process. Performance will be even more degraded compared to TC and XDP mode, but all per-PID traffic will be visible, inside of all Cgroups, containers, K8s pods etc.

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=dkorunic/pktstat,dkorunic/pktstat-bpf&type=Date)](https://star-history.com/#dkorunic/pktstat&dkorunic/pktstat-bpf&Date)
