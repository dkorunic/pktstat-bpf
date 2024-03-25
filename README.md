# pktstat-bpf

[![GitHub license](https://img.shields.io/github/license/dkorunic/pktstat-bpf)](https://github.com/dkorunic/pktstat-bpf/blob/master/LICENSE)
[![GitHub release](https://img.shields.io/github/release/dkorunic/pktstat-bpf)](https://github.com/dkorunic/pktstat-bpf/releases/latest)

![](gopher.png)

## About

pktstat-bpf is a work in progress simple replacement for ncurses-based [pktstat](https://github.com/dleonard0/pktstat), using tc eBPF ([extended Berkeley Packet Filter](https://prototype-kernel.readthedocs.io/en/latest/bpf/)) with TCX attaching. It requires a fairly recent Linux kernel to be able to work.

Using tc eBPF will allow packet statistics gathering even under high traffic conditions, typically several million packets per second even on an average server.

At the end of the execution program will display per-IP and per-protocol (IPv4, IPv6, TCP, UDP, ICMPv4 and ICMPv6) statistics sorted by per-connection bps, packets and (source-IP:port, destination-IP:port) tuples.

Program consists of the eBPF code in C and the pure-Go userland Golang program that parses and outputs final IP/port/protocol/bitrate statistics. Go part of the program uses [cillium/ebpf](https://github.com/cilium/ebpf) to load and run eBPF program.

![Demo](demo.gif)

## Requirements

Sniffing traffic and loading TC eBPF program typically requires root privileges or CAP_BPF [capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html):

```shell
$ setcap CAP_BPF=eip pktstat-bpf
```

## Usage

```shell
NAME
  pktstat-bpf

FLAGS
  -?, --help               display help
  -j, --json               if true, output in JSON format
      --version            display program version
  -i, --iface STRING       interface to read from (default: eth0)
  -t, --timeout DURATION   timeout for packet capture (default: 1h0m0s)
```

It is possible to specify interface with `--iface`.

Timeout `--timeout` will stop execution after a specified time, but it is also possible to interrupt program with Ctrl C, SIGTERM or SIGINT.

With `--json` it is possible to get traffic statistics in JSON format.
