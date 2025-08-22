# pktstat-kube

[![GitHub license](https://img.shields.io/github/license/dkorunic/pktstat-bpf)](https://github.com/dkorunic/pktstat-bpf/blob/master/LICENSE)
[![GitHub release](https://img.shields.io/github/release/dkorunic/pktstat-bpf)](https://github.com/dkorunic/pktstat-bpf/releases/latest)

> **Note:** This project is a fork of [dkorunic/pktstat-bpf](https://github.com/dkorunic/pktstat-bpf) with significant modifications. It has been refocused to function as a lightweight packet logger using kprobes rather than maintaining the full feature set of the original tool.

## About

This fork of pktstat-bpf is a simplified packet logging tool built using Linux eBPF and kprobes. While the original pktstat-bpf offers multiple capture methods (TC, XDP, CGroups), this version focuses exclusively on kprobe-based packet capturing.

Key differences from the original project:
- Uses only kprobes for packet capture
- Simplified output formats (JSON by default, optional plain text)
- No TUI interface - designed for logging to files or processing by other tools
- Added packet source identification based on the capturing kprobe
- Runs indefinitely until stopped, making it suitable for continuous monitoring
- Added support for kubernetes pod lookups
- Added support for filtering external traffic only
- Added chronological sorting of packet entries

The tool collects connection information including source/destination IPs and ports, protocol, process ID, timestamp, and command name, making it useful for network connection auditing, troubleshooting, and security monitoring.

At the end of execution, the program will output the collected packet data in either JSON format (default) or plain text format.

## Requirements

The main requirement for this tool is a Linux kernel with **BTF support** (typically kernel 4.10 or newer). Since this fork uses only kprobes, it works on older kernels than those required for TC or XDP modes in the original project.

Loading the eBPF program typically requires root privileges as the eBPF code's pointer arithmetic causes the [eBPF verifier](https://docs.kernel.org/bpf/verifier.html) to explicitly deny non-root use.

Typically BPF JIT (Just in Time compiler) should be enabled for best performance (most Linux distributions have this enabled by default):

```shell
sysctl -w net.core.bpf_jit_enable=1
```

## Usage

```shell
NAME
  pktstat-bpf

FLAGS
  -?, --help                    display help
  -p, --plain                   if true, output in plain text format (default: JSON format)
  -u, --unique                  if true, only show the first instance of each connection
  --kubeconfig STRING           path to kubeconfig file (Kubernetes lookups enabled if provided)
  --external                    if true, only show traffic to external destinations
  --internal-networks STRING    comma-separated list of internal network CIDRs to filter out when using --external
                                (default: 127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16)
  --version                     display program version
```

The program will run indefinitely until interrupted with Ctrl+C, SIGTERM or SIGINT.

By default, output is in JSON format. With `--plain` the program will output in human-readable plain text format.

With `--kubeconfig` the program will perform Kubernetes pod name lookups for IPs detected in the capture.

With `--external` the program will only show traffic to external destinations (non-internal networks). The list of internal networks can be customized using the `--internal-networks` flag.

With `--unique` the program will only show the first occurrence of each unique connection, ignoring timestamp differences. This is useful to filter out repetitive traffic and focus on the connection patterns.

You can redirect the output to a file using standard shell redirection (e.g., `./pktstat-kube > output.json`).

## Development
### Dependencies
If you're developing this against an Ubuntu system, you can install the
needed packages to run `make generate` with:

```shell
sudo apt install linux-headers-$(uname -r) \
                 libbpfcc-dev \
                 libbpf-dev \
                 llvm \
                 clang \
                 gcc-multilib \
                 build-essential \
                 linux-tools-$(uname -r) \
                 linux-tools-common \
                 linux-tools-generic
```

### Testing a Release with Cluster Provisioner
Build the test release of `pktstat-bpf`:

```shell
make generate build
```

Move the release into the `network-report-collector-path` set in
`/etc/cluster-provisioner/cluster-provisioner.yaml` (default: `/opt/cluster-provisioner/bin/pktstat-bpf`) and spin up a cluster
or VM.  Cluster Provisioner will use the binary at that path to collect
network reports.
