// @license
// Copyright (C) 2024  Dinko Korunic
//
// SPDX-License-Identifier: MIT

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 tc ./bpf/tc.bpf.c -- -I./contrib/amd64
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target arm64 tc ./bpf/tc.bpf.c -- -I./contrib/arm64

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 xdp ./bpf/xdp.bpf.c -- -I./contrib/amd64
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target arm64 xdp ./bpf/xdp.bpf.c -- -I./contrib/arm64

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 kprobe ./bpf/kprobe.bpf.c -- -I./contrib/amd64
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target arm64 kprobe ./bpf/kprobe.bpf.c -- -I./contrib/arm64

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 cgroupSkb ./bpf/cgroup_skb.bpf.c -- -I./contrib/amd64
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target arm64 cgroupSkb ./bpf/cgroup_skb.bpf.c -- -I./contrib/arm64

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 cgroup ./bpf/cgroup.bpf.c -- -I./contrib/amd64
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target arm64 cgroup ./bpf/cgroup.bpf.c -- -I./contrib/arm64
