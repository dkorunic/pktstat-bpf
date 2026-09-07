// @license
// Copyright (C) 2024  Dinko Korunic
//
// SPDX-License-Identifier: MIT

package main

import (
	"net/netip"

	"github.com/cilium/ebpf"
)

type statEntry struct {
	SrcIP    netip.Addr `json:"srcIp"`
	DstIP    netip.Addr `json:"dstIp"`
	Proto    string     `json:"proto"`
	Comm     string     `json:"comm,omitempty"`
	CGroup   string     `json:"cgroup,omitempty"`
	AppProto string     `json:"appProto,omitempty"`
	Bytes    uint64     `json:"bytes"`
	Packets  uint64     `json:"packets"`
	Bitrate  float64    `json:"bitrate"`
	Pid      int32      `json:"pid,omitempty"`
	SrcPort  uint16     `json:"srcPort"`
	DstPort  uint16     `json:"dstPort"`
}

type kprobeHook struct {
	prog   *ebpf.Program
	kprobe string
}

// aggEntry is one aggregated row: either the grand total (Key == "") or one
// group under --aggregate-by.
//
// Flows counts the per-flow rows collapsed into this entry. It is a pointer
// because a totals-only run reads the BPF total_count counter without ever
// materialising per-flow rows, so the flow count is genuinely unknown there —
// and reporting 0 would be indistinguishable from "no traffic". Nil means
// unknown and is omitted from both output formats.
type aggEntry struct {
	Flows   *uint64 `json:"flows,omitempty"`
	Key     string  `json:"key,omitempty"`
	Bytes   uint64  `json:"bytes"`
	Packets uint64  `json:"packets"`
	Bitrate float64 `json:"bitrate"`
}
