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
