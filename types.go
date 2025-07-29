// @license
// Copyright (C) 2024  Dinko Korunic
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package main

import (
	"net/netip"

	"github.com/cilium/ebpf"
)

type statEntry struct {
	SrcIP   netip.Addr `json:"srcIp"`
	DstIP   netip.Addr `json:"dstIp"`
	Proto   string     `json:"proto"`
	Comm    string     `json:"comm,omitempty"`
	Cgroup  string     `json:"cgroup,omitempty"`
	Bytes   uint64     `json:"bytes"`
	Packets uint64     `json:"packets"`
	Bitrate float64    `json:"bitrate"`
	Pid     int32      `json:"pid,omitempty"`
	SrcPort uint16     `json:"srcPort"`
	DstPort uint16     `json:"dstPort"`
}

type kprobeHook struct {
	prog   *ebpf.Program
	kprobe string
}
