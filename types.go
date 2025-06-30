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
	"time"

	"github.com/cilium/ebpf"
)

type kprobeHook struct {
	prog   *ebpf.Program
	kprobe string
}

type uprobeHook struct {
	prog   *ebpf.Program
	symbol string // Name of the function to attach to
}

type statEntry struct {
	Timestamp time.Time `json:"timestamp"`

	SrcIP     netip.Addr `json:"srcIp"`
	DstIP     netip.Addr `json:"dstIp"`
	SrcPort   uint16     `json:"srcPort"`
	DstPort   uint16     `json:"dstPort"`
	Proto     string     `json:"proto"`
	Comm      string     `json:"comm,omitempty"`
	Pid       int32      `json:"pid,omitempty"`
	SourcePod string     `json:"sourcePod,omitempty"`
	DstPod    string     `json:"dstPod,omitempty"`

	DNSQueryName  string `json:"dnsQueryName,omitempty"`
	LikelyService string `json:"likelyService,omitempty"`
}

// dnsOriginMapping stores a mapping between a hostname and IP with a timestamp
type dnsOriginMapping struct {
	Hostname  string
	IP        string
	Timestamp time.Time
}

// dnsOrigin stores information about the original process that initiated a DNS request
type dnsOrigin struct {
	SrcIP     string
	SrcPort   uint16
	Pid       uint32
	Comm      string
	Timestamp time.Time
	PodName   string
}

// dnsLookupEvent represents a DNS lookup event
type dnsLookupEvent struct {
	AddrType uint32
	IP       [16]uint8
	Host     [252]byte
	Pid      uint32
	Comm     [16]byte
}

// dnsCorrelatedEvent represents a complete DNS flow from client to external DNS
type dnsCorrelatedEvent struct {
	// Original client information
	OriginalSrcIP   string `json:"originalSrcIp"`
	OriginalSrcPort uint16 `json:"originalSrcPort"`
	OriginalPod     string `json:"originalPod"`
	OriginalComm    string `json:"originalComm"`
	OriginalPid     int32  `json:"originalPid"`

	// Timestamp of the correlation
	Timestamp time.Time `json:"timestamp"`

	// DNS server information (e.g., CoreDNS)
	DNSServerIP   string `json:"dnsServerIp"`
	DNSServerComm string `json:"dnsServerComm"`
	DNSServerPid  int32  `json:"dnsServerPid"`

	// External destination information
	ExternalDstIP   string `json:"externalDstIp"`
	ExternalDstPort uint16 `json:"externalDstPort"`

	// Protocol and service info
	Proto         string `json:"proto"`
	LikelyService string `json:"likelyService"`

	// DNS query name if available
	DNSQueryName string `json:"dnsQueryName,omitempty"`
}
