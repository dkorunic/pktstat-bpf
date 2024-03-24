package main

import "net/netip"

type statEntry struct {
	SrcIP   netip.Addr `json:"srcIp"`
	DstIP   netip.Addr `json:"dstIp"`
	Proto   string     `json:"proto"`
	SrcPort uint16     `json:"srcPort"`
	DstPort uint16     `json:"dstPort"`
	Bytes   uint64     `json:"bytes"`
	Packets uint64     `json:"packets"`
	Bitrate float64    `json:"bitrate"`
}
