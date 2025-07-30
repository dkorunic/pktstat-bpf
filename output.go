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
	"bytes"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/goccy/go-json"
)

const (
	Bps  float64 = 1.0
	Kbps         = 1000 * Bps
	Mbps         = 1000 * Kbps
	Gbps         = 1000 * Mbps
	Tbps         = 1000 * Gbps
)

// processMap generates statEntry objects from an ebpf.Map using the provided start time.
//
// Parameters:
//
//	m *ebpf.Map - the eb
func processMap(m *ebpf.Map, start time.Time, sortFunc func([]statEntry)) ([]statEntry, error) {
	var (
		key counterStatkey
		val counterStatvalue
	)

	dur := time.Since(start).Seconds()
	stats := make([]statEntry, 0, m.MaxEntries())
	iter := m.Iterate()

	// build statEntry slice converting data where needed
	for iter.Next(&key, &val) {
		stats = append(stats, statEntry{
			SrcIP:   bytesToAddr(key.Srcip.In6U.U6Addr8),
			DstIP:   bytesToAddr(key.Dstip.In6U.U6Addr8),
			Proto:   protoToString(key.Proto),
			SrcPort: key.SrcPort,
			DstPort: key.DstPort,
			Bytes:   val.Bytes,
			Packets: val.Packets,
			Bitrate: 8 * float64(val.Bytes) / dur,
			Pid:     key.Pid,
			Comm:    commToString(key.Comm[:]),
			Cgroup:  cgroupToPath(key.Cgroupid),
		})
	}

	sortFunc(stats)

	return stats, iter.Err()
}

// bitrateSort sorts a slice of statEntry objects by their Bitrate field in descending order.
//
// Parameters:
//
//	stats []statEntry - the slice of statEntry objects to be sorted
func bitrateSort(stats []statEntry) {
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].Bitrate > stats[j].Bitrate
	})
}

// packetSort sorts a slice of statEntry objects by their Packets field in descending order.
//
// Parameters:
//
//	stats []statEntry - the slice of statEntry objects to be sorted
func packetSort(stats []statEntry) {
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].Packets > stats[j].Packets
	})
}

// bytesSort sorts a slice of statEntry objects by their Bytes field in descending order.
//
// Parameters:
//
//	stats []statEntry - the slice of statEntry objects to be sorted
func bytesSort(stats []statEntry) {
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].Bytes > stats[j].Bytes
	})
}

// srcIPSort sorts a slice of statEntry objects by their SrcIP field in descending order.
//
// Parameters:
//
//	stats []statEntry - the slice of statEntry objects to be sorted
func srcIPSort(stats []statEntry) {
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].SrcIP.Compare(stats[j].SrcIP) < 0
	})
}

// dstIPSort sorts a slice of statEntry objects by their DstIP field in descending order.
//
// Parameters:
//
//	stats []statEntry - the slice of statEntry objects to be sorted
func dstIPSort(stats []statEntry) {
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].DstIP.Compare(stats[j].DstIP) < 0
	})
}

// formatBitrate formats the bitrate value into a human-readable string.
//
// It takes a float64 parameter representing the bitrate and returns a string.
func formatBitrate(b float64) string {
	switch {
	case b < Kbps:
		return fmt.Sprintf("%.2f bps", b)
	case b < 10*Kbps:
		return fmt.Sprintf("%.2f Kbps", b/Kbps)
	case b < 10*Mbps:
		return fmt.Sprintf("%.2f Mbps", b/Mbps)
	case b < 10*Gbps:
		return fmt.Sprintf("%.2f Gbps", b/Gbps)
	case b < 10*Tbps:
		return fmt.Sprintf("%.2f Tbps", b/Tbps)
	}

	return fmt.Sprintf("%.2fTbps", b/Tbps)
}

// outputPlain formats the provided statEntry slice into a plain text string.
//
// Each line contains information about a single protocol flow, including bitrate,
// packets, bytes, protocol, source IP:port, destination IP:port, and ICMP type and
// code if applicable. If kprobes are being used, the PID and comm fields are also
// included. The output is sorted by bitrate in descending order.
//
// Parameters:
//
//	m []statEntry - the statEntry slice to be formatted
//
// Returns:
//
//	string - the formatted string
func outputPlain(m []statEntry) string {
	var sb strings.Builder

	for _, v := range m {
		switch v.Proto {
		case "ICMPv4", "IPv6-ICMP":
			sb.WriteString(fmt.Sprintf("bitrate: %v, packets: %d, bytes: %d, proto: %v, src: %v, dst: %v, type: %d, code: %d",
				formatBitrate(v.Bitrate), v.Packets, v.Bytes, v.Proto, v.SrcIP, v.DstIP, v.SrcPort, v.DstPort))
		default:
			sb.WriteString(fmt.Sprintf("bitrate: %v, packets: %d, bytes: %d, proto: %v, src: %v:%d, dst: %v:%d",
				formatBitrate(v.Bitrate), v.Packets, v.Bytes, v.Proto, v.SrcIP, v.SrcPort, v.DstIP, v.DstPort))
		}

		if *useKProbes || *useCGroup != "" {
			if v.Pid > 0 {
				sb.WriteString(fmt.Sprintf(", pid: %d", v.Pid))
			}

			if v.Comm != "" {
				sb.WriteString(fmt.Sprintf(", comm: %v", v.Comm))
			}

			if v.Cgroup != "" {
				sb.WriteString(fmt.Sprintf(", cgroup: %v", v.Cgroup))
			}
		}

		sb.WriteString("\n")
	}

	return sb.String()
}

// outputJSON formats the provided statEntry slice into a JSON string.
//
// The JSON is created using the encoding/json package, marshaling the statEntry
// slice into a JSON array. The output is a string.
//
// Parameters:
//
//	m []statEntry - the statEntry slice to be formatted
//
// Returns:
//
//	string - the JSON string representation of m
func outputJSON(m []statEntry) string {
	out, _ := json.Marshal(m)

	return string(out)
}

// commToString converts a byte slice to a string, trimming any null bytes.
//
// It takes a byte slice as its parameter and returns a string.
// If the byte slice is empty, the function returns the string "kernel".
// Otherwise, it creates a new byte slice, copies the input byte slice into it,
// trims any null bytes from the end of the slice, and returns the result as a string.
func commToString(bs []int8) string {
	b := make([]byte, len(bs))
	for i, v := range bs {
		b[i] = byte(v)
	}

	// trim excess NULLs
	b = bytes.Trim(b, "\x00")

	return string(b)
}
