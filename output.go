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
	"cmp"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
)

const (
	Bps  float64 = 1.0
	Kbps         = 1000 * Bps
	Mbps         = 1000 * Kbps
	Gbps         = 1000 * Mbps
	Tbps         = 1000 * Gbps
)

// processMap processes a given ebpf.Map object by iterating over all its entries,
// converting the counter values into a statEntry slice, and sorting the slice
// using the given sortFunc.
//
// Parameters:
//   - m *ebpf.Map: the eBPF map to process
//   - start time.Time: the start time for calculating entry duration
//   - sortFunc func([]statEntry): a function to sort the statEntry slice
//
// Returns:
//   - []statEntry: the sorted statEntry slice
//   - error: an error if any occurred during map iteration, otherwise nil
func processMap(m *ebpf.Map, start time.Time, sortFunc func([]statEntry)) ([]statEntry, error) {
	stats, err := listMap(m, start)
	sortFunc(stats)

	return stats, err
}

// bitrateSort sorts a slice of statEntry objects by their Bitrate field in descending order.
//
// Parameters:
//
//	stats []statEntry - the slice of statEntry objects to be sorted
func bitrateSort(stats []statEntry) {
	slices.SortFunc(stats, func(a, b statEntry) int {
		return cmp.Compare(b.Bitrate, a.Bitrate)
	})
}

// packetSort sorts a slice of statEntry objects by their Packets field in descending order.
//
// Parameters:
//
//	stats []statEntry - the slice of statEntry objects to be sorted
func packetSort(stats []statEntry) {
	slices.SortFunc(stats, func(a, b statEntry) int {
		return cmp.Compare(b.Packets, a.Packets)
	})
}

// bytesSort sorts a slice of statEntry objects by their Bytes field in descending order.
//
// Parameters:
//
//	stats []statEntry - the slice of statEntry objects to be sorted
func bytesSort(stats []statEntry) {
	slices.SortFunc(stats, func(a, b statEntry) int {
		return cmp.Compare(b.Bytes, a.Bytes)
	})
}

// srcIPSort sorts a slice of statEntry objects by their SrcIP field in descending order.
//
// Parameters:
//
//	stats []statEntry - the slice of statEntry objects to be sorted
func srcIPSort(stats []statEntry) {
	slices.SortFunc(stats, func(a, b statEntry) int {
		return a.SrcIP.Compare(b.SrcIP)
	})
}

// dstIPSort sorts a slice of statEntry objects by their DstIP field in descending order.
//
// Parameters:
//
//	stats []statEntry - the slice of statEntry objects to be sorted
func dstIPSort(stats []statEntry) {
	slices.SortFunc(stats, func(a, b statEntry) int {
		return a.DstIP.Compare(b.DstIP)
	})
}

// formatBitrate formats the bitrate value into a human-readable string.
//
// It takes a float64 parameter representing the bitrate and returns a string.
func formatBitrate(b float64) string {
	switch {
	case b < Kbps:
		return strconv.FormatFloat(b, 'f', 2, 64) + " bps"
	case b < 10*Kbps:
		return strconv.FormatFloat(b/Kbps, 'f', 2, 64) + " Kbps"
	case b < 10*Mbps:
		return strconv.FormatFloat(b/Mbps, 'f', 2, 64) + " Mbps"
	case b < 10*Gbps:
		return strconv.FormatFloat(b/Gbps, 'f', 2, 64) + " Gbps"
	case b < 10*Tbps:
		return strconv.FormatFloat(b/Tbps, 'f', 2, 64) + " Tbps"
	}

	return strconv.FormatFloat(b/Tbps, 'f', 2, 64) + " Tbps"
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

	sb.Grow(len(m) * 128)

	for _, v := range m {
		switch v.Proto {
		case "ICMPv4", "IPv6-ICMP":
			fmt.Fprintf(&sb, "bitrate: %v, packets: %d, bytes: %d, proto: %v, src: %v, dst: %v, type: %d, code: %d",
				formatBitrate(v.Bitrate), v.Packets, v.Bytes, v.Proto, v.SrcIP, v.DstIP, v.SrcPort, v.DstPort)
		default:
			fmt.Fprintf(&sb, "bitrate: %v, packets: %d, bytes: %d, proto: %v, src: %v:%d, dst: %v:%d",
				formatBitrate(v.Bitrate), v.Packets, v.Bytes, v.Proto, v.SrcIP, v.SrcPort, v.DstIP, v.DstPort)
		}

		if *useKProbes || *useCGroup != "" {
			if v.Pid > 0 {
				fmt.Fprintf(&sb, ", pid: %d", v.Pid)
			}

			if v.Comm != "" {
				fmt.Fprintf(&sb, ", comm: %v", v.Comm)
			}

			if v.CGroup != "" {
				fmt.Fprintf(&sb, ", cgroup: %v", v.CGroup)
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
func outputJSON(m []statEntry) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(m)
}

// bsliceToString converts a slice of int8 values to a string by first
// transforming each int8 element to a byte. It then trims any NULL
// characters from the resulting byte slice before converting it to
// a string.
//
// Parameters:
//   - bs []int8: The slice of int8 values to be converted.
//
// Returns:
//   - string: The resulting string after conversion and trimming.
func bsliceToString(bs []int8) string {
	// reinterpret []int8 as []byte without allocation (identical memory layout)
	b := unsafe.Slice((*byte)(unsafe.Pointer(unsafe.SliceData(bs))), len(bs))

	// find null terminator of C string and slice to it
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}

	return string(b)
}
