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
func processMap(m *ebpf.Map, start time.Time) ([]statEntry, error) {
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
			Comm:    byte2String(key.Comm[:]),
		})
	}

	sort.Slice(stats, func(i, j int) bool {
		return stats[i].Bitrate > stats[j].Bitrate
	})

	return stats, iter.Err()
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

// outputPlain generates a plain text representation of the given statEntry slice.
//
// It takes a slice of statEntry structs as its parameter and formats them into a string
// containing information about each entry's bitrate, packets, bytes, protocol, source IP,
// source port, and destination IP and port. The resulting string is then printed to the
// console.
//
// The function does not return anything.
func outputPlain(m []statEntry) {
	var sb strings.Builder

	for _, v := range m {
		sb.WriteString(fmt.Sprintf("bitrate: %v, packets: %d, bytes: %d, proto: %v, src: %v:%v, dst: %v:%v",
			formatBitrate(v.Bitrate), v.Packets, v.Bytes, v.Proto, v.SrcIP, v.SrcPort, v.DstIP, v.DstPort))
		if *useKprobes {
			sb.WriteString(fmt.Sprintf(", pid: %d, comm: %v", v.Pid, v.Comm))
		}
		sb.WriteString("\n")
	}

	fmt.Printf("%v", sb.String())
}

// outputJSON marshals the given slice of statEntry structs into a JSON string and prints it.
//
// The function takes a slice of statEntry structs as a parameter.
// The slice is marshaled into a JSON string using the Marshal function of the goccy/go-json package.
// The resulting JSON string is printed using the Printf function from the fmt package.
// The function does not return any value.
func outputJSON(m []statEntry) {
	out, _ := json.Marshal(m)

	fmt.Printf("%v\n", string(out))
}

// byte2String converts a slice of int8 to a string.
//
// It takes a slice of int8 as a parameter, creates a new slice of byte of the same length,
// copies the values of the int8 slice to the byte slice, and converts the byte slice to a string.
// The resulting string is then returned.
func byte2String(bs []int8) string {
	b := make([]byte, len(bs))
	for i, v := range bs {
		b[i] = byte(v)
	}

	return string(b)
}
