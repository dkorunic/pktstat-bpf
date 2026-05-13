// @license
// Copyright (C) 2024  Dinko Korunic
//
// SPDX-License-Identifier: MIT

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

// Protocol name constants used by the per-protocol switch arms in outputPlain,
// MarshalJSON, and tui.go updateStatsTable. Match the values registered in
// helpers.go protoNames.
const (
	protoTCP    = "TCP"
	protoUDP    = "UDP"
	protoICMPv4 = "ICMPv4"
	protoICMPv6 = "IPv6-ICMP"
	protoESP    = "IPSEC-ESP"
	protoAH     = "IPSEC-AH"
	protoGRE    = "GRE"
	protoOSPF   = "OSPFIGP"
	protoARP    = "ARP"
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
func processMap(m *ebpf.Map, l7 *ebpf.Map, start time.Time, sortFunc func([]statEntry), buf []statEntry) ([]statEntry, error) {
	stats, err := listMap(m, l7, start, buf)
	sortFunc(stats)

	return stats, err
}

// sortDescBy sorts a slice of statEntry in descending order of the value
// returned by key. NaN keys would violate strict weak ordering — callers must
// guarantee non-NaN (true for Bitrate by construction, trivial for integers).
func sortDescBy[K cmp.Ordered](stats []statEntry, key func(statEntry) K) {
	slices.SortFunc(stats, func(a, b statEntry) int {
		ka, kb := key(a), key(b)
		if ka > kb {
			return -1
		}
		if ka < kb {
			return 1
		}

		return 0
	})
}

// bitrateSort sorts a slice of statEntry objects by Bitrate (descending).
// Bitrate is non-NaN by construction: bytes ≥ 0, dur ≥ 1e-9.
func bitrateSort(stats []statEntry) {
	sortDescBy(stats, func(e statEntry) float64 { return e.Bitrate })
}

// packetSort sorts a slice of statEntry objects by Packets (descending).
func packetSort(stats []statEntry) {
	sortDescBy(stats, func(e statEntry) uint64 { return e.Packets })
}

// bytesSort sorts a slice of statEntry objects by Bytes (descending).
func bytesSort(stats []statEntry) {
	sortDescBy(stats, func(e statEntry) uint64 { return e.Bytes })
}

// srcIPSort sorts a slice of statEntry objects by their SrcIP field in ascending order.
//
// Parameters:
//
//	stats []statEntry - the slice of statEntry objects to be sorted
func srcIPSort(stats []statEntry) {
	slices.SortFunc(stats, func(a, b statEntry) int {
		return a.SrcIP.Compare(b.SrcIP)
	})
}

// dstIPSort sorts a slice of statEntry objects by their DstIP field in ascending order.
//
// Parameters:
//
//	stats []statEntry - the slice of statEntry objects to be sorted
func dstIPSort(stats []statEntry) {
	slices.SortFunc(stats, func(a, b statEntry) int {
		return a.DstIP.Compare(b.DstIP)
	})
}

// appendHex16 appends n to buf as a 4-digit, zero-padded lowercase hex string.
// Replaces fmt.Sprintf("%04x", n) and the hand-rolled zero-pad loop in the
// hot rendering paths; allocation-free when callers reuse buf.
func appendHex16(buf []byte, n uint16) []byte {
	const hex = "0123456789abcdef"
	return append(buf,
		hex[(n>>12)&0xF],
		hex[(n>>8)&0xF],
		hex[(n>>4)&0xF],
		hex[n&0xF],
	)
}

// formatBitrate formats the bitrate value into a human-readable string.
//
// It takes a float64 parameter representing the bitrate and returns a string.
func formatBitrate(b float64) string {
	switch {
	case b < Kbps:
		return strconv.FormatFloat(b, 'f', 2, 64) + " bps"
	case b < Mbps:
		return strconv.FormatFloat(b/Kbps, 'f', 2, 64) + " Kbps"
	case b < Gbps:
		return strconv.FormatFloat(b/Mbps, 'f', 2, 64) + " Mbps"
	case b < Tbps:
		return strconv.FormatFloat(b/Gbps, 'f', 2, 64) + " Gbps"
	}

	return strconv.FormatFloat(b/Tbps, 'f', 2, 64) + " Tbps"
}

// outputPlain formats the provided statEntry slice into a plain text string.
// showProcessInfo controls whether the per-row pid/comm/cgroup suffix is
// emitted (true under --kprobes / --cgroup). Caller knows the mode; passing
// it in keeps outputPlain decoupled from the global flag pointers and makes
// the function trivially testable without a flag-init shim.
func outputPlain(m []statEntry, showProcessInfo bool) string {
	var sb strings.Builder

	perEntry := 128
	if showProcessInfo {
		perEntry = 256
	}

	sb.Grow(len(m) * perEntry)

	// Reused via AppendTo / AppendUint to avoid per-row string allocs.
	var addrBuf []byte

	for _, v := range m {
		sb.WriteString("bitrate: ")
		sb.WriteString(formatBitrate(v.Bitrate))
		sb.WriteString(", packets: ")
		sb.WriteString(strconv.FormatUint(v.Packets, 10))
		sb.WriteString(", bytes: ")
		sb.WriteString(strconv.FormatUint(v.Bytes, 10))
		sb.WriteString(", proto: ")
		sb.WriteString(v.Proto)

		if v.AppProto != "" {
			sb.WriteString(", l7: ")
			sb.WriteString(v.AppProto)
		}

		switch v.Proto {
		case protoICMPv4, protoICMPv6:
			sb.WriteString(", src: ")
			addrBuf = v.SrcIP.AppendTo(addrBuf[:0])
			sb.Write(addrBuf)
			sb.WriteString(", dst: ")
			addrBuf = v.DstIP.AppendTo(addrBuf[:0])
			sb.Write(addrBuf)
			sb.WriteString(", type: ")
			sb.WriteString(strconv.FormatUint(uint64(v.SrcPort), 10))
			sb.WriteString(", code: ")
			sb.WriteString(strconv.FormatUint(uint64(v.DstPort), 10))
		case protoESP, protoAH:
			spi := uint32(v.SrcPort)<<16 | uint32(v.DstPort)
			sb.WriteString(", src: ")
			addrBuf = v.SrcIP.AppendTo(addrBuf[:0])
			sb.Write(addrBuf)
			sb.WriteString(", dst: ")
			addrBuf = v.DstIP.AppendTo(addrBuf[:0])
			sb.Write(addrBuf)
			sb.WriteString(", spi: 0x")
			sb.WriteString(strconv.FormatUint(uint64(spi), 16))
		case protoGRE:
			sb.WriteString(", src: ")
			addrBuf = v.SrcIP.AppendTo(addrBuf[:0])
			sb.Write(addrBuf)
			sb.WriteString(", dst: ")
			addrBuf = v.DstIP.AppendTo(addrBuf[:0])
			sb.Write(addrBuf)
			sb.WriteString(", inner: ")
			sb.WriteString(greInnerName(v.SrcPort))
			sb.WriteString(", flags: 0x")
			addrBuf = appendHex16(addrBuf[:0], v.DstPort)
			sb.Write(addrBuf)
		case protoOSPF:
			sb.WriteString(", src: ")
			addrBuf = v.SrcIP.AppendTo(addrBuf[:0])
			sb.Write(addrBuf)
			sb.WriteString(", dst: ")
			addrBuf = v.DstIP.AppendTo(addrBuf[:0])
			sb.Write(addrBuf)
			sb.WriteString(", type: ")
			sb.WriteString(ospfTypeName(v.SrcPort))
			sb.WriteString(", v")
			sb.WriteString(strconv.FormatUint(uint64(v.DstPort), 10))
		case protoARP:
			sb.WriteString(", src: ")
			addrBuf = v.SrcIP.AppendTo(addrBuf[:0])
			sb.Write(addrBuf)
			sb.WriteString(", dst: ")
			addrBuf = v.DstIP.AppendTo(addrBuf[:0])
			sb.Write(addrBuf)
			sb.WriteString(", op: ")
			sb.WriteString(arpOpName(v.SrcPort))
		default:
			sb.WriteString(", src: ")
			addrBuf = v.SrcIP.AppendTo(addrBuf[:0])
			addrBuf = append(addrBuf, ':')
			addrBuf = strconv.AppendUint(addrBuf, uint64(v.SrcPort), 10)
			sb.Write(addrBuf)
			sb.WriteString(", dst: ")
			addrBuf = v.DstIP.AppendTo(addrBuf[:0])
			addrBuf = append(addrBuf, ':')
			addrBuf = strconv.AppendUint(addrBuf, uint64(v.DstPort), 10)
			sb.Write(addrBuf)
		}

		if showProcessInfo {
			if v.Pid > 0 {
				sb.WriteString(", pid: ")
				sb.WriteString(strconv.FormatInt(int64(v.Pid), 10))
			}

			if v.Comm != "" {
				sb.WriteString(", comm: ")
				sb.WriteString(v.Comm)
			}

			if v.CGroup != "" {
				sb.WriteString(", cgroup: ")
				sb.WriteString(v.CGroup)
			}
		}

		sb.WriteByte('\n')
	}

	return sb.String()
}

// outputJSON encodes m as a JSON array to os.Stdout. The encoder is built
// per call so that we resolve os.Stdout at call time (a package-level encoder
// would freeze the original fd at init, which would silently mis-write if
// anything ever swaps os.Stdout); the allocation is negligible because
// outputJSON is invoked once per CLI run.
func outputJSON(m []statEntry) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)

	if err := enc.Encode(m); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error encoding JSON output: %v\n", err)
	}
}

// MarshalJSON augments the default struct-tag encoding with protocol-aware
// fields for the protocols where src_port/dst_port carry packed metadata
// (ESP/AH SPI, ARP opcode, OSPF type/version, GRE inner protocol/flags).
//
// Existing fields (srcPort, dstPort, proto, srcIp, dstIp, etc.) are always
// emitted, so consumers that ignore the new fields keep their current shape.
func (e *statEntry) MarshalJSON() ([]byte, error) {
	type alias statEntry

	type extended struct {
		*alias

		SPI      *uint32 `json:"spi,omitempty"`
		GREFlags *uint16 `json:"greFlags,omitempty"`
		ARPOp    string  `json:"arpOp,omitempty"`
		OSPFType string  `json:"ospfType,omitempty"`
		GREInner string  `json:"greInner,omitempty"`
		OSPFVer  uint8   `json:"ospfVersion,omitempty"`
	}

	ext := extended{alias: (*alias)(e)}

	switch e.Proto {
	case protoESP, protoAH:
		spi := uint32(e.SrcPort)<<16 | uint32(e.DstPort) //nolint:mnd
		ext.SPI = &spi
	case protoARP:
		ext.ARPOp = arpOpName(e.SrcPort)
	case protoOSPF:
		ext.OSPFType = ospfTypeName(e.SrcPort)
		ext.OSPFVer = uint8(e.DstPort) //nolint:gosec // OSPF version is 2 or 3
	case protoGRE:
		ext.GREInner = greInnerName(e.SrcPort)
		flags := e.DstPort
		ext.GREFlags = &flags
	}

	return json.Marshal(&ext)
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
	// Reinterpret []int8 → []byte without alloc; same layout.
	b := unsafe.Slice((*byte)(unsafe.Pointer(unsafe.SliceData(bs))), len(bs))

	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}

	return string(b)
}
