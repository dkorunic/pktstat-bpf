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
	"sort"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	json "github.com/goccy/go-json"
	"github.com/hashicorp/go-multierror"
)

// processMap generates statEntry objects from an ebpf.Map.
//
// Parameters:
//
//	m *ebpf.Map - the ebpf map to process
func processMap(m *ebpf.Map, sortFunc func([]statEntry)) ([]statEntry, error) {
	var (
		key counterStatkey
		val counterStatvalue
	)

	stats := make([]statEntry, 0, m.MaxEntries())
	observedKeys := make([]counterStatkey, 0, m.MaxEntries())
	iter := m.Iterate()

	// build statEntry slice converting data where needed
	for iter.Next(&key, &val) {
		observedKeys = append(observedKeys, key)
		srcIP := bytesToAddr(key.Srcip.In6U.U6Addr8)
		dstIP := bytesToAddr(key.Dstip.In6U.U6Addr8)

		// Filter out traffic with unspecified addresses, this is to
		// prevent users from seeing traffic to/from a cluster-provisioner
		// host or invalid/unconnected socket states.
		srcIPStr := srcIP.String()
		dstIPStr := dstIP.String()
		if (srcIPStr == "::" && dstIPStr == "::") || (srcIPStr == "0.0.0.0" && dstIPStr == "0.0.0.0") {
			continue
		}

		// Filter out SSH/SCP traffic coming into the server, this is to
		// prevent users from seeing their own ssh session traffic.
		if key.DstPort == 22 {
			continue
		}

		// Check if this IP is a DNS service
		isDNSTraffic := false
		for _, dnsIP := range dnsServiceIPs {
			if dstIPStr == dnsIP || srcIPStr == dnsIP {
				isDNSTraffic = true
				break
			}
		}

		// Skip if external-only is enabled and destination IP is internal
		// But always include DNS traffic even with externalOnly flag
		if externalOnly != nil && *externalOnly && !isDNSTraffic && !isExternalIP(dstIP) {
			continue
		}

		entry := statEntry{
			SrcIP:     srcIP,
			DstIP:     dstIP,
			Proto:     protoToString(key.Proto),
			SrcPort:   key.SrcPort,
			DstPort:   key.DstPort,
			Pid:       key.Pid,
			Comm:      comm2String(key.Comm[:]),
			Timestamp: time.Now(),
		}

		// Set service name based on destination port
		if key.Proto == 6 || key.Proto == 17 { // TCP or UDP
			entry.LikelyService = portToLikelyServiceName(key.DstPort)
		}

		// Look up pod names if Kubernetes client is available
		if getKubeClient() != nil {
			entry.SourcePod = lookupPodForIP(srcIP)
			entry.DstPod = lookupPodForIP(dstIP)
		}

		stats = append(stats, entry)
	}

	sortFunc(stats)

	var result error
	if err := iter.Err(); err != nil {
		result = multierror.Append(result, err)
	}

	if _, err := m.BatchDelete(observedKeys, nil); err != nil {
		result = multierror.Append(result, err)
	}

	return stats, result
}

// timeDateSort sorts a slice of statEntry objects by their Timestamp field in ascending order.
//
// Parameters:
//
//	stats []statEntry - the slice of statEntry objects to be sorted
func timeDateSort(stats []statEntry) {
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].Timestamp.Before(stats[j].Timestamp)
	})
}

// outputJSON formats the provided statEntry slice into JSON Lines format.
//
// JSON Lines format outputs each entry as a separate JSON object on its own line,
// rather than as a JSON array. This is useful for streaming and processing large datasets.
//
// Parameters:
//
//	m []statEntry - the statEntry slice to be formatted
//
// Returns:
//
//	string - the JSON Lines string representation of m
func outputJSON(m []statEntry) string {
	var sb strings.Builder

	for _, entry := range m {
		jsonBytes, _ := json.Marshal(entry)
		sb.Write(jsonBytes)
		sb.WriteByte('\n')
	}

	return sb.String()
}

// comm2String converts a byte slice to a string, trimming any null bytes.
//
// It takes a byte slice as its parameter and returns a string.
// If the byte slice is empty, the function returns the string "kernel".
// Otherwise, it creates a new byte slice, copies the input byte slice into it,
// trims any null bytes from the end of the slice, and returns the result as a string.
func comm2String(bs []int8) string {
	b := make([]byte, len(bs))
	for i, v := range bs {
		b[i] = byte(v)
	}

	// trim excess NULLs
	b = bytes.Trim(b, "\x00")

	return string(b)
}
