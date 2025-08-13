// @license
// Copyright (C) 2025  Dinko Korunic
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
	"errors"
	"sync"
	"time"

	"github.com/cilium/ebpf"
)

var (
	haveBatchMapSupport      bool
	checkBatchMapSupportOnce sync.Once
)

// checkBatchMapSupport checks whether the given ebpf.Map supports batch lookups.
//
// A batch lookup is supported if the map supports the BPF_MAP_LOOKUP_BATCH
// flag. This flag is only supported on Linux 5.7 and above.
//
// The function performs a batch lookup on the map with a single dummy key and
// value to test whether the operation is supported. If the map does not
// support batch lookups, the function returns false. Otherwise, it returns true.
func checkBatchMapSupport(m *ebpf.Map) bool {
	keys := make([]counterStatkey, 1)
	values := make([]counterStatvalue, 1)

	var cursor ebpf.MapBatchCursor

	// BPF_MAP_LOOKUP_BATCH support requires v5.6 kernel
	_, err := m.BatchLookup(&cursor, keys, values, nil)

	if err != nil && errors.Is(err, ebpf.ErrNotSupported) {
		return false
	}

	return true
}

// listMap lists all the entries in the given ebpf.Map, converting the counter
// values into a statEntry slice.
//
// The function uses the start time to calculate the duration of each entry.
//
// The function checks whether the map supports batch lookups and uses the
// optimized listMapBatch or listMapIterate functions accordingly.
//
// listMap is safe to call concurrently.
func listMap(m *ebpf.Map, start time.Time) ([]statEntry, error) {
	checkBatchMapSupportOnce.Do(func() {
		haveBatchMapSupport = checkBatchMapSupport(m)
	})

	if haveBatchMapSupport {
		return listMapBatch(m, start)
	}

	// fallback to regular eBPF map iteration which might get interrupted for BPF_MAP_TYPE_LRU_HASH
	return listMapIterate(m, start)
}

// listMapBatch lists all the entries in the given ebpf.Map, converting the
// counter values into a statEntry slice using batch lookups.
//
// The function uses the start time to calculate the duration of each entry.
//
// The function is safe to call concurrently.
//
// listMapBatch is used by listMap when the map supports batch lookups.
func listMapBatch(m *ebpf.Map, start time.Time) ([]statEntry, error) {
	keys := make([]counterStatkey, m.MaxEntries())
	values := make([]counterStatvalue, m.MaxEntries())

	dur := time.Since(start).Seconds()
	stats := make([]statEntry, 0, m.MaxEntries())

	var cursor ebpf.MapBatchCursor
	var (
		count int
		c     int
		err   error
	)

	// BPF_MAP_LOOKUP_BATCH support requires v5.6 kernel
	for {
		c, err = m.BatchLookup(&cursor, keys, values, nil)
		count += c

		if err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				break
			}

			return nil, err
		}
	}

	for i := 0; i < len(keys) && i < count; i++ {
		stats = addStats(stats, keys[i], values[i], dur)
	}

	return stats, nil
}

// listMapIterate iterates over all the entries in the given ebpf.Map,
// converting the counter values into a statEntry slice.
//
// The function uses the start time to calculate the duration of each entry,
// which is used to compute the bitrate.
//
// Parameters:
//   - m *ebpf.Map: the eBPF map to iterate over
//   - start time.Time: the start time for calculating entry duration
//
// Returns:
//   - []statEntry: a slice of statEntry objects containing the converted map entries
//   - error: an error if any occurred during map iteration, otherwise nil
func listMapIterate(m *ebpf.Map, start time.Time) ([]statEntry, error) {
	var (
		key counterStatkey
		val counterStatvalue
	)

	dur := time.Since(start).Seconds()
	stats := make([]statEntry, 0, m.MaxEntries())

	iter := m.Iterate()

	// build statEntry slice converting data where needed
	for iter.Next(&key, &val) {
		stats = addStats(stats, key, val, dur)
	}

	return stats, iter.Err()
}

// addStats takes a slice of statEntry, a counterStatkey, a counterStatvalue,
// and a duration in seconds, and appends a new statEntry to the slice using
// the provided data. The function converts the key SrcIP and DstIP fields to
// netip.Addr objects, and the Comm field to a string. It also calculates the
// bitrate by dividing the number of bytes by the duration.
//
// Parameters:
//   - stats []statEntry: the slice of statEntry objects to which the new entry is appended
//   - key counterStatkey: the counterStatkey object containing the source and
//     destination IP addresses, protocol, and ports, as well as the PID, Comm,
//     and CGroup information
//   - val counterStatvalue: the counterStatvalue object containing the packet
//     and byte counters
//   - dur float64: the duration in seconds
//
// Returns:
//   - []statEntry: the updated slice of statEntry objects
func addStats(stats []statEntry, key counterStatkey, val counterStatvalue, dur float64) []statEntry {
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
		Comm:    bsliceToString(key.Comm[:]),
		CGroup:  cGroupToPath(key.Cgroupid),
	})

	return stats
}
