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

const (
	batchSize   = 4096
	minDuration = 1e-9 // 1 nanosecond floor to avoid division by zero in bitrate
)

type batchBuffers struct {
	keys   []tcStatkey
	values []tcStatvalue
}

var (
	haveBatchMapSupport      bool
	mapMaxEntries            uint32
	possibleCPUs             int
	checkBatchMapSupportOnce sync.Once

	batchPool sync.Pool
)

// sumPerCPUValue collapses a per-CPU statvalue vector into a single
// aggregate. The pkt_count map is BPF_MAP_TYPE_LRU_PERCPU_HASH, so every
// lookup returns one slot per possible CPU and we add them together for the
// userspace view.
func sumPerCPUValue(perCPU []tcStatvalue) tcStatvalue {
	var sum tcStatvalue

	for i := range perCPU {
		sum.Packets += perCPU[i].Packets
		sum.Bytes += perCPU[i].Bytes
	}

	return sum
}

// checkBatchMapSupport checks whether the given ebpf.Map supports batch lookups.
//
// A batch lookup is supported if the map supports the BPF_MAP_LOOKUP_BATCH
// flag. This flag is only supported on Linux v5.6 and above.
//
// The function performs a batch lookup on the map with a single dummy key and
// per-CPU value buffer to test whether the operation is supported. If the
// map does not support batch lookups, the function returns false. Otherwise,
// it returns true.
func checkBatchMapSupport(m *ebpf.Map) bool {
	keys := make([]tcStatkey, 1)
	values := make([]tcStatvalue, possibleCPUs) // flat: 1 key × possibleCPUs

	var cursor ebpf.MapBatchCursor

	// BPF_MAP_LOOKUP_BATCH support requires v5.6 kernel
	_, err := m.BatchLookup(&cursor, keys, values, nil)

	return !errors.Is(err, ebpf.ErrNotSupported)
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
func listMap(m *ebpf.Map, start time.Time, buf []statEntry) ([]statEntry, error) {
	checkBatchMapSupportOnce.Do(func() {
		// PossibleCPU must be resolved before allocating per-CPU value
		// buffers; it depends on a one-time procfs read inside cilium/ebpf.
		cpus, err := ebpf.PossibleCPU()
		if err != nil || cpus < 1 {
			cpus = 1
		}
		possibleCPUs = cpus

		batchPool = sync.Pool{
			New: func() any {
				return &batchBuffers{
					keys:   make([]tcStatkey, batchSize),
					values: make([]tcStatvalue, batchSize*possibleCPUs),
				}
			},
		}

		haveBatchMapSupport = checkBatchMapSupport(m)
		mapMaxEntries = m.MaxEntries()
	})

	if haveBatchMapSupport {
		return listMapBatch(m, start, buf)
	}

	// fallback to regular eBPF map iteration which might get interrupted for BPF_MAP_TYPE_LRU_PERCPU_HASH
	return listMapIterate(m, start, buf)
}

// listMapBatch lists all the entries in the given ebpf.Map, converting the
// counter values into a statEntry slice using batch lookups.
//
// The function uses the start time to calculate the duration of each entry.
//
// The function is safe to call concurrently.
//
// listMapBatch is used by listMap when the map supports batch lookups.
func listMapBatch(m *ebpf.Map, start time.Time, buf []statEntry) ([]statEntry, error) {
	batch := batchPool.Get().(*batchBuffers)
	defer batchPool.Put(batch)

	keys := batch.keys
	values := batch.values // flat: batchSize × possibleCPUs

	dur := time.Since(start).Seconds()
	if dur < minDuration {
		dur = minDuration
	}

	var stats []statEntry
	if buf != nil {
		stats = buf[:0]
	} else {
		stats = make([]statEntry, 0, mapMaxEntries)
	}

	var cursor ebpf.MapBatchCursor

	// BPF_MAP_LOOKUP_BATCH support requires v5.6 kernel. For per-CPU maps
	// cilium/ebpf returns a flat slice of length count*possibleCPUs, where
	// values[i*possibleCPUs : (i+1)*possibleCPUs] holds the per-CPU vector
	// for keys[i].
	for {
		c, err := m.BatchLookup(&cursor, keys, values, nil)

		for i := range keys[:c] {
			perCPU := values[i*possibleCPUs : (i+1)*possibleCPUs]
			stats = addStats(stats, keys[i], sumPerCPUValue(perCPU), dur)
		}

		if err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				break
			}

			return stats, err
		}
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
func listMapIterate(m *ebpf.Map, start time.Time, buf []statEntry) ([]statEntry, error) {
	var key tcStatkey
	// Per-CPU map iterator expects a slice of length PossibleCPU().
	val := make([]tcStatvalue, possibleCPUs)

	dur := time.Since(start).Seconds()
	if dur < minDuration {
		dur = minDuration
	}

	var stats []statEntry
	if buf != nil {
		stats = buf[:0]
	} else {
		stats = make([]statEntry, 0, mapMaxEntries)
	}

	iter := m.Iterate()

	// build statEntry slice converting data where needed
	for iter.Next(&key, &val) {
		stats = addStats(stats, key, sumPerCPUValue(val), dur)
	}

	return stats, iter.Err()
}

// addStats takes a slice of statEntry, a tcStatkey, a tcStatvalue,
// and a duration in seconds, and appends a new statEntry to the slice using
// the provided data. The function converts the key SrcIP and DstIP fields to
// netip.Addr objects, and the Comm field to a string. It also calculates the
// bitrate by dividing the number of bytes by the duration.
//
// Parameters:
//   - stats []statEntry: the slice of statEntry objects to which the new entry is appended
//   - key tcStatkey: the tcStatkey object containing the source and
//     destination IP addresses, protocol, and ports, as well as the PID, Comm,
//     and CGroup information
//   - val tcStatvalue: the tcStatvalue object containing the packet
//     and byte counters
//   - dur float64: the duration in seconds
//
// Returns:
//   - []statEntry: the updated slice of statEntry objects
func addStats(stats []statEntry, key tcStatkey, val tcStatvalue, dur float64) []statEntry {
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
