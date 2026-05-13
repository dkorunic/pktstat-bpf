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

	// Initial cap for the statEntry result slice when the caller didn't pass a
	// reuse buffer. mapMaxEntries can be 131072+ (or whatever --max-entries
	// sets), which on a low-traffic system would mean a ~16 MB allocation per
	// call holding mostly nothing. 4096 covers most steady-state workloads;
	// append-grow handles the long tail.
	initialStatsHint = 4096
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

	// commIntern dedupes comm strings across all statEntry rows. Process names
	// repeat heavily (a few dozen distinct values across 100k+ entries), so
	// interning by the raw [16]int8 array means we only do the unsafe.Slice +
	// trim + string allocation once per *distinct* comm rather than per entry.
	commIntern   = make(map[[16]int8]string)
	commInternMu sync.Mutex
)

// internComm returns a single shared string for each distinct [16]int8 comm
// blob, materialising the string on first sight and reusing it thereafter.
// addStats is the only caller and runs on the listMap goroutine, so the mutex
// is uncontended in practice; we still hold it to be safe against future use.
func internComm(bs [16]int8) string {
	commInternMu.Lock()
	defer commInternMu.Unlock()

	if s, ok := commIntern[bs]; ok {
		return s
	}

	s := bsliceToString(bs[:])
	commIntern[bs] = s

	return s
}

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

	// BatchLookup needs v5.6+.
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
func listMap(m *ebpf.Map, l7 *ebpf.Map, start time.Time, buf []statEntry) ([]statEntry, error) {
	checkBatchMapSupportOnce.Do(func() {
		// Resolve before allocating per-CPU value buffers.
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

	appProtoByFlow := readFlowAppProto(l7)

	if haveBatchMapSupport {
		return listMapBatch(m, appProtoByFlow, start, buf)
	}

	// Iterator fallback; may abort on LRU per-CPU churn.
	return listMapIterate(m, appProtoByFlow, start, buf)
}

// listMapBatch lists all the entries in the given ebpf.Map, converting the
// counter values into a statEntry slice using batch lookups.
//
// The function uses the start time to calculate the duration of each entry.
//
// The function is safe to call concurrently.
//
// listMapBatch is used by listMap when the map supports batch lookups.
func listMapBatch(m *ebpf.Map, appProtoByFlow map[tcFlowkey]uint8, start time.Time, buf []statEntry) ([]statEntry, error) {
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
		stats = make([]statEntry, 0, min(mapMaxEntries, initialStatsHint))
	}

	var cursor ebpf.MapBatchCursor

	// values is flat: per-CPU vector for keys[i] at [i*possibleCPUs : (i+1)*possibleCPUs].
	for {
		c, err := m.BatchLookup(&cursor, keys, values, nil)

		for i := range keys[:c] {
			perCPU := values[i*possibleCPUs : (i+1)*possibleCPUs]
			stats = addStats(stats, keys[i], sumPerCPUValue(perCPU), appProtoByFlow, dur)
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
func listMapIterate(m *ebpf.Map, appProtoByFlow map[tcFlowkey]uint8, start time.Time, buf []statEntry) ([]statEntry, error) {
	var key tcStatkey
	// Per-CPU iterator wants a slice of length PossibleCPU.
	val := make([]tcStatvalue, possibleCPUs)

	dur := time.Since(start).Seconds()
	if dur < minDuration {
		dur = minDuration
	}

	var stats []statEntry
	if buf != nil {
		stats = buf[:0]
	} else {
		stats = make([]statEntry, 0, min(mapMaxEntries, initialStatsHint))
	}

	iter := m.Iterate()

	for iter.Next(&key, &val) {
		stats = addStats(stats, key, sumPerCPUValue(val), appProtoByFlow, dur)
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
func addStats(stats []statEntry, key tcStatkey, val tcStatvalue, appProtoByFlow map[tcFlowkey]uint8, dur float64) []statEntry {
	stats = append(stats, statEntry{
		SrcIP:    bytesToAddr(key.Srcip.In6U.U6Addr8),
		DstIP:    bytesToAddr(key.Dstip.In6U.U6Addr8),
		Proto:    protoToString(key.Proto),
		AppProto: appProtoToString(appProtoByFlow[statkeyToFlowkey(key)]),
		SrcPort:  key.SrcPort,
		DstPort:  key.DstPort,
		Bytes:    val.Bytes,
		Packets:  val.Packets,
		Bitrate:  8 * float64(val.Bytes) / dur,
		Pid:      key.Pid,
		Comm:     internComm(key.Comm),
		CGroup:   cGroupToPath(key.Cgroupid),
	})

	return stats
}

// readFlowAppProto loads the entire flow_app_proto map into a Go map keyed
// by the canonical tcFlowkey type. Returns nil on error; callers treat that
// the same as an empty map (all entries get AppProto = "" / unknown).
func readFlowAppProto(m *ebpf.Map) map[tcFlowkey]uint8 {
	if m == nil {
		return nil
	}

	out := make(map[tcFlowkey]uint8, m.MaxEntries()/8)

	var k tcFlowkey
	var v uint8

	iter := m.Iterate()
	for iter.Next(&k, &v) {
		out[k] = v
	}

	// Iteration aborted under churn is non-fatal — worst case is a few rows
	// missing AppProto until the next refresh.
	_ = iter.Err()

	return out
}

// statkeyToFlowkey derives the canonical 5-tuple flowkey from a tcStatkey,
// dropping PID, comm, and cgroupid — L7 protocol is a property of the flow.
func statkeyToFlowkey(k tcStatkey) tcFlowkey {
	return tcFlowkey{
		Srcip:   k.Srcip,
		Dstip:   k.Dstip,
		SrcPort: k.SrcPort,
		DstPort: k.DstPort,
		Proto:   k.Proto,
	}
}
