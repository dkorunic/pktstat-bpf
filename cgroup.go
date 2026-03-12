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
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf/perf"
)

const (
	CGroupRootPath        = "/sys/fs/cgroup"
	CGroupRootPathUnified = "/sys/fs/cgroup/unified"
	PerfBufferPages       = 16
	Cgroup1FsMagic        = 0x27e0eb
	Cgroup2FsMagic        = 0x63677270
	TmpFsMagic            = 0x1021994
)

var (
	cGroupCache     = make(map[uint64]string)
	cGroupCacheLock sync.RWMutex
	cGroupRebuildMu sync.Mutex // serialises filesystem walks to avoid thundering herd
	cGroupInitOnce  sync.Once
)

// cGroupToPath takes a cgroup ID and returns the corresponding path in the cgroup filesystem.
// The function will cache cgroup paths for better performance, but it will also invalidate the cache
// if it detects a change in the cgroup filesystem. If the cgroup ID is not found in the cache, it will
// refresh the cache and return an empty string.
//
// The function is safe to call concurrently.
func cGroupToPath(id uint64) string {
	// ID 0 is not a valid Cgroup ID
	if id == 0 {
		return ""
	}

	// fetch from cache first
	cGroupCacheLock.RLock()
	p, ok := cGroupCache[id]
	cGroupCacheLock.RUnlock()

	if ok {
		return p
	}

	// Serialise filesystem walks: only one goroutine rebuilds at a time.
	// This prevents the thundering-herd where N concurrent misses each do a
	// full walk and the last writer discards everyone else's results.
	cGroupRebuildMu.Lock()
	defer cGroupRebuildMu.Unlock()

	// Re-check after acquiring the rebuild lock; a concurrent goroutine may
	// have already walked and populated the entry while we were waiting.
	cGroupCacheLock.RLock()
	p, ok = cGroupCache[id]
	cGroupCacheLock.RUnlock()

	if ok {
		return p
	}

	// Build a fresh mapping outside any lock to avoid blocking readers during
	// the filesystem walk.
	fresh := make(map[uint64]string)
	_ = cGroupWalk(CGroupRootPath, fresh)

	// Synthesise a negative cache entry if still missing after the walk.
	p, ok = fresh[id]
	if !ok {
		p = "cgroup-id: " + strconv.FormatUint(id, 10)
		fresh[id] = p
	}

	// Merge fresh entries into the existing cache rather than replacing it,
	// so that entries written by cGroupWatcher between the walk start and now
	// are preserved.
	cGroupCacheLock.Lock()
	maps.Copy(cGroupCache, fresh)
	cGroupCacheLock.Unlock()

	return p
}

// cGroupCacheInit initializes the cgroup cache and starts a goroutine to watch the cgroup filesystem for create events.
//
// The function creates an empty map to store the cgroup IDs and their corresponding paths and then starts a goroutine to watch the cgroup filesystem for create events. When a create event is received, the goroutine refreshes the cache.
//
// The function is safe to call concurrently.
func cGroupCacheInit() {
	cGroupInitOnce.Do(func() {
		cGroupCacheLock.Lock()
		cGroupCache = make(map[uint64]string)
		cGroupCacheLock.Unlock()

		// initial cache refresh
		cgroupCacheRefresh(CGroupRootPath)
	})
}

// cgroupCacheRefresh refreshes the cache with the current cgroup paths.
//
// It walks the cgroup filesystem from the given directory and builds a new
// mapping outside of any lock. The fresh entries are then merged into the
// existing cache under a brief write lock, preserving any entries that
// cGroupWatcher wrote concurrently. cGroupRebuildMu is held for the duration
// so that concurrent callers do not each trigger a redundant walk.
//
// The function is safe to call concurrently.
func cgroupCacheRefresh(dir string) {
	cGroupRebuildMu.Lock()
	defer cGroupRebuildMu.Unlock()

	fresh := make(map[uint64]string)
	_ = cGroupWalk(dir, fresh)

	cGroupCacheLock.Lock()
	maps.Copy(cGroupCache, fresh)
	cGroupCacheLock.Unlock()
}

// cGroupWalk walks the cgroup filesystem and returns a mapping of cgroup IDs to their corresponding paths.
//
// The function takes a directory as an argument, which is the root of the cgroup filesystem. It walks the directory and its subdirectories, and for each subdirectory, it extracts the cgroup ID from the subdirectory's inode using `getInodeID`.
// The function returns a mapping of cgroup IDs to their corresponding paths. If an error occurs during the walk, it is returned as the second argument.
//
// The function is safe to call concurrently.
func cGroupWalk(dir string, mapping map[uint64]string) error {
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// ignore disappearing files/directories
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}

			return err
		}

		if !d.IsDir() {
			return nil
		}

		i, err := getInodeID(path)
		if err != nil {
			// ignore disappearing files/directories
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}

			return err
		}

		p := strings.TrimPrefix(path, CGroupRootPath)
		if p == "" {
			p = "/"
		}

		mapping[i] = p

		return nil
	})
}

// getInodeID returns the inode number of the file at the given path.
//
// The function takes a path as an argument, and returns the inode number of the file at that path. If an error occurs during the retrieval of the inode number, it is returned as the second argument.
//
// The function is safe to call concurrently.
func getInodeID(path string) (uint64, error) {
	var s syscall.Stat_t
	if err := syscall.Stat(path, &s); err != nil {
		return 0, err
	}

	return s.Ino, nil
}

// cGroupWatcher watches the cgroup filesystem for create events and updates the cgroup cache with the new cgroup IDs and their corresponding paths.
//
// The function takes a cgroupObjects structure as an argument, which contains the file descriptors of the cgroup filesystem and the perf event map. The function returns a perf.Reader object which can be used to read the events from the perf event map, and an error if any occurred during the creation of the perf.Reader object.
//
// The function is safe to call concurrently.
//
// The returned perf.Reader object will be closed when the returned error is ErrClosed.
func cGroupWatcher(objs cgroupObjects) (*perf.Reader, error) {
	rd, err := perf.NewReader(objs.PerfCgroupEvent, PerfBufferPages*os.Getpagesize())
	if err != nil {
		return nil, err
	}

	go func() {
		var (
			event cgroupCgroupevent
			r     perf.Record
			err   error
		)

		for {
			r, err = rd.Read()
			if err != nil {
				// reader has been closed
				if errors.Is(err, perf.ErrClosed) {
					return
				}

				// log and avoid tight-spinning on persistent errors
				log.Printf("cGroupWatcher: perf read error: %v", err)
				time.Sleep(10 * time.Millisecond)

				continue
			}

			// Perf buffer overflowed: lost samples mean we may have missed
			// cgroup mkdir events, so rebuild the cache from the filesystem.
			if r.LostSamples > 0 {
				cgroupCacheRefresh(CGroupRootPath)

				continue
			}

			if _, err = binary.Decode(r.RawSample, binary.LittleEndian, &event); err != nil {
				continue
			}

			path := bsliceToString(event.Path[:])

			cgroupPath := strings.TrimPrefix(path, CGroupRootPath)
			if cgroupPath == "" {
				cgroupPath = "/"
			}

			cGroupCacheLock.Lock()
			cGroupCache[event.Cgroupid] = cgroupPath
			cGroupCacheLock.Unlock()
		}
	}()

	return rd, nil
}

// getCgroupFsMagic returns the magic number of the cgroup filesystem.
//
// The function takes no arguments and returns the magic number of the cgroup filesystem as a uint32, and an error if any occurred during the retrieval of the magic number.
//
// The function is safe to call concurrently.
//
// The possible return values are Cgroup1FsMagic (0x27e0eb) and Cgroup2FsMagic (0x63677270).
func getCgroupFsMagic() (uint64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(CGroupRootPath, &stat); err != nil {
		return 0, err
	}

	switch stat.Type {
	case Cgroup1FsMagic:
		log.Printf("Detected cgroup v1 (legacy mode)")

		return Cgroup1FsMagic, nil // for legacy cgroups v1 we use cgroup v1 syscalls
	case Cgroup2FsMagic:
		log.Printf("Detected cgroup v2 (unified mode)")

		return Cgroup2FsMagic, nil // for unified cgroups v2 we use cgroup v2 syscalls
	case TmpFsMagic:
		err := syscall.Statfs(CGroupRootPathUnified, &stat)
		if err == nil && stat.Type == Cgroup2FsMagic {
			log.Printf("Detected cgroup v1 and v2 in hybrid mode")

			return Cgroup1FsMagic, nil // for hybrid systemd mode we use cgroup v1 syscalls
		}

		log.Printf("Detected cgroup v1 (legacy)")

		return Cgroup1FsMagic, nil
	}

	return 0, fmt.Errorf("unknown cgroup magic type %v", stat.Type)
}
