// @license
// Copyright (C) 2025  Dinko Korunic
//
// SPDX-License-Identifier: MIT

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
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf/perf"
)

const (
	CGroupRootPath           = "/sys/fs/cgroup"
	CGroupRootPathUnified    = "/sys/fs/cgroup/unified"
	PerfBufferPages          = 16
	Cgroup1FsMagic           = 0x27e0eb
	Cgroup2FsMagic           = 0x63677270
	TmpFsMagic               = 0x1021994
	cgroupRefreshMinInterval = 250 * time.Millisecond
)

var (
	cGroupCache     = make(map[uint64]string)
	cGroupCacheLock sync.RWMutex
	cGroupRebuildMu sync.Mutex // serialises FS walks
	cGroupInitOnce  sync.Once

	// lastCgroupRefreshNano coalesces bursty refresh callers against the last walk.
	lastCgroupRefreshNano atomic.Int64
)

// cGroupToPath takes a cgroup ID and returns the corresponding path in the cgroup filesystem.
// The function will cache cgroup paths for better performance, but it will also invalidate the cache
// if it detects a change in the cgroup filesystem. If the cgroup ID is not found in the cache, it will
// refresh the cache and return an empty string.
//
// The function is safe to call concurrently.
func cGroupToPath(id uint64) string {
	if id == 0 {
		return ""
	}

	cGroupCacheLock.RLock()
	p, ok := cGroupCache[id]
	cGroupCacheLock.RUnlock()

	if ok {
		return p
	}

	// Single-walker gate prevents a thundering-herd of duplicate FS walks.
	cGroupRebuildMu.Lock()
	defer cGroupRebuildMu.Unlock()

	// Re-check: another goroutine may have populated `id` while we waited.
	cGroupCacheLock.RLock()
	p, ok = cGroupCache[id]
	hint := len(cGroupCache)
	cGroupCacheLock.RUnlock()

	if ok {
		return p
	}

	// Walk outside the cache lock so readers aren't blocked.
	fresh := make(map[uint64]string, hint)
	_ = cGroupWalk(CGroupRootPath, fresh)

	// Synthesise placeholder after merge to avoid clobbering watcher writes.
	cGroupCacheLock.Lock()
	maps.Copy(cGroupCache, fresh)

	p, ok = cGroupCache[id]
	if !ok {
		p = "cgroup-id: " + strconv.FormatUint(id, 10)
		cGroupCache[id] = p
	}
	cGroupCacheLock.Unlock()

	lastCgroupRefreshNano.Store(time.Now().UnixNano())

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
// Debounced via lastCgroupRefreshNano: when bursts of LostSamples events
// arrive (or many cold misses queue behind one walker), all but the first
// caller returns immediately rather than re-walking the filesystem.
//
// The function is safe to call concurrently.
func cgroupCacheRefresh(dir string) {
	now := time.Now().UnixNano()
	if now-lastCgroupRefreshNano.Load() < int64(cgroupRefreshMinInterval) {
		return
	}

	cGroupRebuildMu.Lock()
	defer cGroupRebuildMu.Unlock()

	// Re-check under the lock to coalesce queued callers.
	now = time.Now().UnixNano()
	if now-lastCgroupRefreshNano.Load() < int64(cgroupRefreshMinInterval) {
		return
	}

	cGroupCacheLock.RLock()
	hint := len(cGroupCache)
	cGroupCacheLock.RUnlock()

	fresh := make(map[uint64]string, hint)
	_ = cGroupWalk(dir, fresh)

	cGroupCacheLock.Lock()
	maps.Copy(cGroupCache, fresh)
	cGroupCacheLock.Unlock()

	lastCgroupRefreshNano.Store(time.Now().UnixNano())
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
			// Tolerate races with rmdir.
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
			// Tolerate races with rmdir.
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}

			return err
		}

		p := strings.TrimPrefix(path, dir)
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
				if errors.Is(err, perf.ErrClosed) {
					return
				}

				// Sleep to avoid tight-spin on persistent errors.
				log.Printf("cGroupWatcher: perf read error: %v", err)
				time.Sleep(10 * time.Millisecond)

				continue
			}

			// Lost samples → may have missed mkdirs; rebuild from FS.
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

// getCgroupFsMagic detects which cgroup hierarchy is mounted at /sys/fs/cgroup
// and returns the value to patch into the BPF-side `cgrpfs_magic` global so
// the verifier can fold the v1/v2 branch at load time.
//
// Returns one of:
//   - Cgroup1FsMagic — root is cgroup v1 (legacy); also returned for hybrid
//     systemd setups where root is tmpfs but /sys/fs/cgroup/unified is v2,
//     because v1 syscalls remain the working path under hybrid.
//   - Cgroup2FsMagic — root is the cgroup v2 unified hierarchy.
//
// The function is safe to call concurrently.
func getCgroupFsMagic() (uint64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(CGroupRootPath, &stat); err != nil {
		return 0, err
	}

	switch stat.Type {
	case Cgroup1FsMagic:
		log.Printf("Detected cgroup v1 (legacy mode)")

		return Cgroup1FsMagic, nil
	case Cgroup2FsMagic:
		log.Printf("Detected cgroup v2 (unified mode)")

		return Cgroup2FsMagic, nil
	case TmpFsMagic:
		err := syscall.Statfs(CGroupRootPathUnified, &stat)
		if err == nil && stat.Type == Cgroup2FsMagic {
			log.Printf("Detected cgroup v1 and v2 in hybrid mode")

			return Cgroup1FsMagic, nil
		}

		log.Printf("Detected cgroup v1 (legacy)")

		return Cgroup1FsMagic, nil
	}

	return 0, fmt.Errorf("unknown cgroup magic type %v", stat.Type)
}
