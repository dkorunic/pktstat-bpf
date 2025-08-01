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
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/cilium/ebpf/perf"
)

const (
	CGroupRootPath  = "/sys/fs/cgroup"
	PerfBufferPages = 16
)

var (
	cGroupCache     map[uint64]string
	cGroupCacheLock sync.RWMutex
	cGroupInitOnce  sync.Once

	ErrNotStatT = errors.New("not a syscall.Stat_t") // not a syscall.Stat_t for path %s
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
	if p, ok := cGroupCache[id]; ok {
		cGroupCacheLock.RUnlock()

		return p
	}
	cGroupCacheLock.RUnlock()

	// force the cache refresh if missing
	cgroupCacheRefresh(CGroupRootPath)

	cGroupCacheLock.Lock()
	defer cGroupCacheLock.Unlock()

	// create negative cache entry if still missing
	if _, ok := cGroupCache[id]; !ok {
		cGroupCache[id] = fmt.Sprintf("cgroup-id: %v", id)
	}

	// return the result, positive or negative
	return cGroupCache[id]
}

// cGroupCacheInit initializes the cgroup cache and starts a goroutine to watch the cgroup filesystem for create events.
//
// The function creates an empty map to store the cgroup IDs and their corresponding paths and then starts a goroutine to watch the cgroup filesystem for create events. When a create event is received, the goroutine refreshes the cache.
//
// The function is safe to call concurrently.
func cGroupCacheInit() {
	cGroupInitOnce.Do(func() {
		cGroupCache = make(map[uint64]string)

		// initial cache refresh
		cgroupCacheRefresh(CGroupRootPath)
	})
}

// cgroupCacheRefresh refreshes the cache with the current cgroup paths.
//
// It walks the cgroup filesystem from the given directory and updates the cache
// with the cgroup IDs and their corresponding paths. If the cache is already up
// to date, the function does nothing.
//
// The function is safe to call concurrently.
func cgroupCacheRefresh(dir string) {
	cGroupCacheLock.Lock()
	defer cGroupCacheLock.Unlock()

	if mapping, err := cGroupWalk(dir); err == nil {
		maps.Copy(cGroupCache, mapping)
	}
}

// cGroupWalk walks the cgroup filesystem and returns a mapping of cgroup IDs to their corresponding paths.
//
// The function takes a directory as an argument, which is the root of the cgroup filesystem. It walks the directory and its subdirectories, and for each subdirectory, it extracts the cgroup ID from the subdirectory's inode using `getInodeID`.
// The function returns a mapping of cgroup IDs to their corresponding paths. If an error occurs during the walk, it is returned as the second argument.
//
// The function is safe to call concurrently.
func cGroupWalk(dir string) (map[uint64]string, error) {
	mapping := map[uint64]string{}

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// ignore disappearing files/directories
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
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

		mapping[i] = path

		return nil
	})

	return mapping, err
}

// getInodeID returns the inode number of the file at the given path.
//
// The function takes a path as an argument, and returns the inode number of the file at that path. If an error occurs during the retrieval of the inode number, it is returned as the second argument.
//
// The function is safe to call concurrently.
func getInodeID(path string) (uint64, error) {
	i, err := os.Stat(path)
	if err != nil {
		return 0, err
	}

	s, ok := i.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("%w: %s", ErrNotStatT, path)
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
		var event cgroupCgroupevent

		var r perf.Record

		for {
			r, err = rd.Read()
			if err != nil {
				// reader has been closed
				if errors.Is(err, perf.ErrClosed) {
					return
				}

				continue
			}

			if err = binary.Read(bytes.NewBuffer(r.RawSample), binary.LittleEndian, &event); err != nil {
				continue
			}

			cGroupCacheLock.Lock()
			cGroupCache[event.Cgroupid] = bsliceToString(event.Path[:])
			cGroupCacheLock.Unlock()
		}
	}()

	return rd, nil
}
