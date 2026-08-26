// @license
// Copyright (C) 2026  Dinko Korunic
//
// SPDX-License-Identifier: MIT

package main

import (
	"math"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// resetCgroupCacheState gives a test a known starting cache. Callers must not
// be parallel: these are package-wide globals.
func resetCgroupCacheState(t *testing.T) {
	t.Helper()

	cGroupCacheLock.Lock()
	cGroupCache = make(map[uint64]string)
	clear(cGroupUnknown)
	clear(cGroupPending)
	cGroupWalkActive = false
	cGroupCacheLock.Unlock()

	// Zero the debounce so the next refresh actually walks.
	lastCgroupRefreshNano.Store(0)
}

func TestCGroupToPathZero(t *testing.T) {
	t.Parallel()

	if got := cGroupToPath(0); got != "" {
		t.Errorf("cGroupToPath(0) = %q, want empty (zero id is the no-cgroup sentinel)", got)
	}
}

func TestGetInodeIDExistingPath(t *testing.T) {
	t.Parallel()

	// Per-test tempdir avoids platform-specific paths and auto-cleans.
	tmp := t.TempDir()

	ino, err := getInodeID(tmp)
	if err != nil {
		t.Fatalf("getInodeID(%q): %v", tmp, err)
	}

	if ino == 0 {
		t.Errorf("getInodeID returned zero inode for %q", tmp)
	}

	// Same path → same inode (sanity).
	ino2, err := getInodeID(tmp)
	if err != nil {
		t.Fatalf("getInodeID second call: %v", err)
	}

	if ino != ino2 {
		t.Errorf("getInodeID not stable: %d vs %d", ino, ino2)
	}
}

func TestGetInodeIDMissingPath(t *testing.T) {
	t.Parallel()

	// A path that cannot exist under any sane mount table.
	bogus := filepath.Join(t.TempDir(), "does-not-exist-zZz")

	if _, err := getInodeID(bogus); err == nil {
		t.Errorf("getInodeID(%q) succeeded, want error", bogus)
	}
}

func TestCGroupWalk(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	// Tree: a/, b/c/, plus file.txt (must be skipped).
	for _, sub := range []string{"a", "b/c"} {
		if err := os.MkdirAll(filepath.Join(root, sub), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", sub, err)
		}
	}

	if err := os.WriteFile(filepath.Join(root, "file.txt"), []byte("ignored"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	mapping := make(map[uint64]string)
	if err := cGroupWalk(root, mapping); err != nil {
		t.Fatalf("cGroupWalk: %v", err)
	}

	// Expect 4 entries: root + a + b + b/c.
	if len(mapping) < 4 {
		t.Errorf("len(mapping) = %d, want >= 4 (root + 3 subdirs)", len(mapping))
	}

	// Verify the path values are present (we don't know the inode numbers).
	gotPaths := make(map[string]struct{}, len(mapping))
	for _, p := range mapping {
		gotPaths[p] = struct{}{}
	}

	for _, want := range []string{"/", "/a", "/b", "/b/c"} {
		if _, ok := gotPaths[want]; !ok {
			t.Errorf("missing path %q in mapping; got %v", want, gotPaths)
		}
	}

	// The regular file must NOT appear (cGroupWalk filters on d.IsDir()).
	if _, ok := gotPaths["/file.txt"]; ok {
		t.Errorf("regular file leaked into cgroup mapping")
	}
}

// Regression: merge-only walks let ids of removed cgroups accumulate forever.
func TestCgroupCacheRefreshEvictsRemovedDirs(t *testing.T) {
	resetCgroupCacheState(t)

	root := t.TempDir()
	keep := filepath.Join(root, "keep")
	gone := filepath.Join(root, "gone")

	for _, d := range []string{keep, gone} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	keepID, err := getInodeID(keep)
	if err != nil {
		t.Fatalf("getInodeID(keep): %v", err)
	}

	goneID, err := getInodeID(gone)
	if err != nil {
		t.Fatalf("getInodeID(gone): %v", err)
	}

	cgroupCacheRefresh(root)

	cGroupCacheLock.RLock()
	_, haveKeep := cGroupCache[keepID]
	_, haveGone := cGroupCache[goneID]
	cGroupCacheLock.RUnlock()

	if !haveKeep || !haveGone {
		t.Fatalf("first refresh cached keep=%v gone=%v, want both", haveKeep, haveGone)
	}

	if err := os.Remove(gone); err != nil {
		t.Fatalf("rmdir gone: %v", err)
	}

	// Without this the debounce would swallow the second walk.
	lastCgroupRefreshNano.Store(0)
	cgroupCacheRefresh(root)

	cGroupCacheLock.RLock()
	_, haveKeep = cGroupCache[keepID]
	_, haveGone = cGroupCache[goneID]
	cGroupCacheLock.RUnlock()

	if haveGone {
		t.Errorf("id %d still cached after its directory was removed (leak)", goneID)
	}

	if !haveKeep {
		t.Errorf("id %d evicted even though its directory still exists", keepID)
	}
}

// A mkdir mid-walk must survive the walk's wholesale replace.
func TestCgroupInstallPreservesMidWalkMkdir(t *testing.T) {
	resetCgroupCacheState(t)

	const (
		walkedID  uint64 = 1001
		pendingID uint64 = 2002
	)

	cgroupWalkBegin()

	// Stands in for cGroupWatcher handling a cgroup_mkdir mid-walk.
	cGroupCacheLock.Lock()
	if cGroupWalkActive {
		cGroupPending[pendingID] = "/late"
	}
	cGroupCacheLock.Unlock()

	cgroupInstall(map[uint64]string{walkedID: "/walked"})

	cGroupCacheLock.RLock()
	defer cGroupCacheLock.RUnlock()

	if got := cGroupCache[pendingID]; got != "/late" {
		t.Errorf("mid-walk mkdir dropped by install: got %q, want %q", got, "/late")
	}

	if got := cGroupCache[walkedID]; got != "/walked" {
		t.Errorf("walk result missing after install: got %q, want %q", got, "/walked")
	}

	if len(cGroupPending) != 0 {
		t.Errorf("pending buffer not drained: %d entries left", len(cGroupPending))
	}

	if cGroupWalkActive {
		t.Error("walk window still open after install")
	}
}

// Regression: placeholders once lived in the main cache, one per dead id,
// never evicted.
func TestMarkCgroupUnknownStaysBounded(t *testing.T) {
	resetCgroupCacheState(t)

	for i := range cgroupUnknownMax * 2 {
		markCgroupUnknown(uint64(i) + 1)
	}

	cGroupCacheLock.RLock()
	n := len(cGroupUnknown)
	cGroupCacheLock.RUnlock()

	if n > cgroupUnknownMax {
		t.Errorf("negative cache holds %d entries, cap is %d", n, cgroupUnknownMax)
	}

	if n == 0 {
		t.Error("negative cache is empty; entries should persist between overflows")
	}
}

// An unresolvable id must be remembered, or every lookup re-walks the tree.
func TestCGroupToPathUnknownIsRemembered(t *testing.T) {
	resetCgroupCacheState(t)

	// No real cgroup directory can carry this inode number.
	const id uint64 = math.MaxUint64

	want := "cgroup-id: " + strconv.FormatUint(id, 10)

	if got := cGroupToPath(id); got != want {
		t.Fatalf("cGroupToPath(%d) = %q, want %q", id, got, want)
	}

	cGroupCacheLock.RLock()
	_, remembered := cGroupUnknown[id]
	cGroupCacheLock.RUnlock()

	if !remembered {
		t.Error("unresolved id not recorded; every lookup would re-walk the filesystem")
	}

	// Served from the negative cache this time.
	if got := cGroupToPath(id); got != want {
		t.Errorf("second cGroupToPath(%d) = %q, want %q", id, got, want)
	}
}

func TestCGroupWalkToleratesMissingPath(t *testing.T) {
	t.Parallel()

	// Pin rmdir-race tolerance: missing root must return nil, not an error.
	mapping := make(map[uint64]string)

	err := cGroupWalk(filepath.Join(t.TempDir(), "nope"), mapping)
	if err != nil {
		t.Errorf("cGroupWalk on missing root returned %v, want nil (rmdir-race tolerance)", err)
	}

	if len(mapping) != 0 {
		t.Errorf("mapping should be empty when root is missing, got %d entries", len(mapping))
	}
}
