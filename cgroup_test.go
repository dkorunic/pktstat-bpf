// @license
// Copyright (C) 2026  Dinko Korunic
//
// SPDX-License-Identifier: MIT

package main

import (
	"os"
	"path/filepath"
	"testing"
)

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

	// Build a small directory tree:
	//   <root>/
	//     a/
	//     b/c/
	//     file.txt   (ignored: not a directory)
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
