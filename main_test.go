// @license
// Copyright (C) 2026  Dinko Korunic
//
// SPDX-License-Identifier: MIT

package main

import (
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

// withFlags swaps the package-level flag pointers used by the apply* helpers
// for the duration of the test. The helpers dereference these pointers
// directly, so leaving them nil would panic. Tests calling withFlags must NOT
// run with t.Parallel — the swap mutates shared state.
func withFlags(t *testing.T, maxEnt uint, noArpFlag bool) {
	t.Helper()

	savedMax := maxEntries
	savedNoARP := noARP

	t.Cleanup(func() {
		maxEntries = savedMax
		noARP = savedNoARP
	})

	m := maxEnt
	n := noArpFlag
	maxEntries = &m
	noARP = &n
}

// withAggregate swaps the aggregation flag state for the duration of the test,
// mirroring withFlags. keyFn nil means a grand total (the BPF fast path);
// non-nil means --aggregate-by, which must stay on the per-flow path.
func withAggregate(t *testing.T, on bool, keyFn func(statEntry) string) {
	t.Helper()

	savedAggregate := aggregate
	savedKeyFn := aggregateKeyFn

	t.Cleanup(func() {
		aggregate = savedAggregate
		aggregateKeyFn = savedKeyFn
	})

	a := on
	aggregate = &a
	aggregateKeyFn = keyFn
}

func TestApplyMaxEntriesPatchesTCMaps(t *testing.T) { //nolint:paralleltest // mutates package-level flag globals
	withFlags(t, 16384, false)

	spec, err := loadTc()
	if err != nil {
		t.Fatalf("loadTc: %v", err)
	}

	applyMaxEntries(spec)

	for _, name := range []string{"pkt_count", "flow_app_proto"} {
		m, ok := spec.Maps[name]
		if !ok {
			t.Fatalf("map %q missing from TC spec", name)
		}

		if m.MaxEntries != 16384 {
			t.Errorf("TC %s.MaxEntries = %d, want 16384", name, m.MaxEntries)
		}
	}
}

func TestApplyMaxEntriesPatchesCgroupSkbSockInfo(t *testing.T) { //nolint:paralleltest // mutates package-level flag globals
	withFlags(t, 32768, false)

	spec, err := loadCgroupSkb()
	if err != nil {
		t.Fatalf("loadCgroupSkb: %v", err)
	}

	applyMaxEntries(spec)

	for _, name := range []string{"pkt_count", "flow_app_proto", "sock_info"} {
		m, ok := spec.Maps[name]
		if !ok {
			t.Fatalf("map %q missing from CgroupSkb spec", name)
		}

		if m.MaxEntries != 32768 {
			t.Errorf("CgroupSkb %s.MaxEntries = %d, want 32768", name, m.MaxEntries)
		}
	}
}

func TestApplyMaxEntriesZeroIsNoOp(t *testing.T) { //nolint:paralleltest // mutates package-level flag globals
	withFlags(t, 0, false)

	spec, err := loadTc()
	if err != nil {
		t.Fatalf("loadTc: %v", err)
	}

	// Capture pre-patch defaults so we can diff against them.
	before := make(map[string]uint32, len(spec.Maps))
	for name, m := range spec.Maps {
		before[name] = m.MaxEntries
	}

	applyMaxEntries(spec)

	for name, prev := range before {
		if spec.Maps[name].MaxEntries != prev {
			t.Errorf("map %q changed under maxEntries=0: %d → %d",
				name, prev, spec.Maps[name].MaxEntries)
		}
	}
}

func TestApplyArpEnabledOff(t *testing.T) { //nolint:paralleltest // mutates package-level flag globals
	withFlags(t, 0, true)

	spec, err := loadTc()
	if err != nil {
		t.Fatalf("loadTc: %v", err)
	}

	applyArpEnabled(spec)

	v, ok := spec.Variables["arp_enabled"]
	if !ok {
		t.Fatal("arp_enabled variable missing from TC spec")
	}

	var got uint8
	if err := v.Get(&got); err != nil {
		t.Fatalf("variable Get: %v", err)
	}

	if got != 0 {
		t.Errorf("arp_enabled = %d, want 0 when --no-arp", got)
	}
}

func TestApplyArpEnabledOnLeavesDefault(t *testing.T) { //nolint:paralleltest // mutates package-level flag globals
	withFlags(t, 0, false)

	spec, err := loadTc()
	if err != nil {
		t.Fatalf("loadTc: %v", err)
	}

	applyArpEnabled(spec)

	v := spec.Variables["arp_enabled"]

	var got uint8
	if err := v.Get(&got); err != nil {
		t.Fatalf("variable Get: %v", err)
	}

	// BPF-side default in counter_common.h is 1 (ARP capture enabled).
	if got != 1 {
		t.Errorf("arp_enabled = %d, want 1 (BPF default)", got)
	}
}

func TestApplyCgrpfsMagicOnCgroupSkbSpec(t *testing.T) { //nolint:paralleltest // mutates package-level flag globals
	// withFlags isolates global state across tests, even though we pass magic explicitly.
	withFlags(t, 0, false)

	spec, err := loadCgroupSkb()
	if err != nil {
		t.Fatalf("loadCgroupSkb: %v", err)
	}

	const magic uint64 = 0x63677270 // Cgroup2FsMagic

	if err := applyCgrpfsMagic(spec, magic); err != nil {
		t.Fatalf("applyCgrpfsMagic: %v", err)
	}

	v, ok := spec.Variables["cgrpfs_magic"]
	if !ok {
		t.Fatal("cgrpfs_magic variable missing from CgroupSkb spec")
	}

	var got uint64
	if err := v.Get(&got); err != nil {
		t.Fatalf("variable Get: %v", err)
	}

	if got != magic {
		t.Errorf("cgrpfs_magic = 0x%x, want 0x%x", got, magic)
	}
}

func TestApplyCgrpfsMagicMissingVariableIsNoOp(t *testing.T) { //nolint:paralleltest // mutates spec.Variables map
	// Simulate a spec without cgrpfs_magic by deleting it from the TC spec.
	spec, err := loadTc()
	if err != nil {
		t.Fatalf("loadTc: %v", err)
	}

	delete(spec.Variables, "cgrpfs_magic")

	// Must not error or panic on the missing variable.
	if err := applyCgrpfsMagic(spec, 0xdeadbeef); err != nil {
		t.Errorf("applyCgrpfsMagic on spec without variable returned error: %v", err)
	}
}

func TestApplyMaxEntriesIgnoresMissingMaps(t *testing.T) { //nolint:paralleltest // mutates package-level flag globals
	withFlags(t, 4096, false)

	spec, err := loadTc()
	if err != nil {
		t.Fatalf("loadTc: %v", err)
	}

	// TC spec lacks sock_info; guards against silent additions.
	if _, has := spec.Maps["sock_info"]; has {
		t.Skip("TC spec unexpectedly has sock_info; test no longer guards the missing-map path")
	}

	// Missing-map branch must not panic and must still patch present maps.
	applyMaxEntries(spec)

	if spec.Maps["pkt_count"].MaxEntries != 4096 {
		t.Errorf("pkt_count not patched after missing-map fallthrough")
	}
}

// Sanity that loadTc / loadCgroupSkb actually returns usable specs. Without
// this, a corrupt embedded .o would manifest as flaky downstream test failures
// (Maps[...] returning nil) rather than a clean diagnostic.
func TestEmbeddedSpecsLoadable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		loader func() (*ebpf.CollectionSpec, error)
	}{
		{"tc", loadTc},
		{"xdp", loadXdp},
		{"kprobe", loadKprobe},
		{"cgroupSkb", loadCgroupSkb},
		{"cgroup", loadCgroup},
	}

	for _, c := range cases {
		spec, err := c.loader()
		if err != nil {
			t.Errorf("%s loader failed: %v", c.name, err)

			continue
		}

		if spec == nil {
			t.Errorf("%s loader returned nil spec", c.name)
		}
	}
}

// The counter programs must all expose total_count as a 1-entry per-CPU array.
// An LRU hash here would silently reintroduce the eviction undercount that the
// map exists to avoid, so assert the type explicitly.
func TestTotalCountMapShape(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		loader func() (*ebpf.CollectionSpec, error)
	}{
		{"tc", loadTc},
		{"xdp", loadXdp},
		{"kprobe", loadKprobe},
		{"cgroupSkb", loadCgroupSkb},
	}

	for _, c := range cases {
		spec, err := c.loader()
		if err != nil {
			t.Fatalf("%s loader failed: %v", c.name, err)
		}

		m, ok := spec.Maps["total_count"]
		if !ok {
			t.Errorf("%s: total_count map missing", c.name)

			continue
		}

		if m.Type != ebpf.PerCPUArray {
			t.Errorf("%s: total_count type = %v, want PerCPUArray", c.name, m.Type)
		}

		if m.MaxEntries != 1 {
			t.Errorf("%s: total_count MaxEntries = %d, want 1", c.name, m.MaxEntries)
		}
	}
}

// --max-entries sizes the per-flow maps; total_count is a fixed single slot
// and must not be swept up by that patch.
func TestApplyMaxEntriesLeavesTotalCount(t *testing.T) { //nolint:paralleltest // mutates package-level flag globals
	withFlags(t, 16384, false)

	spec, err := loadTc()
	if err != nil {
		t.Fatalf("loadTc: %v", err)
	}

	applyMaxEntries(spec)

	if got := spec.Maps["total_count"].MaxEntries; got != 1 {
		t.Errorf("total_count MaxEntries = %d, want 1 (unaffected by --max-entries)", got)
	}
}

func TestApplyAggregateOnlyTotals(t *testing.T) { //nolint:paralleltest // mutates package-level flag globals
	withAggregate(t, true, nil)

	spec, err := loadTc()
	if err != nil {
		t.Fatalf("loadTc: %v", err)
	}

	applyAggregateOnly(spec)

	v, ok := spec.Variables["aggregate_only"]
	if !ok {
		t.Fatal("aggregate_only variable missing from TC spec")
	}

	var got uint8
	if err := v.Get(&got); err != nil {
		t.Fatalf("variable Get: %v", err)
	}

	if got != 1 {
		t.Errorf("aggregate_only = %d, want 1 under --aggregate", got)
	}
}

// --aggregate-by needs the per-flow rows, so it must leave the per-flow write
// path enabled even though *aggregate is set.
func TestApplyAggregateOnlyGroupedLeavesDefault(t *testing.T) { //nolint:paralleltest // mutates package-level flag globals
	keyFn, ok := aggKeyFunc("proto")
	if !ok {
		t.Fatal("aggKeyFunc(proto) not found")
	}

	withAggregate(t, true, keyFn)

	spec, err := loadTc()
	if err != nil {
		t.Fatalf("loadTc: %v", err)
	}

	applyAggregateOnly(spec)

	var got uint8
	if err := spec.Variables["aggregate_only"].Get(&got); err != nil {
		t.Fatalf("variable Get: %v", err)
	}

	if got != 0 {
		t.Errorf("aggregate_only = %d, want 0 under --aggregate-by", got)
	}
}

func TestApplyAggregateOnlyOffLeavesDefault(t *testing.T) { //nolint:paralleltest // mutates package-level flag globals
	withAggregate(t, false, nil)

	spec, err := loadTc()
	if err != nil {
		t.Fatalf("loadTc: %v", err)
	}

	applyAggregateOnly(spec)

	var got uint8
	if err := spec.Variables["aggregate_only"].Get(&got); err != nil {
		t.Fatalf("variable Get: %v", err)
	}

	if got != 0 {
		t.Errorf("aggregate_only = %d, want 0 (BPF default)", got)
	}
}

// The cgroup_mkdir tracer does not include counter_common.h; the patcher must
// no-op rather than panic on a spec without the variable.
func TestApplyAggregateOnlyMissingVariableIsNoOp(t *testing.T) { //nolint:paralleltest // mutates package-level flag globals
	withAggregate(t, true, nil)

	spec, err := loadCgroup()
	if err != nil {
		t.Fatalf("loadCgroup: %v", err)
	}

	if _, ok := spec.Variables["aggregate_only"]; ok {
		t.Fatal("cgroup spec unexpectedly exposes aggregate_only")
	}

	applyAggregateOnly(spec)
}

func TestReadTotalsNilMap(t *testing.T) {
	t.Parallel()

	if _, err := readTotals(nil, time.Now()); err == nil {
		t.Error("readTotals(nil) must return an error, not a zero row")
	}
}
