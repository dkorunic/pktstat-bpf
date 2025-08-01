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
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

//go:build ignore

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "cgroup.h"

typedef struct cgroup_event_t {
  char path[PATH_MAX]; // cgroup path
  __u64 cgroupid;      // cgroup ID
} cgroupevent;

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); // per cpu array requires 4.6 kernel
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, cgroupevent);
} cgroup_event SEC(".maps");

struct {
  __uint(type,
         BPF_MAP_TYPE_PERF_EVENT_ARRAY); // perf event array requires 4.3 kernel
  __uint(max_entries, MAX_ENTRIES);
  __type(key, int);
  __type(value, __u32);
} perf_cgroup_event SEC(".maps");

/**
 * get_cgroupid - reads the cgroup ID from the given struct cgroup
 *
 * This function reads the cgroup ID from the given struct cgroup and returns
 * it. The function works on kernels v4.10 and above.
 *
 * @cgrp: the struct cgroup to read the cgroup ID from
 *
 * Returns: the cgroup ID as an unsigned 64-bit integer
 *
 * get_cgroupid() comes from aquasecurity/tracee, license: Apache-2.0
 */
static inline __attribute__((always_inline)) __u64
get_cgroupid(struct cgroup *cgrp) {
  struct kernfs_node *kn = BPF_CORE_READ(cgrp, kn);

  if (kn == NULL)
    return 0;

  __u64 id; // was union kernfs_node_id before 5.5, can read it as u64 in both
            // situations

  if (bpf_core_type_exists(union kernfs_node_id)) {
    struct kernfs_node___older_v55 *kn_old = (void *)kn;
    struct kernfs_node___rh8 *kn_rh8 = (void *)kn;

    if (bpf_core_field_exists(kn_rh8->id)) {
      // RHEL8 has both types declared: union and u64:
      //     kn->id
      //     rh->rh_kabi_hidden_172->id
      // pointing to the same data
      bpf_core_read(&id, sizeof(__u64), &kn_rh8->id);
      id = id & 0xffffffff; // XXX: u32 is required
    } else {
      // all other regular kernels below v5.5
      bpf_core_read(&id, sizeof(__u64), &kn_old->id);
      id = id & 0xffffffff; // XXX: u32 is required
    }
  } else {
    // kernel v5.5 and above
    bpf_core_read(&id, sizeof(__u64), &kn->id);
  }

  return id;
}
/**
 * trace_cgroup_mkdir traces the creation of a new cgroup directory.
 *
 * This function is attached to the raw tracepoint for cgroup_mkdir events.
 * It retrieves the cgroup ID and the path of the newly created cgroup
 * directory, then stores this information in a cgroupevent structure.
 * The function outputs the event data to a perf event map for further
 * processing.
 *
 * @param ctx A pointer to the bpf_raw_tracepoint_args structure containing
 *            the arguments of the tracepoint, including the destination
 *            cgroup and path.
 *
 * @return Always returns 0.
 */
SEC("raw_tracepoint/cgroup_mkdir")
int trace_cgroup_mkdir(struct bpf_raw_tracepoint_args *ctx) {
  struct cgroup *dst_cgrp = (struct cgroup *)ctx->args[0];
  char *path = (char *)ctx->args[1];

  __u64 cgroupid = get_cgroupid(dst_cgrp);
  __u32 zero_key = 0;

  cgroupevent *val =
      (cgroupevent *)bpf_map_lookup_elem(&cgroup_event, &zero_key);
  if (val == NULL) {
    return 0;
  }

  bpf_probe_read_str(val->path, PATH_MAX, path);
  val->cgroupid = cgroupid;

  bpf_perf_event_output(ctx, &perf_cgroup_event, BPF_F_CURRENT_CPU, val,
                        sizeof(cgroupevent));

  return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
