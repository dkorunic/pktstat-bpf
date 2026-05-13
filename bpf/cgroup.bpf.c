// @license
// Copyright (C) 2025  Dinko Korunic
//
// SPDX-License-Identifier: MIT

//go:build ignore

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "cgroup.h"

typedef struct cgroup_event_t {
  char path[PATH_MAX];
  __u64 cgroupid;
} cgroupevent;

// Per-CPU PATH_MAX scratch (too large for stack).
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, cgroupevent);
} cgroup_event SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(max_entries, 0);
  __type(key, int);
  __type(value, __u32);
} perf_cgroup_event SEC(".maps");

SEC("raw_tracepoint/cgroup_mkdir")
int trace_cgroup_mkdir(struct bpf_raw_tracepoint_args *ctx) {
  struct cgroup *dst_cgrp = (struct cgroup *)ctx->args[0];
  char *path = (char *)ctx->args[1];

  __u64 cgroupid = get_cgroup_id(dst_cgrp);
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
