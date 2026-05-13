// @license
// Copyright (C) 2025  Dinko Korunic
//
// SPDX-License-Identifier: MIT

//go:build ignore

#pragma once

#define PATH_MAX 4096
#define CGROUP_FSMAGIC 0x27e0eb    // v1
#define CGROUP2_FSMAGIC 0x63677270 // v2

union kernfs_node_id {
  struct {
    u32 ino;
    u32 generation;
  };
  u64 id;
};

struct kernfs_node___older_v55 {
  const char *name;
  union kernfs_node_id id;
};

struct kernfs_node___rh8 {
  const char *name;
  union {
    u64 id;
    struct {
      union kernfs_node_id id;
    } rh_kabi_hidden_172;
    union {};
  };
};

// Adapted from aquasecurity/tracee (Apache-2.0).
static inline __attribute__((always_inline)) __u64
get_cgroup_id(struct cgroup *cgrp) {
  struct kernfs_node *kn = BPF_CORE_READ(cgrp, kn);

  if (kn == NULL)
    return 0;

  __u64 id;

  if (bpf_core_type_exists(union kernfs_node_id)) {
    // Pre-5.5: id is a union; RHEL8 backports a u64 alongside it.
    struct kernfs_node___older_v55 *kn_old = (void *)kn;
    struct kernfs_node___rh8 *kn_rh8 = (void *)kn;

    if (bpf_core_field_exists(kn_rh8->id)) {
      bpf_core_read(&id, sizeof(__u64), &kn_rh8->id);
      id = id & 0xffffffff; // u32 portion
    } else {
      bpf_core_read(&id, sizeof(__u64), &kn_old->id);
      id = id & 0xffffffff;
    }
  } else {
    bpf_core_read(&id, sizeof(__u64), &kn->id);
  }

  return id;
}
