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
