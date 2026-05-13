// @license
// Copyright (C) 2024  Dinko Korunic
//
// SPDX-License-Identifier: MIT

//go:build ignore

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define PKTSTAT_NEEDS_CGROUP_HELPERS
#include "counter_common.h"

// cookie → PID/comm, populated on sock_create, deleted on sock_release.
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, __u64);
  __type(value, sockinfo);
} sock_info SEC(".maps");

static inline __attribute__((always_inline)) void
process_cgroup_skb(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  __u64 pkt_len = skb->len;

  // cgroup_skb sees the packet at L3; bypass the eth parse.
  statkey key;
  if (!process_l3(data, data_end, bpf_ntohs(skb->protocol), &key)) {
    return;
  }

  __u64 cookie = bpf_get_socket_cookie(skb);
  // Cookie 0 = no socket; skip to avoid stale-entry hits.
  if (likely(cookie != 0)) {
    sockinfo *ski = bpf_map_lookup_elem(&sock_info, &cookie);
    if (likely(ski)) {
      key.pid = ski->pid;
      __builtin_memcpy(key.comm, ski->comm, sizeof(key.comm));
    }
  }

  // Branch folded at load time via cgrpfs_magic.
  if (cgrpfs_magic == CGROUP2_FSMAGIC) {
    key.cgroupid = bpf_skb_cgroup_id(skb);
  } else {
    key.cgroupid = get_current_cgroup_id_v1();
  }

  update_val(&key, pkt_len);
}

SEC("cgroup/sock_create")
int cgroup_sock_create(struct bpf_sock *sk) {
  __u64 cookie = bpf_get_socket_cookie(sk);
  // High 32 bits hold TGID (userspace PID).
  sockinfo ski = {
      .pid = bpf_get_current_pid_tgid() >> 32,
      .comm = {0},
  };

  bpf_get_current_comm(ski.comm, sizeof(ski.comm));

  bpf_map_update_elem(&sock_info, &cookie, &ski, BPF_ANY);

  return ALLOW_SK;
}

// Counterpart to sock_create; frees the sock_info slot eagerly so the LRU
// map doesn't carry dead bindings until natural eviction.
SEC("cgroup/sock_release")
int cgroup_sock_release(struct bpf_sock *sk) {
  __u64 cookie = bpf_get_socket_cookie(sk);
  if (likely(cookie != 0)) {
    bpf_map_delete_elem(&sock_info, &cookie);
  }

  return ALLOW_SK;
}

SEC("cgroup_skb/ingress")
int cgroup_skb_ingress(struct __sk_buff *skb) {
  process_cgroup_skb(skb);

  return ALLOW_PKT;
}

SEC("cgroup_skb/egress")
int cgroup_skb_egress(struct __sk_buff *skb) {
  process_cgroup_skb(skb);

  return ALLOW_PKT;
}

char __license[] SEC("license") = "Dual MIT/GPL";
