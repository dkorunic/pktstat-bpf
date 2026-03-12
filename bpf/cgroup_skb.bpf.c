// @license
// Copyright (C) 2024  Dinko Korunic
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

#include "counter_common.h"

// sock_info map: tracks socket cookie → PID/comm, populated on sock_create
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH); // LRU hash requires 4.10 kernel
  __uint(max_entries, MAX_ENTRIES);
  __type(key, __u64);
  __type(value, sockinfo);
} sock_info SEC(".maps");

/**
 * Process a socket buffer and extract relevant information to populate the key.
 *
 * This function is called by the BPF program for each socket buffer received.
 * It extracts relevant information from the socket buffer (PID, command name,
 * src/dst IP, src/dst port, protocol) and stores it in the key. It then looks
 * up the value in the packet count hash and increments the packet count and
 * byte count if the key is found. If the key is not found, it creates a new
 * entry with the packet count and byte count set to 1.
 *
 * @param skb pointer to the socket buffer
 *
 * @return none
 *
 * @throws none
 */
static inline __attribute__((always_inline)) void
process_cgroup_skb(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  __u64 pkt_len = skb->len;

  // initialize key
  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  switch (bpf_ntohs(skb->protocol)) {
  case ETH_P_IP: {
    struct iphdr *ip4 = data;

    if (process_ip4(ip4, data_end, &key) == NOK) {
      return;
    }

    break;
  }
  case ETH_P_IPV6: {
    struct ipv6hdr *ip6 = data;

    if (process_ip6(ip6, data_end, &key) == NOK) {
      return;
    }

    break;
  }
  default:
    return;
  }

  __u64 cookie = bpf_get_socket_cookie(skb);
  sockinfo *ski = bpf_map_lookup_elem(&sock_info, &cookie);
  if (ski) {
    key.pid = ski->pid;
    __builtin_memcpy(key.comm, ski->comm, sizeof(key.comm));
  }

  key.cgroupid = get_current_cgroup_id();

  statvalue *val = (statvalue *)bpf_map_lookup_elem(&pkt_count, &key);
  if (val) {
    // atomic XADD, doesn't need bpf_spin_lock()
    __sync_fetch_and_add(&val->packets, 1);
    __sync_fetch_and_add(&val->bytes, pkt_len);
  } else {
    statvalue initval = {.packets = 1, .bytes = pkt_len};

    // BPF_NOEXIST can race on multi-CPU: another CPU may insert the same key
    // between our lookup and this insert. On failure, retry the lookup and
    // increment atomically so the packet is not silently dropped.
    if (bpf_map_update_elem(&pkt_count, &key, &initval, BPF_NOEXIST) != 0) {
      val = (statvalue *)bpf_map_lookup_elem(&pkt_count, &key);
      if (val) {
        __sync_fetch_and_add(&val->packets, 1);
        __sync_fetch_and_add(&val->bytes, pkt_len);
      }
    }
  }
}

/**
 * BPF program entry point for tracking socket creations in a CGroup.
 *
 * This program is attached to the sock_create hook in the CGroup
 * hierarchy. It records the PID and command name of the process
 * creating the socket in the sock_info map.
 *
 * @param sk pointer to the newly created socket
 *
 * @return ALLOW_SK to allow the socket creation
 *
 * @throws none
 */
SEC("cgroup/sock_create")
int cgroup_sock_create(struct bpf_sock *sk) {
  __u64 cookie = bpf_get_socket_cookie(sk);
  sockinfo ski = {
      .pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF,
      .comm = {0},
  };

  bpf_get_current_comm(ski.comm, sizeof(ski.comm));

  bpf_map_update_elem(&sock_info, &cookie, &ski, BPF_ANY);

  return ALLOW_SK;
}

/**
 * BPF program entry point for tracking ingress traffic in a CGroup.
 *
 * This program is attached to the ingress hook in the CGroup hierarchy.
 * It records the packet and byte counters for the process associated with
 * the socket in the pkt_count map.
 *
 * @param skb pointer to the packet buffer
 *
 * @return ALLOW_PKT to allow the packet to be processed
 *
 * @throws none
 */
SEC("cgroup_skb/ingress")
int cgroup_skb_ingress(struct __sk_buff *skb) {
  process_cgroup_skb(skb);

  return ALLOW_PKT;
}

/**
 * BPF program entry point for tracking egress traffic in a CGroup.
 *
 * This program is attached to the egress hook in the CGroup hierarchy.
 * It records the packet and byte counters for the process associated with
 * the socket in the pkt_count map.
 *
 * @param skb pointer to the packet buffer
 *
 * @return ALLOW_PKT to allow the packet to be processed
 *
 * @throws none
 */
SEC("cgroup_skb/egress")
int cgroup_skb_egress(struct __sk_buff *skb) {
  process_cgroup_skb(skb);

  return ALLOW_PKT;
}

char __license[] SEC("license") = "Dual MIT/GPL";
