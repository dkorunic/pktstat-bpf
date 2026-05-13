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

// kprobes lack skb-derived cgroup helper; use task-walk fallback.
#define PKTSTAT_NEEDS_CGROUP_HELPERS
#include "counter_common.h"

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  pid_t pid = bpf_get_current_pid_tgid() >> 32;

  // Filter unsupported families before paying for comm/cgroupid lookups.
  if (!process_tcp(false, sk, &key, pid))
    return 0;

  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
  }
  key.cgroupid = get_current_cgroup_id();

  update_val(&key, size);

  return 0;
}

SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(tcp_cleanup_rbuf, struct sock *sk, int copied) {
  if (unlikely(copied <= 0)) {
    return 0;
  }

  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  pid_t pid = bpf_get_current_pid_tgid() >> 32;

  if (!process_tcp(true, sk, &key, pid))
    return 0;

  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
  }
  key.cgroupid = get_current_cgroup_id();

  update_val(&key, copied);

  return 0;
}

SEC("kprobe/ip_send_skb")
int BPF_KPROBE(ip_send_skb, struct net *net, struct sk_buff *skb) {
  struct iphdr *iphdr = (struct iphdr *)(BPF_CORE_READ(skb, head) +
                                         BPF_CORE_READ(skb, network_header));
  if (BPF_CORE_READ(iphdr, protocol) != IPPROTO_UDP) {
    return 0;
  }

  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  pid_t pid = bpf_get_current_pid_tgid() >> 32;

  size_t msglen = process_udp_send(skb, &key, pid);
  if (unlikely(msglen == 0))
    return 0;

  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
  }
  key.cgroupid = get_current_cgroup_id();

  update_val(&key, msglen);

  __u16 th_off = BPF_CORE_READ(skb, transport_header);
  detect_and_cache_l7_skb(skb, (__u32)th_off + (__u32)sizeof(struct udphdr),
                          &key);

  return 0;
}

SEC("kprobe/ip6_send_skb")
int BPF_KPROBE(ip6_send_skb, struct sk_buff *skb) {
  // Use sk_protocol; ip6hdr->nexthdr would miss UDP behind ext headers.
  struct sock *sk = BPF_CORE_READ(skb, sk);
  if (!sk || BPF_CORE_READ(sk, sk_protocol) != IPPROTO_UDP) {
    return 0;
  }

  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  pid_t pid = bpf_get_current_pid_tgid() >> 32;

  size_t msglen = process_udp_send(skb, &key, pid);
  if (unlikely(msglen == 0))
    return 0;

  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
  }
  key.cgroupid = get_current_cgroup_id();

  update_val(&key, msglen);

  __u16 th_off = BPF_CORE_READ(skb, transport_header);
  detect_and_cache_l7_skb(skb, (__u32)th_off + (__u32)sizeof(struct udphdr),
                          &key);

  return 0;
}

SEC("kprobe/skb_consume_udp")
int BPF_KPROBE(skb_consume_udp, struct sock *sk, struct sk_buff *skb, int len) {
  if (unlikely(len <= 0)) {
    return 0;
  }

  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  pid_t pid = bpf_get_current_pid_tgid() >> 32;

  if (!process_udp_recv(true, skb, &key, pid, NULL))
    return 0;

  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
  }
  key.cgroupid = get_current_cgroup_id();

  update_val(&key, len);

  __u16 th_off = BPF_CORE_READ(skb, transport_header);
  detect_and_cache_l7_skb(skb, (__u32)th_off + (__u32)sizeof(struct udphdr),
                          &key);

  return 0;
}

// transport_header points at the triggering TCP/UDP, not the ICMP being
// emitted — read IPs from iphdr and take type/code from kprobe args.
SEC("kprobe/__icmp_send")
int BPF_KPROBE(__icmp_send, struct sk_buff *skb, __u8 type, __u8 code,
               __be32 info, const struct ip_options *opt) {
  struct iphdr *iphdr = (struct iphdr *)(BPF_CORE_READ(skb, head) +
                                         BPF_CORE_READ(skb, network_header));

  __u16 ihl_raw = (__u16)BPF_CORE_READ_BITFIELD_PROBED(iphdr, ihl);
  if (unlikely(ihl_raw < 5)) {
    return 0;
  }

  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  // iphdr is src=peer/dst=us; ICMP error flips that — peer→dst, us→src.
  __be32 ip4_remote = BPF_CORE_READ(iphdr, saddr);
  __be32 ip4_local = BPF_CORE_READ(iphdr, daddr);
  MAP_V4_IN_V6(key.srcip, ip4_local);
  MAP_V4_IN_V6(key.dstip, ip4_remote);

  key.proto = IPPROTO_ICMP;
  // ICMP has no ports; stash type/code in the port slots.
  key.src_port = type;
  key.dst_port = code;

  pid_t pid = bpf_get_current_pid_tgid() >> 32;
  key.pid = pid;
  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
  }
  key.cgroupid = get_current_cgroup_id();

  // RFC 792: 8B ICMP hdr + orig IP hdr + up to 8 data bytes.
  __u16 tot_len = bpf_ntohs(BPF_CORE_READ(iphdr, tot_len));
  __u16 ihl_bytes = ihl_raw * 4;
  __u16 payload = (ihl_bytes <= tot_len) ? (tot_len - ihl_bytes) : 0;
  size_t msglen =
      sizeof(struct icmphdr) + ihl_bytes + (payload > 8 ? 8 : payload);

  update_val(&key, msglen);

  return 0;
}

// See __icmp_send for the rationale on skipping process_icmp6().
SEC("kprobe/icmp6_send")
int BPF_KPROBE(icmp6_send, struct sk_buff *skb, __u8 type, __u8 code,
               __u32 info) {
  struct ipv6hdr *iphdr =
      (struct ipv6hdr *)(BPF_CORE_READ(skb, head) +
                         BPF_CORE_READ(skb, network_header));

  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  // iphdr has src=peer, dst=us; flip for the ICMPv6 error we emit.
  BPF_CORE_READ_INTO(&key.dstip, iphdr, saddr);
  BPF_CORE_READ_INTO(&key.srcip, iphdr, daddr);

  key.proto = IPPROTO_ICMPV6;
  // ICMP has no ports; stash type/code in the port slots.
  key.src_port = type;
  key.dst_port = code;

  pid_t pid = bpf_get_current_pid_tgid() >> 32;
  key.pid = pid;
  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
  }
  key.cgroupid = get_current_cgroup_id();

  // RFC 4443: 8B ICMPv6 hdr + orig packet, capped at min-MTU body (1232).
  __u16 payload_len = bpf_ntohs(BPF_CORE_READ(iphdr, payload_len));
  __u32 orig_len = (__u32)sizeof(struct ipv6hdr) + payload_len;
  __u32 max_body =
      1280U - (__u32)sizeof(struct ipv6hdr) - (__u32)sizeof(struct icmp6hdr);
  __u32 body = orig_len < max_body ? orig_len : max_body;
  size_t msglen = sizeof(struct icmp6hdr) + body;

  update_val(&key, msglen);

  return 0;
}

SEC("kprobe/icmp_rcv")
int BPF_KPROBE(icmp_rcv, struct sk_buff *skb) {
  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  pid_t pid = bpf_get_current_pid_tgid() >> 32;

  size_t msglen = process_icmp4(skb, &key, pid);
  if (unlikely(msglen == 0))
    return 0;

  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
  }
  key.cgroupid = get_current_cgroup_id();

  update_val(&key, msglen);

  return 0;
}

SEC("kprobe/icmpv6_rcv")
int BPF_KPROBE(icmpv6_rcv, struct sk_buff *skb) {
  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  pid_t pid = bpf_get_current_pid_tgid() >> 32;

  size_t msglen = process_icmp6(skb, &key, pid);
  if (unlikely(msglen == 0))
    return 0;

  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
  }
  key.cgroupid = get_current_cgroup_id();

  update_val(&key, msglen);

  return 0;
}

// ESP/AH/GRE/OSPF send (v4). Skips TCP/UDP/ICMP — those have own kprobes.
SEC("kprobe/ip_local_out")
int BPF_KPROBE(ip_local_out, struct net *net, struct sock *sk,
               struct sk_buff *skb) {
  if (unlikely(!skb)) {
    return 0;
  }

  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  pid_t pid = bpf_get_current_pid_tgid() >> 32;

  size_t msglen = process_l4_skb(skb, &key, pid);
  if (unlikely(msglen == 0)) {
    sniff_tcp_skb(skb);
    return 0;
  }

  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
  }
  key.cgroupid = get_current_cgroup_id();

  update_val(&key, msglen);

  return 0;
}

// ESP/AH/GRE/OSPF send path (v6).
SEC("kprobe/ip6_local_out")
int BPF_KPROBE(ip6_local_out, struct net *net, struct sock *sk,
               struct sk_buff *skb) {
  if (unlikely(!skb)) {
    return 0;
  }

  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  pid_t pid = bpf_get_current_pid_tgid() >> 32;

  size_t msglen = process_l4_skb(skb, &key, pid);
  if (unlikely(msglen == 0)) {
    sniff_tcp_skb(skb);
    return 0;
  }

  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
  }
  key.cgroupid = get_current_cgroup_id();

  update_val(&key, msglen);

  return 0;
}

// ESP/AH/GRE/OSPF recv (v4). Pre-routing: counts transit on routers.
// PID/comm typically 0/swapper (softirq context).
SEC("kprobe/ip_rcv")
int BPF_KPROBE(ip_rcv, struct sk_buff *skb, struct net_device *dev,
               struct packet_type *pt, struct net_device *orig_dev) {
  if (unlikely(!skb)) {
    return 0;
  }

  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  pid_t pid = bpf_get_current_pid_tgid() >> 32;

  size_t msglen = process_l4_skb(skb, &key, pid);
  if (unlikely(msglen == 0)) {
    sniff_tcp_skb(skb);
    return 0;
  }

  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
  }
  key.cgroupid = get_current_cgroup_id();

  update_val(&key, msglen);

  return 0;
}

// ESP/AH/GRE/OSPF receive path (v6).
SEC("kprobe/ipv6_rcv")
int BPF_KPROBE(ipv6_rcv, struct sk_buff *skb, struct net_device *dev,
               struct packet_type *pt, struct net_device *orig_dev) {
  if (unlikely(!skb)) {
    return 0;
  }

  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  pid_t pid = bpf_get_current_pid_tgid() >> 32;

  size_t msglen = process_l4_skb(skb, &key, pid);
  if (unlikely(msglen == 0)) {
    sniff_tcp_skb(skb);
    return 0;
  }

  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
  }
  key.cgroupid = get_current_cgroup_id();

  update_val(&key, msglen);

  return 0;
}

// TCP retransmissions counted under synthetic proto 253 (PROTO_TCP_RETX) so
// they appear as their own flow rows without colliding with regular TCP.
SEC("kprobe/tcp_retransmit_skb")
int BPF_KPROBE(tcp_retransmit_skb, struct sock *sk, struct sk_buff *skb) {
  if (unlikely(!sk || !skb)) {
    return 0;
  }

  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  pid_t pid = bpf_get_current_pid_tgid() >> 32;

  if (!process_tcp(false, sk, &key, pid)) {
    return 0;
  }
  key.proto = PROTO_TCP_RETX;

  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
  }
  key.cgroupid = get_current_cgroup_id();

  __u32 skb_len = BPF_CORE_READ(skb, len);
  update_val(&key, skb_len);

  return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
