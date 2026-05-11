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

// kprobes have no skb-derived cgroup helper; need the task-walk fallback.
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

  return 0;
}

// __icmp_send fires with the triggering packet's skb, whose transport_header
// points at the original TCP/UDP, not at the ICMP we're emitting. Read IPs
// directly from the iphdr and use the kprobe args for type/code.
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

  // iphdr has src=peer, dst=us. The ICMP error we emit flips that, so
  // write peer into dstip and us into srcip directly.
  __be32 ip4_remote = BPF_CORE_READ(iphdr, saddr);
  __be32 ip4_local = BPF_CORE_READ(iphdr, daddr);

  __builtin_memcpy(key.srcip.s6_addr, ip4in6, sizeof(ip4in6));
  __builtin_memcpy(key.srcip.s6_addr + sizeof(ip4in6), &ip4_local,
                   sizeof(ip4_local));

  __builtin_memcpy(key.dstip.s6_addr, ip4in6, sizeof(ip4in6));
  __builtin_memcpy(key.dstip.s6_addr + sizeof(ip4in6), &ip4_remote,
                   sizeof(ip4_remote));

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

  // RFC 792 / 1812: 8-byte ICMP header + orig IP header + up to 8 data bytes.
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

  // RFC 4443 §2.4: 8-byte ICMPv6 header + as much orig packet as fits in
  // the minimum IPv6 MTU (1280 - 40 - 8 = 1232 max body bytes).
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

// Raw-socket ICMP hooks: kept disabled but compileable for future reuse.
#if 0
SEC("kprobe/raw_sendmsg")
int BPF_KPROBE(raw_sendmsg, struct sock *sk, struct msghdr *msg, size_t len) {
  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  pid_t pid = bpf_get_current_pid_tgid() >> 32;

  if (!process_raw_sendmsg4(sk, msg, &key, pid))
    return 0;
  update_val(&key, len);

  return 0;
}
#endif

#if 0
SEC("kprobe/rawv6_sendmsg")
int BPF_KPROBE(rawv6_sendmsg, struct sock *sk, struct msghdr *msg, size_t len) {
  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  pid_t pid = bpf_get_current_pid_tgid() >> 32;

  if (!process_raw_sendmsg6(sk, msg, &key, pid))
    return 0;
  update_val(&key, len);

  return 0;
}
#endif

char __license[] SEC("license") = "Dual MIT/GPL";
