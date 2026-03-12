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

/**
 * Hook function for kprobe on tcp_sendmsg function.
 *
 * Populates the statkey structure with information from the TCP packet and
 * the process ID associated with the packet, and updates the packet and byte
 * counters in the packet count map.
 *
 * @param sk pointer to the socket structure
 * @param msg pointer to the msghdr structure
 * @param size size of the packet to be counted
 *
 * @return 0
 *
 * @throws none
 */
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  pid_t pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
  }

  key.cgroupid = get_current_cgroup_id();

  if (!process_tcp(false, sk, &key, pid))
    return 0;
  update_val(&key, size);

  return 0;
}

/**
 * Hook function for kprobe on tcp_cleanup_rbuf function.
 *
 * Populates the statkey structure with information from the socket and the
 * process ID associated with the socket, and updates the packet and byte
 * counters in the packet count map.
 *
 * @param sk pointer to the socket structure
 * @param copied size of the packet to be counted
 *
 * @return 0
 *
 * @throws none
 */
SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(tcp_cleanup_rbuf, struct sock *sk, int copied) {
  if (copied <= 0) {
    return 0;
  }

  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  pid_t pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
  }

  key.cgroupid = get_current_cgroup_id();

  if (!process_tcp(true, sk, &key, pid))
    return 0;
  update_val(&key, copied);

  return 0;
}

/**
 * Hook function for kprobe on ip_send_skb function.
 *
 * Populates the statkey structure with information from the socket and the
 * process ID associated with the socket, and updates the packet and byte
 * counters in the packet count map.
 *
 * @param net pointer to the network namespace structure
 * @param skb pointer to the socket buffer
 *
 * @return 0
 *
 * @throws none
 */
SEC("kprobe/ip_send_skb")
int BPF_KPROBE(ip_send_skb, struct net *net, struct sk_buff *skb) {
  struct iphdr *iphdr = (struct iphdr *)(BPF_CORE_READ(skb, head) +
                                         BPF_CORE_READ(skb, network_header));
  if (BPF_CORE_READ(iphdr, protocol) != IPPROTO_UDP) {
    return 0;
  }

  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  pid_t pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
  }

  key.cgroupid = get_current_cgroup_id();

  size_t msglen = process_udp_send(skb, &key, pid);
  if (msglen > 0)
    update_val(&key, msglen);

  return 0;
}

/**
 * Hook function for kprobe on ip6_send_skb function.
 *
 * Populates the statkey structure with information from the socket and the
 * process ID associated with the socket, and updates the packet and byte
 * counters in the packet count map.
 *
 * @param skb pointer to the socket buffer
 *
 * @return 0
 *
 * @throws none
 */
SEC("kprobe/ip6_send_skb")
int BPF_KPROBE(ip6_send_skb, struct sk_buff *skb) {
  // Use sk_protocol from the socket rather than ip6hdr->nexthdr so that
  // IPv6 packets with extension headers (where nexthdr != IPPROTO_UDP) are
  // still accounted for correctly.
  struct sock *sk = BPF_CORE_READ(skb, sk);
  if (!sk || BPF_CORE_READ(sk, sk_protocol) != IPPROTO_UDP) {
    return 0;
  }

  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  pid_t pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
  }

  key.cgroupid = get_current_cgroup_id();

  size_t msglen = process_udp_send(skb, &key, pid);
  if (msglen > 0)
    update_val(&key, msglen);

  return 0;
}

/**
 * Hook function for kprobe on skb_consume_udp function.
 *
 * Populates the statkey structure with information from the UDP packet and
 * the process ID associated with the packet, and updates the packet and byte
 * counters in the packet count map.
 *
 * @param sk pointer to the socket structure
 * @param skb pointer to the socket buffer containing the UDP packet
 * @param len length of the UDP message
 *
 * @return 0
 *
 * @throws none
 */
SEC("kprobe/skb_consume_udp")
int BPF_KPROBE(skb_consume_udp, struct sock *sk, struct sk_buff *skb, int len) {
  if (len <= 0) {
    return 0;
  }

  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  pid_t pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
  }

  key.cgroupid = get_current_cgroup_id();

  if (!process_udp_recv(true, skb, &key, pid))
    return 0;
  update_val(&key, len);

  return 0;
}

/**
 * Hook function for kprobe on __icmp_send function.
 *
 * Populates the statkey structure with information from the ICMPv4 packet and
 * the process ID associated with the packet, and updates the packet and byte
 * counters in the packet count map.
 *
 * @param skb pointer to the socket buffer containing the ICMPv4 packet
 * @param type type of ICMPv4 packet
 * @param code code of ICMPv4 packet
 * @param info additional information for the ICMPv4 packet
 * @param opt pointer to the ip_options structure
 *
 * @return 0
 *
 * @throws none
 */
SEC("kprobe/__icmp_send")
int BPF_KPROBE(__icmp_send, struct sk_buff *skb, __u8 type, __u8 code,
               __be32 info, const struct ip_options *opt) {
  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  pid_t pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
  }

  key.cgroupid = get_current_cgroup_id();

  /* Extract src/dst IPs directly from the triggering packet's IP header.
   * process_icmp4() cannot be used here: the skb's transport_header points to
   * the triggering transport layer (TCP/UDP), not an ICMP header, so calling
   * it would read garbage type/code that we would then have to overwrite. */
  struct iphdr *iphdr = (struct iphdr *)(BPF_CORE_READ(skb, head) +
                                         BPF_CORE_READ(skb, network_header));

  __be32 ip4_src = BPF_CORE_READ(iphdr, saddr);
  __builtin_memcpy(key.srcip.s6_addr, ip4in6, sizeof(ip4in6));
  __builtin_memcpy(key.srcip.s6_addr + sizeof(ip4in6), &ip4_src,
                   sizeof(ip4_src));

  __be32 ip4_dst = BPF_CORE_READ(iphdr, daddr);
  __builtin_memcpy(key.dstip.s6_addr, ip4in6, sizeof(ip4in6));
  __builtin_memcpy(key.dstip.s6_addr + sizeof(ip4in6), &ip4_dst,
                   sizeof(ip4_dst));

  key.proto = IPPROTO_ICMP;
  key.pid = pid;

  /* __icmp_send is called with the triggering packet's skb, so src/dst IPs
   * come from the original packet (src=sender, dst=us). Swap them to reflect
   * the actual ICMP error direction (src=us, dst=original sender).
   * Use kprobe arguments directly for type/code. */
  struct in6_addr tmp_ip = key.srcip;
  key.srcip = key.dstip;
  key.dstip = tmp_ip;
  key.src_port = type;
  key.dst_port = code;

  /* Compute the actual ICMP error response size per RFC 792 / RFC 1812:
   * 8-byte ICMP header + original IP header + first 8 bytes of original data.
   * Validate ihl >= 5 (minimum 20-byte header) before using it. */
  __u16 tot_len = bpf_ntohs(BPF_CORE_READ(iphdr, tot_len));
  __u16 ihl_raw = (__u16)BPF_CORE_READ_BITFIELD_PROBED(iphdr, ihl);
  if (ihl_raw < 5) {
    return 0;
  }
  __u16 ihl_bytes = ihl_raw * 4;
  __u16 payload = (ihl_bytes <= tot_len) ? (tot_len - ihl_bytes) : 0;
  size_t msglen =
      sizeof(struct icmphdr) + ihl_bytes + (payload > 8 ? 8 : payload);

  update_val(&key, msglen);

  return 0;
}

/**
 * Hook function for kprobe on icmp6_send function.
 *
 * Populates the statkey structure with information from the ICMPv6 packet and
 * the process ID associated with the packet, and updates the packet and byte
 * counters in the packet count map.
 *
 * @param skb pointer to the socket buffer containing the ICMPv6 packet
 * @param type type of ICMPv6 packet
 * @param code code of ICMPv6 packet
 * @param info additional information for the ICMPv6 packet
 *
 * @return 0
 *
 * @throws none
 */
SEC("kprobe/icmp6_send")
int BPF_KPROBE(icmp6_send, struct sk_buff *skb, __u8 type, __u8 code,
               __u32 info) {
  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  pid_t pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
  }

  key.cgroupid = get_current_cgroup_id();

  /* Extract src/dst IPs directly from the triggering packet's IPv6 header.
   * process_icmp6() cannot be used here: the skb's transport_header points to
   * the triggering transport layer (TCP/UDP), not an ICMPv6 header, so calling
   * it would read garbage type/code that we would then have to overwrite. */
  struct ipv6hdr *iphdr =
      (struct ipv6hdr *)(BPF_CORE_READ(skb, head) +
                         BPF_CORE_READ(skb, network_header));

  BPF_CORE_READ_INTO(&key.srcip, iphdr, saddr);
  BPF_CORE_READ_INTO(&key.dstip, iphdr, daddr);

  key.proto = IPPROTO_ICMPV6;
  key.pid = pid;

  /* icmp6_send is called with the triggering packet's skb, so src/dst IPs
   * come from the original packet (src=sender, dst=us). Swap them to reflect
   * the actual ICMPv6 error direction (src=us, dst=original sender).
   * Use kprobe arguments directly for type/code. */
  struct in6_addr tmp_ip = key.srcip;
  key.srcip = key.dstip;
  key.dstip = tmp_ip;
  key.src_port = type;
  key.dst_port = code;

  /* Compute the ICMPv6 error response size per RFC 4443 section 2.4:
   * 8-byte ICMPv6 header + as much of the original IPv6 packet as fits within
   * the minimum IPv6 MTU (1280 bytes). Max includable body:
   * 1280 - 40 (outer IPv6 header) - 8 (ICMPv6 header) = 1232 bytes. */
  __u16 payload_len = bpf_ntohs(BPF_CORE_READ(iphdr, payload_len));
  __u32 orig_len = (__u32)sizeof(struct ipv6hdr) + payload_len;
  __u32 max_body =
      1280U - (__u32)sizeof(struct ipv6hdr) - (__u32)sizeof(struct icmp6hdr);
  __u32 body = orig_len < max_body ? orig_len : max_body;
  size_t msglen = sizeof(struct icmp6hdr) + body;

  update_val(&key, msglen);

  return 0;
}

/**
 * Hook function for kprobe on icmp_rcv function.
 *
 * Populates the statkey structure with information from the ICMP packet and
 * the process ID associated with the packet, and updates the packet and byte
 * counters in the packet count map.
 *
 * @param skb pointer to the socket buffer containing the ICMP packet
 *
 * @return 0
 *
 * @throws none
 */
SEC("kprobe/icmp_rcv")
int BPF_KPROBE(icmp_rcv, struct sk_buff *skb) {
  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  pid_t pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
  }

  key.cgroupid = get_current_cgroup_id();

  size_t msglen = process_icmp4(skb, &key, pid);
  if (msglen > 0)
    update_val(&key, msglen);

  return 0;
}

/**
 * Hook function for kprobe on icmpv6_rcv function.
 *
 * Populates the statkey structure with information from the ICMPv6 packet and
 * the process ID associated with the packet, and updates the packet and byte
 * counters in the packet count map.
 *
 * @param skb pointer to the socket buffer containing the ICMPv6 packet
 *
 * @return 0
 *
 * @throws none
 */
SEC("kprobe/icmpv6_rcv")
int BPF_KPROBE(icmpv6_rcv, struct sk_buff *skb) {
  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  pid_t pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
  }

  key.cgroupid = get_current_cgroup_id();

  size_t msglen = process_icmp6(skb, &key, pid);
  if (msglen > 0)
    update_val(&key, msglen);

  return 0;
}

#if 0
/**
 * Hook function for kprobe on raw_sendmsg function.
 *
 * Populates the statkey structure with information from the raw IPv4 packet and
 * the process ID associated with the packet, and updates the packet and byte
 * counters in the packet count map.
 *
 * @param sk pointer to the socket structure
 * @param msg pointer to the msghdr structure
 * @param len size of the message
 *
 * @return 0
 *
 * @throws none
 */
SEC("kprobe/raw_sendmsg")
int BPF_KPROBE(raw_sendmsg, struct sock *sk, struct msghdr *msg, size_t len) {
  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  pid_t pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

  if (!process_raw_sendmsg4(sk, msg, &key, pid))
    return 0;
  update_val(&key, len);

  return 0;
}
#endif

#if 0
/**
 * Hook function for kprobe on rawv6_sendmsg function.
 *
 * Populates the statkey structure with information from the raw IPv6 packet and
 * the process ID associated with the packet, and updates the packet and byte
 * counters in the packet count map.
 *
 * @param sk pointer to the socket structure
 * @param msg pointer to the msghdr structure
 * @param len size of the message
 *
 * @return 0
 *
 * @throws none
 */
SEC("kprobe/rawv6_sendmsg")
int BPF_KPROBE(rawv6_sendmsg, struct sock *sk, struct msghdr *msg, size_t len) {
  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  pid_t pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

  if (!process_raw_sendmsg6(sk, msg, &key, pid))
    return 0;
  update_val(&key, len);

  return 0;
}
#endif

char __license[] SEC("license") = "Dual MIT/GPL";
