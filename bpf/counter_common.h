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

#pragma once

#include "cgroup.h"
#include "counter.h"

typedef struct statkey_t {
  struct in6_addr srcip;
  struct in6_addr dstip;
  __u64 cgroupid;
  char comm[TASK_COMM_LEN];
  pid_t pid;
  __u16 src_port;
  __u16 dst_port;
  __u8 proto;
} statkey;

typedef struct statvalue_t {
  __u64 packets;
  __u64 bytes;
} statvalue;

// Per-CPU slots avoid cross-CPU atomic contention; userspace sums on read.
struct {
  __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, statkey);
  __type(value, statvalue);
} pkt_count SEC(".maps");

typedef struct sockinfo_t {
  __u8 comm[TASK_COMM_LEN];
  pid_t pid;
} sockinfo;

// Patched at load time; verifier folds the v1/v2 branch.
#ifdef PKTSTAT_NEEDS_CGROUP_HELPERS
volatile const __u64 cgrpfs_magic = 0;
#endif

// V4MAPPED prefix: ::ffff:a.b.c.d
static const __u8 ip4in6[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

// Map an IPv4 __be32 into the v4-in-v6 layout of an in6_addr.
#define MAP_V4_IN_V6(v6, v4be32)                                               \
  do {                                                                         \
    __builtin_memcpy((v6).s6_addr, ip4in6, sizeof(ip4in6));                    \
    __builtin_memcpy((v6).s6_addr + sizeof(ip4in6), &(v4be32),                 \
                     sizeof(v4be32));                                          \
  } while (0)

// Switch-case helper for ESP/AH/GRE/OSPF parsers in process_ip4/process_ip6.
#define CASE_PARSE(proto, parser)                                              \
  case proto: {                                                                \
    if ((parser)(transport, data_end, key) != OK) {                            \
      return NOK;                                                              \
    }                                                                          \
    break;                                                                     \
  }

// Runtime ARP toggle for process_eth. Patched via cilium/ebpf Variables
// before load; verifier folds the dispatch away when zero.
volatile const __u8 arp_enabled = 1;

// ESP: 32-bit SPI split across src_port (high 16) / dst_port (low 16).
static inline __attribute__((always_inline)) int
parse_esp(void *transport, void *data_end, statkey *key) {
  if (unlikely(transport + 8 > data_end)) {
    return NOK;
  }
  __u32 spi = bpf_ntohl(*(__be32 *)transport);
  key->src_port = (__u16)(spi >> 16);
  key->dst_port = (__u16)(spi & 0xFFFF);
  return OK;
}

// AH: SPI at offset 4. Same port-slot split as ESP.
static inline __attribute__((always_inline)) int
parse_ah(void *transport, void *data_end, statkey *key) {
  if (unlikely(transport + 12 > data_end)) {
    return NOK;
  }
  __u32 spi = bpf_ntohl(*(__be32 *)(transport + 4));
  key->src_port = (__u16)(spi >> 16);
  key->dst_port = (__u16)(spi & 0xFFFF);
  return OK;
}

// GRE base header only: src_port=inner-proto, dst_port=flags.
static inline __attribute__((always_inline)) int
parse_gre(void *transport, void *data_end, statkey *key) {
  if (unlikely(transport + 4 > data_end)) {
    return NOK;
  }
  __be16 flags = *(__be16 *)transport;
  __be16 proto = *(__be16 *)(transport + 2);
  key->src_port = bpf_ntohs(proto);
  key->dst_port = bpf_ntohs(flags);
  return OK;
}

// OSPF: src_port=type (1=Hello..5=LSAck), dst_port=version (2 or 3).
static inline __attribute__((always_inline)) int
parse_ospf(void *transport, void *data_end, statkey *key) {
  if (unlikely(transport + 2 > data_end)) {
    return NOK;
  }
  __u8 *o = transport;
  key->src_port = o[1];
  key->dst_port = o[0];
  return OK;
}

// ARP IPv4-over-Ethernet only. SPA→srcip, TPA→dstip, src_port=opcode.
// Inverse ARP (op 8/9), RARP (EtherType 0x8035), and InfiniBand ARP
// (htype=32) are intentionally excluded — out of scope.
// SPA/TPA loads use __builtin_memcpy: unaligned offsets inside the payload.
static inline __attribute__((always_inline)) bool
parse_arp(void *l3, void *data_end, statkey *key) {
  struct arphdr *arp = l3;
  if (unlikely((void *)arp + sizeof(*arp) > data_end)) {
    return false;
  }

  if (bpf_ntohs(arp->ar_hrd) != 1) return false;
  if (bpf_ntohs(arp->ar_pro) != ETH_P_IP) return false;
  if (arp->ar_hln != 6 || arp->ar_pln != 4) return false;

  // Payload: sha[6] spa[4] tha[6] tpa[4] = 20 bytes.
  void *payload = (void *)arp + sizeof(*arp);
  if (unlikely(payload + 20 > data_end)) {
    return false;
  }

  __be32 spa, tpa;
  __builtin_memcpy(&spa, payload + 6,  4);
  __builtin_memcpy(&tpa, payload + 16, 4);

  __builtin_memset(key, 0, sizeof(*key));
  MAP_V4_IN_V6(key->srcip, spa);
  MAP_V4_IN_V6(key->dstip, tpa);

  key->proto    = PROTO_ARP_FAKE;
  key->src_port = bpf_ntohs(arp->ar_op);
  key->dst_port = 0;
  return true;
}

static inline __attribute__((always_inline)) int
process_ip4(struct iphdr *ip4, void *data_end, statkey *key) {
  if (unlikely((void *)ip4 + sizeof(*ip4) > data_end)) {
    return NOK;
  }

  // ihl: header length in 32-bit words; <5 is malformed.
  __u8 ihl = ip4->ihl;
  if (unlikely(ihl < 5)) {
    return NOK;
  }
  __u32 ip4_hdr_len = (__u32)ihl * 4;

  if (unlikely((void *)ip4 + ip4_hdr_len > data_end)) {
    return NOK;
  }

  void *transport = (void *)ip4 + ip4_hdr_len;

  MAP_V4_IN_V6(key->srcip, ip4->saddr);
  MAP_V4_IN_V6(key->dstip, ip4->daddr);

  key->proto = ip4->protocol;

  switch (ip4->protocol) {
  case IPPROTO_TCP: {
    struct tcphdr *tcp = transport;
    if (unlikely((void *)tcp + sizeof(*tcp) > data_end)) {
      return NOK;
    }
    key->src_port = bpf_ntohs(tcp->source);
    key->dst_port = bpf_ntohs(tcp->dest);
    break;
  }
  case IPPROTO_UDP: {
    struct udphdr *udp = transport;
    if (unlikely((void *)udp + sizeof(*udp) > data_end)) {
      return NOK;
    }
    key->src_port = bpf_ntohs(udp->source);
    key->dst_port = bpf_ntohs(udp->dest);
    break;
  }
  case IPPROTO_ICMP: {
    struct icmphdr *icmp = transport;
    if (unlikely((void *)icmp + sizeof(*icmp) > data_end)) {
      return NOK;
    }
    // ICMP has no ports; stash type/code in the port slots.
    key->src_port = icmp->type;
    key->dst_port = icmp->code;
    break;
  }
    CASE_PARSE(IPPROTO_ESP, parse_esp)
    CASE_PARSE(IPPROTO_AH, parse_ah)
    CASE_PARSE(IPPROTO_GRE, parse_gre)
    CASE_PARSE(IPPROTO_OSPF, parse_ospf)
  }

  return OK;
}

static inline __attribute__((always_inline)) int
process_ip6(struct ipv6hdr *ip6, void *data_end, statkey *key) {
  if (unlikely((void *)ip6 + sizeof(*ip6) > data_end)) {
    return NOK;
  }

  key->srcip = ip6->saddr;
  key->dstip = ip6->daddr;

  // Ext-header sizes: HopByHop/Routing/DstOpts = (hdr_ext_len+1)*8, Fragment = 8.
  __u8 nexthdr = ip6->nexthdr;
  void *transport = (void *)ip6 + sizeof(*ip6);

  // Cap at 2: deeper chains attribute to the last ext header (intentional).
#pragma unroll 2
  for (int i = 0; i < 2; i++) {
    if (likely(nexthdr != IPPROTO_HOPOPTS && nexthdr != IPPROTO_ROUTING &&
               nexthdr != IPPROTO_FRAGMENT && nexthdr != IPPROTO_DSTOPTS)) {
      break;
    }
    if (nexthdr == IPPROTO_FRAGMENT) {
      if (unlikely(transport + 8 > data_end))
        return NOK;
      nexthdr = ((__u8 *)transport)[0];
      transport += 8;
    } else {
      if (unlikely(transport + 2 > data_end))
        return NOK;
      nexthdr = ((__u8 *)transport)[0];
      __u8 hdrlen = ((__u8 *)transport)[1];
      transport += ((__u32)(hdrlen + 1) * 8);
    }
  }

  key->proto = nexthdr;

  switch (nexthdr) {
  case IPPROTO_TCP: {
    struct tcphdr *tcp = transport;
    if (unlikely((void *)tcp + sizeof(*tcp) > data_end)) {
      return NOK;
    }
    key->src_port = bpf_ntohs(tcp->source);
    key->dst_port = bpf_ntohs(tcp->dest);
    break;
  }
  case IPPROTO_UDP: {
    struct udphdr *udp = transport;
    if (unlikely((void *)udp + sizeof(*udp) > data_end)) {
      return NOK;
    }
    key->src_port = bpf_ntohs(udp->source);
    key->dst_port = bpf_ntohs(udp->dest);
    break;
  }
  case IPPROTO_ICMPV6: {
    struct icmp6hdr *icmp = transport;
    if (unlikely((void *)icmp + sizeof(*icmp) > data_end)) {
      return NOK;
    }
    // ICMP has no ports; stash type/code in the port slots.
    key->src_port = icmp->icmp6_type;
    key->dst_port = icmp->icmp6_code;
    break;
  }
    CASE_PARSE(IPPROTO_ESP, parse_esp)
    CASE_PARSE(IPPROTO_AH, parse_ah)
    CASE_PARSE(IPPROTO_GRE, parse_gre)
    CASE_PARSE(IPPROTO_OSPF, parse_ospf)
  }

  return OK;
}

static inline __attribute__((always_inline)) void update_val(statkey *key,
                                                             size_t size) {
  // LRU_PERCPU_HASH: `val` is this CPU's slot. Plain stores are race-free.
  statvalue *val = (statvalue *)bpf_map_lookup_elem(&pkt_count, key);
  if (likely(val)) {
    val->packets += 1;
    val->bytes += size;
    return;
  }

  // BPF_NOEXIST race: losing inserter sees its own zeroed per-CPU slot,
  // retry += gives correct sums after userspace aggregation.
  statvalue initval = {.packets = 1, .bytes = size};
  if (unlikely(bpf_map_update_elem(&pkt_count, key, &initval, BPF_NOEXIST) !=
               0)) {
    val = (statvalue *)bpf_map_lookup_elem(&pkt_count, key);
    if (val) {
      val->packets += 1;
      val->bytes += size;
    }
  }
}

static inline __attribute__((always_inline)) bool
process_l3(void *l3, void *data_end, __u16 proto_host, statkey *key) {
  // Skip the memset for non-IP traffic.
  if (proto_host != ETH_P_IP && proto_host != ETH_P_IPV6) {
    return false;
  }

  __builtin_memset(key, 0, sizeof(*key));

  if (proto_host == ETH_P_IP) {
    return process_ip4((struct iphdr *)l3, data_end, key) == OK;
  }
  return process_ip6((struct ipv6hdr *)l3, data_end, key) == OK;
}

static inline __attribute__((always_inline)) void
process_eth(void *data, void *data_end, __u64 pkt_len) {
  struct ethhdr *eth = data;

  if (unlikely((void *)eth + sizeof(*eth) > data_end)) {
    return;
  }

  __u16 h_proto = bpf_ntohs(eth->h_proto);
  void *l3 = (void *)eth + sizeof(*eth);

  // Unwrap up to two VLAN tags (802.1Q or QinQ). vlan_hdr is 4 bytes:
  // (tci:16, encapsulated_proto:16); the encapsulated_proto replaces h_proto.
#pragma unroll 2
  for (int i = 0; i < 2; i++) {
    if (h_proto != ETH_P_8021Q && h_proto != ETH_P_8021AD) {
      break;
    }
    if (unlikely(l3 + 4 > data_end)) {
      return;
    }
    h_proto = bpf_ntohs(*(__be16 *)(l3 + 2));
    l3 += 4;
  }

  // ARP is L2-only; parse_arp zeroes the key itself.
  if (arp_enabled && h_proto == ETH_P_ARP) {
    statkey key;
    if (parse_arp(l3, data_end, &key)) {
      update_val(&key, pkt_len);
    }
    return;
  }

  statkey key;
  if (!process_l3(l3, data_end, h_proto, &key)) {
    return;
  }

  update_val(&key, pkt_len);
}

static inline __attribute__((always_inline)) void
tc_process_packet(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  process_eth(data, data_end, skb->len);
}

static inline __attribute__((always_inline)) void
xdp_process_packet(struct xdp_md *xdp) {
  void *data = (void *)(long)xdp->data;
  void *data_end = (void *)(long)xdp->data_end;

  process_eth(data, data_end, bpf_xdp_get_buff_len(xdp));
}

static inline __attribute__((always_inline)) bool
process_tcp(bool receive, struct sock *sk, statkey *key, pid_t pid) {
  __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);

  // sk holds local in skc_(rcv_)saddr/skc_num, remote in skc_daddr/dport.
  // Receive-direction flips local→dst / remote→src up-front.
  struct in6_addr *src = receive ? &key->dstip : &key->srcip;
  struct in6_addr *dst = receive ? &key->srcip : &key->dstip;

  switch (family) {
  case AF_INET: {
    __be32 ip4_local = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    __be32 ip4_remote = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    MAP_V4_IN_V6(*src, ip4_local);
    MAP_V4_IN_V6(*dst, ip4_remote);
    break;
  }
  case AF_INET6:
    BPF_CORE_READ_INTO(src, sk, __sk_common.skc_v6_rcv_saddr);
    BPF_CORE_READ_INTO(dst, sk, __sk_common.skc_v6_daddr);
    break;
  default:
    return false;
  }

  __u16 local_port = BPF_CORE_READ(sk, __sk_common.skc_num);
  if (unlikely(local_port == 0)) {
    // Unbound sockets keep the source port in inet_sport (network order).
    struct inet_sock *isk = (struct inet_sock *)sk;
    local_port = bpf_ntohs(BPF_CORE_READ(isk, inet_sport));
  }
  __u16 remote_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

  if (receive) {
    key->src_port = remote_port;
    key->dst_port = local_port;
  } else {
    key->src_port = local_port;
    key->dst_port = remote_port;
  }

  key->proto = IPPROTO_TCP;
  key->pid = pid;

  return true;
}

// On success, publishes the parsed udphdr via udphdr_out (NULL to skip).
static inline __attribute__((always_inline)) bool
process_udp_recv(bool receive, struct sk_buff *skb, statkey *key, pid_t pid,
                 struct udphdr **udphdr_out) {
  // Cache the CO-RE chain: the compiler can't CSE across the relocation.
  unsigned char *head = (unsigned char *)BPF_CORE_READ(skb, head);
  __u16 nh_off = BPF_CORE_READ(skb, network_header);
  __u16 th_off = BPF_CORE_READ(skb, transport_header);

  struct udphdr *udphdr = (struct udphdr *)(head + th_off);

  __u16 proto = BPF_CORE_READ(skb, protocol);

  // Packet IP header holds src=sender, dst=us; flip for the send direction.
  struct in6_addr *ip_src = receive ? &key->srcip : &key->dstip;
  struct in6_addr *ip_dst = receive ? &key->dstip : &key->srcip;

  switch (bpf_ntohs(proto)) {
  case ETH_P_IP: {
    struct iphdr *iphdr = (struct iphdr *)(head + nh_off);
    __be32 ip4_pkt_src = BPF_CORE_READ(iphdr, saddr);
    __be32 ip4_pkt_dst = BPF_CORE_READ(iphdr, daddr);
    MAP_V4_IN_V6(*ip_src, ip4_pkt_src);
    MAP_V4_IN_V6(*ip_dst, ip4_pkt_dst);
    break;
  }
  case ETH_P_IPV6: {
    struct ipv6hdr *iphdr = (struct ipv6hdr *)(head + nh_off);
    BPF_CORE_READ_INTO(ip_src, iphdr, saddr);
    BPF_CORE_READ_INTO(ip_dst, iphdr, daddr);
    break;
  }
  default:
    return false;
  }

  __u16 pkt_src_port = bpf_ntohs(BPF_CORE_READ(udphdr, source));
  __u16 pkt_dst_port = bpf_ntohs(BPF_CORE_READ(udphdr, dest));

  if (receive) {
    key->src_port = pkt_src_port;
    key->dst_port = pkt_dst_port;
  } else {
    key->src_port = pkt_dst_port;
    key->dst_port = pkt_src_port;
  }

  key->proto = IPPROTO_UDP;
  key->pid = pid;

  // Publish only on success so failures leave caller's pointer untouched.
  if (udphdr_out)
    *udphdr_out = udphdr;

  return true;
}

// Returns the IP-payload length (0 if header math fails sanity).
static inline __attribute__((always_inline)) size_t
process_icmp4(struct sk_buff *skb, statkey *key, pid_t pid) {
  unsigned char *head = (unsigned char *)BPF_CORE_READ(skb, head);
  __u16 nh_off = BPF_CORE_READ(skb, network_header);
  __u16 th_off = BPF_CORE_READ(skb, transport_header);

  struct icmphdr *icmphdr = (struct icmphdr *)(head + th_off);
  struct iphdr *iphdr = (struct iphdr *)(head + nh_off);

  __be32 ip4_src = BPF_CORE_READ(iphdr, saddr);
  __be32 ip4_dst = BPF_CORE_READ(iphdr, daddr);
  MAP_V4_IN_V6(key->srcip, ip4_src);
  MAP_V4_IN_V6(key->dstip, ip4_dst);

  // ICMP has no ports; stash type/code in the port slots.
  key->src_port = BPF_CORE_READ(icmphdr, type);
  key->dst_port = BPF_CORE_READ(icmphdr, code);

  key->proto = IPPROTO_ICMP;
  key->pid = pid;

  __u16 tot_len = bpf_ntohs(BPF_CORE_READ(iphdr, tot_len));
  __u16 ihl_bytes = (__u16)(BPF_CORE_READ_BITFIELD_PROBED(iphdr, ihl) * 4);
  size_t msglen = (ihl_bytes <= tot_len) ? (tot_len - ihl_bytes) : 0;

  return msglen;
}

// Returns the ICMPv6 payload length (IPv6 payload_len field).
static inline __attribute__((always_inline)) size_t
process_icmp6(struct sk_buff *skb, statkey *key, pid_t pid) {
  unsigned char *head = (unsigned char *)BPF_CORE_READ(skb, head);
  __u16 nh_off = BPF_CORE_READ(skb, network_header);
  __u16 th_off = BPF_CORE_READ(skb, transport_header);

  struct icmp6hdr *icmphdr = (struct icmp6hdr *)(head + th_off);
  struct ipv6hdr *iphdr = (struct ipv6hdr *)(head + nh_off);

  BPF_CORE_READ_INTO(&key->srcip, iphdr, saddr);
  BPF_CORE_READ_INTO(&key->dstip, iphdr, daddr);

  // ICMP has no ports; stash type/code in the port slots.
  key->src_port = BPF_CORE_READ(icmphdr, icmp6_type);
  key->dst_port = BPF_CORE_READ(icmphdr, icmp6_code);

  key->proto = IPPROTO_ICMPV6;
  key->pid = pid;

  return bpf_ntohs(BPF_CORE_READ(iphdr, payload_len));
}

// Fill `key` from an skb for ESP/AH/GRE/OSPF; returns 0 to skip everything else
// (TCP/UDP/ICMP have their own kprobes — counting here would double-count).
//
// __noinline: inlining tripped "R3 !read_ok" in the verifier on kernel 6.12.
static __attribute__((noinline)) size_t
process_l4_skb(struct sk_buff *skb, statkey *key, pid_t pid) {
  unsigned char *head = (unsigned char *)BPF_CORE_READ(skb, head);
  __u16 nh_off = BPF_CORE_READ(skb, network_header);
  __u16 proto_be = BPF_CORE_READ(skb, protocol);

  __u8 ip_proto;
  size_t ip_payload_len;

  switch (bpf_ntohs(proto_be)) {
  case ETH_P_IP: {
    struct iphdr *iphdr = (struct iphdr *)(head + nh_off);
    ip_proto = BPF_CORE_READ(iphdr, protocol);

    if (ip_proto != IPPROTO_ESP && ip_proto != IPPROTO_AH &&
        ip_proto != IPPROTO_GRE && ip_proto != IPPROTO_OSPF) {
      return 0;
    }

    __be32 ip4_src = BPF_CORE_READ(iphdr, saddr);
    __be32 ip4_dst = BPF_CORE_READ(iphdr, daddr);
    MAP_V4_IN_V6(key->srcip, ip4_src);
    MAP_V4_IN_V6(key->dstip, ip4_dst);

    __u16 tot_len = bpf_ntohs(BPF_CORE_READ(iphdr, tot_len));
    __u16 ihl_bytes = (__u16)(BPF_CORE_READ_BITFIELD_PROBED(iphdr, ihl) * 4);
    ip_payload_len = (ihl_bytes <= tot_len) ? (size_t)(tot_len - ihl_bytes) : 0;
    break;
  }
  case ETH_P_IPV6: {
    struct ipv6hdr *iphdr = (struct ipv6hdr *)(head + nh_off);
    ip_proto = BPF_CORE_READ(iphdr, nexthdr);

    // Walk up to 2 ext headers via probe_read so ESP/AH/GRE/OSPF behind
    // HopByHop/Routing/Fragment/DstOpts attribute correctly.
    __u16 ext_skip = 0;
#pragma unroll 2
    for (int i = 0; i < 2; i++) {
      if (likely(ip_proto != IPPROTO_HOPOPTS && ip_proto != IPPROTO_ROUTING &&
                 ip_proto != IPPROTO_FRAGMENT && ip_proto != IPPROTO_DSTOPTS)) {
        break;
      }
      __u8 pair[2];
      if (bpf_probe_read_kernel(pair, 2, head + nh_off + sizeof(*iphdr) +
                                            ext_skip) != 0) {
        return 0;
      }
      if (ip_proto == IPPROTO_FRAGMENT) {
        ip_proto = pair[0];
        ext_skip += 8;
      } else {
        ip_proto = pair[0];
        ext_skip += ((__u16)(pair[1] + 1) * 8);
      }
    }

    if (ip_proto != IPPROTO_ESP && ip_proto != IPPROTO_AH &&
        ip_proto != IPPROTO_GRE && ip_proto != IPPROTO_OSPF) {
      return 0;
    }

    BPF_CORE_READ_INTO(&key->srcip, iphdr, saddr);
    BPF_CORE_READ_INTO(&key->dstip, iphdr, daddr);

    __u16 payload_len = bpf_ntohs(BPF_CORE_READ(iphdr, payload_len));
    ip_payload_len = (ext_skip <= payload_len) ? (size_t)(payload_len - ext_skip)
                                               : 0;
    break;
  }
  default:
    return 0;
  }

  key->proto = ip_proto;
  key->pid = pid;
  // Port slots left zero; SPI/type/flags decode via probe_read deferred.

  return ip_payload_len;
}

static inline __attribute__((always_inline)) size_t
process_udp_send(struct sk_buff *skb, statkey *key, pid_t pid) {
  // Reuse the udphdr that process_udp_recv resolved.
  struct udphdr *udphdr = NULL;
  if (!process_udp_recv(false, skb, key, pid, &udphdr))
    return 0;

  return bpf_ntohs(BPF_CORE_READ(udphdr, len));
}

#ifdef PKTSTAT_NEEDS_CGROUP_HELPERS

// v1 task-walk. Wrong in softirq — prefer bpf_skb_cgroup_id() when skb exists.
static inline __attribute__((always_inline)) __u64
get_current_cgroup_id_v1(void) {
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  struct cgroup *cgroup = BPF_CORE_READ(task, cgroups, subsys[0], cgroup);

  return get_cgroup_id(cgroup);
}

// Umbrella helper; verifier folds the v1/v2 branch via cgrpfs_magic.
static inline __attribute__((always_inline)) __u64 get_current_cgroup_id(void) {
  if (bpf_core_enum_value_exists(enum bpf_func_id,
                                 BPF_FUNC_get_current_cgroup_id) &&
      cgrpfs_magic == CGROUP2_FSMAGIC) {
    return bpf_get_current_cgroup_id();
  }

  return get_current_cgroup_id_v1();
}

#endif // PKTSTAT_NEEDS_CGROUP_HELPERS
