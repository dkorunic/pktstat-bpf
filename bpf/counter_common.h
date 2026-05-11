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

// Packed: drops 7 bytes of tail padding, shrinking 72 → 65. Saves hashed
// bytes per lookup and nCPU × 7 bytes per entry under LRU_PERCPU_HASH.
// All interior fields stay naturally aligned within the first 65 bytes.
typedef struct __attribute__((packed)) statkey_t {
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

// Patched at load time; verifier folds the v1/v2 branch into a constant.
// Only emitted in translation units that actually call the cgroup helpers.
#ifdef PKTSTAT_NEEDS_CGROUP_HELPERS
volatile const __u64 cgrpfs_magic = 0;
#endif

// V4MAPPED prefix: ::ffff:a.b.c.d
static const __u8 ip4in6[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

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

  __builtin_memcpy(key->srcip.s6_addr, ip4in6, sizeof(ip4in6));
  __builtin_memcpy(key->srcip.s6_addr + sizeof(ip4in6), &ip4->saddr,
                   sizeof(ip4->saddr));
  __builtin_memcpy(key->dstip.s6_addr, ip4in6, sizeof(ip4in6));
  __builtin_memcpy(key->dstip.s6_addr + sizeof(ip4in6), &ip4->daddr,
                   sizeof(ip4->daddr));

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

  // Walk ext headers: HopByHop/Routing/DstOpts size = (hdr_ext_len+1)*8;
  // Fragment is fixed 8 bytes. next_header lives at offset 0.
  __u8 nexthdr = ip6->nexthdr;
  void *transport = (void *)ip6 + sizeof(*ip6);

  // Cap at 2 iterations: real traffic almost never has >1 ext header.
  // Chained ext headers beyond that attribute to the depth-1 next_header
  // (e.g. IPPROTO_ROUTING) rather than the actual transport. Intentional.
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
      // (next_header, hdr_ext_len) as a network-order u16.
      __u16 hdr_pair = bpf_ntohs(*(__u16 *)transport);
      nexthdr = hdr_pair >> 8;
      __u8 hdrlen = (__u8)hdr_pair;
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

  // Key existence is global; per-CPU slots are zero-initialized on first
  // insert. So if BPF_NOEXIST loses the race, our slot is guaranteed (0,0)
  // and the retry +=  produces correct sums after userspace aggregation.
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

  statkey key;
  if (!process_l3((void *)eth + sizeof(*eth), data_end,
                  bpf_ntohs(eth->h_proto), &key)) {
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

  // Socket holds local in skc_(rcv_)saddr/skc_num, remote in skc_daddr/dport.
  // Pick destinations up-front for the receive flow instead of swapping.
  struct in6_addr *src = receive ? &key->dstip : &key->srcip;
  struct in6_addr *dst = receive ? &key->srcip : &key->dstip;

  switch (family) {
  case AF_INET: {
    __be32 ip4_local = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    __builtin_memcpy(src->s6_addr, ip4in6, sizeof(ip4in6));
    __builtin_memcpy(src->s6_addr + sizeof(ip4in6), &ip4_local,
                     sizeof(ip4_local));

    __be32 ip4_remote = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    __builtin_memcpy(dst->s6_addr, ip4in6, sizeof(ip4in6));
    __builtin_memcpy(dst->s6_addr + sizeof(ip4in6), &ip4_remote,
                     sizeof(ip4_remote));
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

// On success, optionally publishes the parsed udphdr via udphdr_out (NULL
// to skip). Caller must check the return value before dereferencing it.
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
    __builtin_memcpy(ip_src->s6_addr, ip4in6, sizeof(ip4in6));
    __builtin_memcpy(ip_src->s6_addr + sizeof(ip4in6), &ip4_pkt_src,
                     sizeof(ip4_pkt_src));

    __be32 ip4_pkt_dst = BPF_CORE_READ(iphdr, daddr);
    __builtin_memcpy(ip_dst->s6_addr, ip4in6, sizeof(ip4in6));
    __builtin_memcpy(ip_dst->s6_addr + sizeof(ip4in6), &ip4_pkt_dst,
                     sizeof(ip4_pkt_dst));
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
  __builtin_memcpy(key->srcip.s6_addr, ip4in6, sizeof(ip4in6));
  __builtin_memcpy(key->srcip.s6_addr + sizeof(ip4in6), &ip4_src,
                   sizeof(ip4_src));

  __be32 ip4_dst = BPF_CORE_READ(iphdr, daddr);
  __builtin_memcpy(key->dstip.s6_addr, ip4in6, sizeof(ip4in6));
  __builtin_memcpy(key->dstip.s6_addr + sizeof(ip4in6), &ip4_dst,
                   sizeof(ip4_dst));

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

static inline __attribute__((always_inline)) size_t
process_udp_send(struct sk_buff *skb, statkey *key, pid_t pid) {
  // Reuse the udphdr that process_udp_recv resolved.
  struct udphdr *udphdr = NULL;
  if (!process_udp_recv(false, skb, key, pid, &udphdr))
    return 0;

  return bpf_ntohs(BPF_CORE_READ(udphdr, len));
}

#ifdef PKTSTAT_NEEDS_CGROUP_HELPERS

// task->cgroups walk. Use only after confirming v1 mode. Inaccurate in
// softirq context — prefer bpf_skb_cgroup_id() when an skb is available.
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

static inline __attribute__((always_inline)) bool
process_raw_sendmsg4(struct sock *sk, struct msghdr *msg, statkey *key,
                     pid_t pid) {
  struct inet_sock *isk = (struct inet_sock *)sk;

  // Raw socket protocol number lives in inet_num.
  __u16 proto = BPF_CORE_READ(isk, inet_num);
  if (proto != IPPROTO_ICMP) {
    return false;
  }

  if (pid > 0) {
    bpf_get_current_comm(&key->comm, sizeof(key->comm));
  }
  key->cgroupid = get_current_cgroup_id();

  // msg_name is NULL on connected raw sockets — destination is unknown.
  struct sockaddr_in *sin = (struct sockaddr_in *)BPF_CORE_READ(msg, msg_name);
  if (!sin) {
    return false;
  }

  __be32 ip4_src = BPF_CORE_READ(isk, inet_saddr);
  __builtin_memcpy(key->srcip.s6_addr, ip4in6, sizeof(ip4in6));
  __builtin_memcpy(key->srcip.s6_addr + sizeof(ip4in6), &ip4_src,
                   sizeof(ip4_src));

  __be32 ip4_dst = BPF_CORE_READ(sin, sin_addr.s_addr);
  __builtin_memcpy(key->dstip.s6_addr, ip4in6, sizeof(ip4in6));
  __builtin_memcpy(key->dstip.s6_addr + sizeof(ip4in6), &ip4_dst,
                   sizeof(ip4_dst));

  // iov_base lives in user memory. Kernels ≥6.0 set ITER_UBUF for single
  // buffer sends and store the pointer directly in __ubuf_iovec; ITER_IOVEC
  // requires dereferencing __iov first. Reading __iov for ITER_UBUF would
  // misinterpret the data pointer as an iovec array pointer.
  void *iov_base;
  __u8 iter_type = BPF_CORE_READ(msg, msg_iter.iter_type);
  if (iter_type == ITER_UBUF) {
    iov_base = (void *)BPF_CORE_READ(msg, msg_iter.__ubuf_iovec.iov_base);
  } else {
    struct iovec *iov = (struct iovec *)BPF_CORE_READ(msg, msg_iter.__iov);
    if (!iov) {
      return false;
    }
    iov_base = (void *)BPF_CORE_READ(iov, iov_base);
  }
  if (!iov_base) {
    return false;
  }
  struct icmphdr icmphdr;
  if (bpf_probe_read_user(&icmphdr, sizeof(icmphdr), iov_base) != 0) {
    return false;
  }

  // ICMP has no ports; stash type/code in the port slots.
  key->src_port = icmphdr.type;
  key->dst_port = icmphdr.code;

  key->proto = IPPROTO_ICMP;
  key->pid = pid;

  return true;
}

static inline __attribute__((always_inline)) bool
process_raw_sendmsg6(struct sock *sk, struct msghdr *msg, statkey *key,
                     pid_t pid) {
  struct inet_sock *isk = (struct inet_sock *)sk;

  // Raw socket protocol number lives in inet_num.
  __u16 proto = BPF_CORE_READ(isk, inet_num);
  if (proto != IPPROTO_ICMPV6) {
    return false;
  }

  if (pid > 0) {
    bpf_get_current_comm(&key->comm, sizeof(key->comm));
  }
  key->cgroupid = get_current_cgroup_id();

  // msg_name is NULL on connected raw sockets — destination is unknown.
  struct sockaddr_in6 *sin6 =
      (struct sockaddr_in6 *)BPF_CORE_READ(msg, msg_name);
  if (!sin6) {
    return false;
  }

  BPF_CORE_READ_INTO(&key->srcip, sk, __sk_common.skc_v6_rcv_saddr);
  BPF_CORE_READ_INTO(&key->dstip, sin6, sin6_addr);

  // See process_raw_sendmsg4 for the ITER_UBUF / ITER_IOVEC split rationale.
  void *iov_base;
  __u8 iter_type = BPF_CORE_READ(msg, msg_iter.iter_type);
  if (iter_type == ITER_UBUF) {
    iov_base = (void *)BPF_CORE_READ(msg, msg_iter.__ubuf_iovec.iov_base);
  } else {
    struct iovec *iov = (struct iovec *)BPF_CORE_READ(msg, msg_iter.__iov);
    if (!iov) {
      return false;
    }
    iov_base = (void *)BPF_CORE_READ(iov, iov_base);
  }
  if (!iov_base) {
    return false;
  }
  struct icmp6hdr icmp6hdr;
  if (bpf_probe_read_user(&icmp6hdr, sizeof(icmp6hdr), iov_base) != 0) {
    return false;
  }

  // ICMP has no ports; stash type/code in the port slots.
  key->src_port = icmp6hdr.icmp6_type;
  key->dst_port = icmp6hdr.icmp6_code;

  key->proto = IPPROTO_ICMPV6;
  key->pid = pid;

  return true;
}
