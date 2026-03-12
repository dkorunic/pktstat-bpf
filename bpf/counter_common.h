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

// Counter map key struct for IP traffic
typedef struct statkey_t {
  struct in6_addr srcip;    // source IPv6 address
  struct in6_addr dstip;    // destination IPv6 address
  __u64 cgroupid;           // cgroup ID
  char comm[TASK_COMM_LEN]; // process command
  pid_t pid;                // process ID
  __u16 src_port;           // source port
  __u16 dst_port;           // destination port
  __u8 proto;               // transport protocol
} statkey;

// Counter map value struct with counters
typedef struct statvalue_t {
  __u64 packets; // packets ingress + egress
  __u64 bytes;   // bytes ingress + egress
} statvalue;

// Counter map definition
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH); // LRU hash requires 4.10 kernel
  __uint(max_entries, MAX_ENTRIES);
  __type(key, statkey);
  __type(value, statvalue);
} pkt_count SEC(".maps");

// Sockinfo struct
typedef struct sockinfo_t {
  __u8 comm[TASK_COMM_LEN];
  pid_t pid;
} sockinfo;

// Configuration map value struct
typedef struct counter_cfg_t {
  __u64 cgrpfs_magic; // cgroupv1 or cgroupv2 fs magic
} counter_cfg_value;

// Configuration map definition
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, counter_cfg_value);
} counter_cfg SEC(".maps");

// IPv4-mapped IPv6 address prefix (for V4MAPPED conversion)
static const __u8 ip4in6[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

/**
 * Process an IPv4 packet and populate the key with the relevant information.
 *
 * @param ip4 pointer to the start of the IPv4 header
 * @param data_end pointer to the end of the packet data
 * @param key pointer to the statkey structure to be populated
 *
 * @return OK if the packet was processed successfully, NOK otherwise
 *
 * @throws none
 */
static inline __attribute__((always_inline)) int
process_ip4(struct iphdr *ip4, void *data_end, statkey *key) {
  // validate IPv4 fixed header size
  if ((void *)ip4 + sizeof(*ip4) > data_end) {
    return NOK;
  }

  // ihl is the header length in 32-bit words (4-bit field, range 0–15).
  // Values < 5 are malformed; values > 5 indicate IPv4 options are present.
  __u8 ihl = ip4->ihl;
  if (ihl < 5) {
    return NOK;
  }
  __u32 ip4_hdr_len = (__u32)ihl * 4;

  // validate the full IP header (including any options) fits in the packet
  if ((void *)ip4 + ip4_hdr_len > data_end) {
    return NOK;
  }

  // transport header starts after the variable-length IP header
  void *transport = (void *)ip4 + ip4_hdr_len;

  // convert to V4MAPPED address
  __builtin_memcpy(key->srcip.s6_addr, ip4in6, sizeof(ip4in6));
  __builtin_memcpy(key->srcip.s6_addr + sizeof(ip4in6), &ip4->saddr,
                   sizeof(ip4->saddr));

  // convert to V4MAPPED address
  __builtin_memcpy(key->dstip.s6_addr, ip4in6, sizeof(ip4in6));
  __builtin_memcpy(key->dstip.s6_addr + sizeof(ip4in6), &ip4->daddr,
                   sizeof(ip4->daddr));

  key->proto = ip4->protocol;

  switch (ip4->protocol) {
  case IPPROTO_TCP: {
    struct tcphdr *tcp = transport;

    // validate TCP size
    if ((void *)tcp + sizeof(*tcp) > data_end) {
      return NOK;
    }

    key->src_port = bpf_ntohs(tcp->source);
    key->dst_port = bpf_ntohs(tcp->dest);

    break;
  }
  case IPPROTO_UDP: {
    struct udphdr *udp = transport;

    // validate UDP size
    if ((void *)udp + sizeof(*udp) > data_end) {
      return NOK;
    }

    key->src_port = bpf_ntohs(udp->source);
    key->dst_port = bpf_ntohs(udp->dest);

    break;
  }
  case IPPROTO_ICMP: {
    struct icmphdr *icmp = transport;

    // validate ICMP size
    if ((void *)icmp + sizeof(*icmp) > data_end) {
      return NOK;
    }

    // store ICMP type in src port
    key->src_port = icmp->type;
    // store ICMP code in dst port
    key->dst_port = icmp->code;

    break;
  }
  }

  return OK;
}

/**
 * Process an IPv6 packet and extract relevant information to populate the key.
 *
 * @param ip6 pointer to the start of the IPv6 header
 * @param data_end pointer to the end of the packet data
 * @param key pointer to the statkey structure to be populated
 *
 * @return OK if the packet was successfully processed, NOK otherwise
 *
 * @throws none
 */
static inline __attribute__((always_inline)) int
process_ip6(struct ipv6hdr *ip6, void *data_end, statkey *key) {
  // validate IPv6 size
  if ((void *)ip6 + sizeof(*ip6) > data_end) {
    return NOK;
  }

  // IPv6 copy of source IP and destination IP
  key->srcip = ip6->saddr;
  key->dstip = ip6->daddr;

  // Walk optional extension headers to find the actual transport protocol.
  // Variable-length extension headers (HopByHop, Routing, Destination):
  //   total size = (hdr_ext_len + 1) * 8 bytes; next_header at offset 0.
  // Fragment header: fixed 8 bytes; next_header at offset 0.
  __u8 nexthdr = ip6->nexthdr;
  void *transport = (void *)ip6 + sizeof(*ip6);

#pragma unroll
  for (int i = 0; i < 6; i++) {
    if (nexthdr != IPPROTO_HOPOPTS && nexthdr != IPPROTO_ROUTING &&
        nexthdr != IPPROTO_FRAGMENT && nexthdr != IPPROTO_DSTOPTS) {
      break;
    }
    if (nexthdr == IPPROTO_FRAGMENT) {
      if (transport + 8 > data_end)
        return NOK;
      nexthdr = ((__u8 *)transport)[0];
      transport += 8;
    } else {
      if (transport + 2 > data_end)
        return NOK;
      __u8 hdrlen = ((__u8 *)transport)[1];
      nexthdr = ((__u8 *)transport)[0];
      transport += ((__u32)(hdrlen + 1) * 8);
    }
  }

  key->proto = nexthdr;

  switch (nexthdr) {
  case IPPROTO_TCP: {
    struct tcphdr *tcp = transport;

    // validate TCP size
    if ((void *)tcp + sizeof(*tcp) > data_end) {
      return NOK;
    }

    key->src_port = bpf_ntohs(tcp->source);
    key->dst_port = bpf_ntohs(tcp->dest);

    break;
  }
  case IPPROTO_UDP: {
    struct udphdr *udp = transport;

    // validate UDP size
    if ((void *)udp + sizeof(*udp) > data_end) {
      return NOK;
    }

    key->src_port = bpf_ntohs(udp->source);
    key->dst_port = bpf_ntohs(udp->dest);

    break;
  }
  case IPPROTO_ICMPV6: {
    struct icmp6hdr *icmp = transport;

    // validate ICMPv6 size
    if ((void *)icmp + sizeof(*icmp) > data_end) {
      return NOK;
    }

    // store ICMP type in src port
    key->src_port = icmp->icmp6_type;
    // store ICMP code in dst port
    key->dst_port = icmp->icmp6_code;

    break;
  }
  }

  return OK;
}

/**
 * Update the packet and byte counters for the given key in the packet count
 * map. If the key is not present, it is inserted with an initial value of 1
 * packet and the given size in bytes. If the key is already present, the
 * packet and byte counters are atomically incremented.
 *
 * @param key pointer to the statkey structure containing the key to be
 * updated
 * @param size size of the packet to be counted
 *
 * @throws none
 */
static inline __attribute__((always_inline)) void update_val(statkey *key,
                                                             size_t size) {
  // lookup value in hash
  statvalue *val = (statvalue *)bpf_map_lookup_elem(&pkt_count, key);
  if (val) {
    // atomic XADD, doesn't need bpf_spin_lock()
    __sync_fetch_and_add(&val->packets, 1);
    __sync_fetch_and_add(&val->bytes, size);
  } else {
    statvalue initval = {.packets = 1, .bytes = size};

    // BPF_NOEXIST can race on multi-CPU: another CPU may insert the same key
    // between our lookup and this insert. On failure, retry the lookup and
    // increment atomically so the packet is not silently dropped.
    if (bpf_map_update_elem(&pkt_count, key, &initval, BPF_NOEXIST) != 0) {
      val = (statvalue *)bpf_map_lookup_elem(&pkt_count, key);
      if (val) {
        __sync_fetch_and_add(&val->packets, 1);
        __sync_fetch_and_add(&val->bytes, size);
      }
    }
  }
}

/**
 * Process an Ethernet packet and populate the key with the relevant
 * information.
 *
 * @param data pointer to the start of the packet data
 * @param data_end pointer to the end of the packet data
 * @param pkt_len length of the packet
 *
 * @return void
 *
 * @throws none
 */
static inline __attribute__((always_inline)) void
process_eth(void *data, void *data_end, __u64 pkt_len) {
  struct ethhdr *eth = data;

  // validate Ethernet size
  if ((void *)eth + sizeof(*eth) > data_end) {
    return;
  }

  // initialize key
  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  // process only IPv4 and IPv6
  switch (bpf_ntohs(eth->h_proto)) {
  case ETH_P_IP: {
    struct iphdr *ip4 = (void *)eth + sizeof(*eth);

    if (process_ip4(ip4, data_end, &key) == NOK) {
      return;
    }

    break;
  }
  case ETH_P_IPV6: {
    struct ipv6hdr *ip6 = (void *)eth + sizeof(*eth);

    if (process_ip6(ip6, data_end, &key) == NOK) {
      return;
    }

    break;
  }
  default:
    return;
  }

  // lookup value in hash
  statvalue *val = (statvalue *)bpf_map_lookup_elem(&pkt_count, &key);
  if (val) {
    // atomic XADD, doesn't need bpf_spin_lock()
    __sync_fetch_and_add(&val->packets, 1);
    __sync_fetch_and_add(&val->bytes, pkt_len);
  } else {
    statvalue initval = {.packets = 1, .bytes = pkt_len};

    bpf_map_update_elem(&pkt_count, &key, &initval, BPF_NOEXIST);
  }
}

/**
 * Process the packet for traffic control and take necessary actions.
 *
 * @param skb pointer to the packet buffer
 *
 * @return void
 *
 * @throws none
 */
static inline __attribute__((always_inline)) void
tc_process_packet(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  process_eth(data, data_end, skb->len);
}

/**
 * Process the packet for XDP (eXpress Data Path) and take necessary actions.
 *
 * @param ctx pointer to the XDP context
 *
 * @return void
 *
 * @throws none
 */
static inline __attribute__((always_inline)) void
xdp_process_packet(struct xdp_md *xdp) {
  void *data = (void *)(long)xdp->data;
  void *data_end = (void *)(long)xdp->data_end;

  process_eth(data, data_end, bpf_xdp_get_buff_len(xdp));
}

/**
 * Process TCP socket information and populate the key structure with
 * extracted data.
 *
 * @param receive boolean flag indicating whether the socket is a receiver
 * @param sk pointer to the socket structure
 * @param key pointer to the statkey structure to be populated
 * @param pid process ID associated with the socket
 *
 * This function reads the socket's address family and based on whether it is
 * IPv4 or IPv6, it extracts the source and destination IP addresses and
 * ports. It also sets the protocol to TCP and assigns the provided process ID
 * to the key.
 *
 * The function handles both IPv4 and IPv6 addresses by converting them to an
 * IPv6-mapped format for uniformity.
 *
 * @throws none
 */
static inline __attribute__((always_inline)) bool
process_tcp(bool receive, struct sock *sk, statkey *key, pid_t pid) {
  __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);

  switch (family) {
  case AF_INET: {
    // convert to V4MAPPED address
    __be32 ip4_src = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    __builtin_memcpy(key->srcip.s6_addr, ip4in6, sizeof(ip4in6));
    __builtin_memcpy(key->srcip.s6_addr + sizeof(ip4in6), &ip4_src,
                     sizeof(ip4_src));

    // convert to V4MAPPED address
    __be32 ip4_dst = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    __builtin_memcpy(key->dstip.s6_addr, ip4in6, sizeof(ip4in6));
    __builtin_memcpy(key->dstip.s6_addr + sizeof(ip4in6), &ip4_dst,
                     sizeof(ip4_dst));

    break;
  }
  case AF_INET6: {
    BPF_CORE_READ_INTO(&key->srcip, sk, __sk_common.skc_v6_rcv_saddr);
    BPF_CORE_READ_INTO(&key->dstip, sk, __sk_common.skc_v6_daddr);

    break;
  }
  default: {
    return false;
  }
  }

  __u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
  if (sport == 0) {
    struct inet_sock *isk = (struct inet_sock *)sk;
    sport = bpf_ntohs(BPF_CORE_READ(isk, inet_sport));
  }
  key->src_port = sport;
  key->dst_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

  key->proto = IPPROTO_TCP;
  key->pid = pid;

  /* we need to swap the source and destination IP addresses and ports */
  if (receive) {
    struct in6_addr tmp_ip = key->srcip;
    key->srcip = key->dstip;
    key->dstip = tmp_ip;

    __u16 tmp_port = key->src_port;
    key->src_port = key->dst_port;
    key->dst_port = tmp_port;
  }

  return true;
}

/**
 * Process UDP socket information from a sk_buff and populate the key
 * structure.
 *
 * @param receive boolean flag indicating whether the socket is a receiver
 * @param skb pointer to the socket buffer containing the UDP packet
 * @param key pointer to the statkey structure to be populated
 * @param pid process ID associated with the packet
 *
 * This function extracts source and destination IP addresses and ports from
 * the UDP packet, taking into account both IPv4 and IPv6 headers. It stores
 * these details in the provided statkey structure, along with the protocol
 * type set to UDP and the associated process ID.
 *
 * @throws none
 */
static inline __attribute__((always_inline)) bool
process_udp_recv(bool receive, struct sk_buff *skb, statkey *key, pid_t pid) {
  struct udphdr *udphdr =
      (struct udphdr *)(BPF_CORE_READ(skb, head) +
                        BPF_CORE_READ(skb, transport_header));

  __u16 proto = BPF_CORE_READ(skb, protocol);

  switch (bpf_ntohs(proto)) {
  case ETH_P_IP: {
    struct iphdr *iphdr = (struct iphdr *)(BPF_CORE_READ(skb, head) +
                                           BPF_CORE_READ(skb, network_header));

    // convert to V4MAPPED address
    __be32 ip4_src = BPF_CORE_READ(iphdr, saddr);
    __builtin_memcpy(key->srcip.s6_addr, ip4in6, sizeof(ip4in6));
    __builtin_memcpy(key->srcip.s6_addr + sizeof(ip4in6), &ip4_src,
                     sizeof(ip4_src));

    // convert to V4MAPPED address
    __be32 ip4_dst = BPF_CORE_READ(iphdr, daddr);
    __builtin_memcpy(key->dstip.s6_addr, ip4in6, sizeof(ip4in6));
    __builtin_memcpy(key->dstip.s6_addr + sizeof(ip4in6), &ip4_dst,
                     sizeof(ip4_dst));
    break;
  }
  case ETH_P_IPV6: {
    struct ipv6hdr *iphdr =
        (struct ipv6hdr *)(BPF_CORE_READ(skb, head) +
                           BPF_CORE_READ(skb, network_header));

    BPF_CORE_READ_INTO(&key->srcip, iphdr, saddr);
    BPF_CORE_READ_INTO(&key->dstip, iphdr, daddr);

    break;
  }
  default:
    return false;
  }

  key->src_port = bpf_ntohs(BPF_CORE_READ(udphdr, source));
  key->dst_port = bpf_ntohs(BPF_CORE_READ(udphdr, dest));

  key->proto = IPPROTO_UDP;
  key->pid = pid;

  /* we need to swap the source and destination IP addresses and ports */
  if (receive) {
    struct in6_addr tmp_ip = key->srcip;
    key->srcip = key->dstip;
    key->dstip = tmp_ip;

    __u16 tmp_port = key->src_port;
    key->src_port = key->dst_port;
    key->dst_port = tmp_port;
  }

  return true;
}

/**
 * Process an ICMPv4 packet and populate the key with the relevant information.
 *
 * @param skb pointer to the socket buffer containing the ICMPv4 packet
 * @param key pointer to the statkey structure to be populated
 * @param pid process ID associated with the packet
 *
 * This function extracts source and destination IP addresses and ICMP type
 * and code from the ICMPv4 packet, taking into account the IPv4 header. It
 * stores these details in the provided statkey structure, along with the
 * protocol type set to ICMPv4 and the associated process ID.
 *
 * @throws none
 */
static inline __attribute__((always_inline)) size_t
process_icmp4(struct sk_buff *skb, statkey *key, pid_t pid) {
  struct icmphdr *icmphdr =
      (struct icmphdr *)(BPF_CORE_READ(skb, head) +
                         BPF_CORE_READ(skb, transport_header));
  struct iphdr *iphdr = (struct iphdr *)(BPF_CORE_READ(skb, head) +
                                         BPF_CORE_READ(skb, network_header));

  // convert to V4MAPPED address
  __be32 ip4_src = BPF_CORE_READ(iphdr, saddr);
  __builtin_memcpy(key->srcip.s6_addr, ip4in6, sizeof(ip4in6));
  __builtin_memcpy(key->srcip.s6_addr + sizeof(ip4in6), &ip4_src,
                   sizeof(ip4_src));

  // convert to V4MAPPED address
  __be32 ip4_dst = BPF_CORE_READ(iphdr, daddr);
  __builtin_memcpy(key->dstip.s6_addr, ip4in6, sizeof(ip4in6));
  __builtin_memcpy(key->dstip.s6_addr + sizeof(ip4in6), &ip4_dst,
                   sizeof(ip4_dst));

  // store ICMP type in src port
  key->src_port = BPF_CORE_READ(icmphdr, type);
  // store ICMP code in dst port
  key->dst_port = BPF_CORE_READ(icmphdr, code);

  key->proto = IPPROTO_ICMP;
  key->pid = pid;

  __u16 tot_len = bpf_ntohs(BPF_CORE_READ(iphdr, tot_len));
  __u16 ihl_bytes = (__u16)(BPF_CORE_READ_BITFIELD_PROBED(iphdr, ihl) * 4);
  size_t msglen = (ihl_bytes <= tot_len) ? (tot_len - ihl_bytes) : 0;

  return msglen;
}

/**
 * Process an ICMPv6 packet and populate the key with the relevant information.
 *
 * @param skb pointer to the socket buffer containing the ICMPv6 packet
 * @param key pointer to the statkey structure to be populated
 * @param pid process ID associated with the packet
 *
 * This function extracts source and destination IP addresses and ICMPv6 type
 * and code from the ICMPv6 packet, taking into account the IPv6 header. It
 * stores these details in the provided statkey structure, along with the
 * protocol type set to ICMPv6 and the associated process ID. It also returns
 * the length of the ICMPv6 message payload.
 *
 * @return the length of the ICMPv6 message payload
 * @throws none
 */
static inline __attribute__((always_inline)) size_t
process_icmp6(struct sk_buff *skb, statkey *key, pid_t pid) {
  struct icmp6hdr *icmphdr =
      (struct icmp6hdr *)(BPF_CORE_READ(skb, head) +
                          BPF_CORE_READ(skb, transport_header));

  struct ipv6hdr *iphdr =
      (struct ipv6hdr *)(BPF_CORE_READ(skb, head) +
                         BPF_CORE_READ(skb, network_header));

  BPF_CORE_READ_INTO(&key->srcip, iphdr, saddr);
  BPF_CORE_READ_INTO(&key->dstip, iphdr, daddr);

  // store ICMP type in src port
  key->src_port = BPF_CORE_READ(icmphdr, icmp6_type);
  // store ICMP code in dst port
  key->dst_port = BPF_CORE_READ(icmphdr, icmp6_code);

  key->proto = IPPROTO_ICMPV6;
  key->pid = pid;

  size_t msglen = bpf_ntohs(BPF_CORE_READ(iphdr, payload_len));

  return msglen;
}

/**
 * Process UDP socket information from a sk_buff and populate the key
 * structure.
 *
 * @param skb pointer to the socket buffer containing the UDP packet
 * @param key pointer to the statkey structure to be populated
 * @param pid process ID associated with the packet
 *
 * This function extracts source and destination IP addresses and ports from
 * the UDP packet, taking into account both IPv4 and IPv6 headers. It stores
 * these details in the provided statkey structure, along with the protocol
 * type set to UDP and the associated process ID. It also returns the length
 * of the UDP message.
 *
 * @throws none
 */
static inline __attribute__((always_inline)) size_t
process_udp_send(struct sk_buff *skb, statkey *key, pid_t pid) {
  if (!process_udp_recv(false, skb, key, pid))
    return 0;

  struct udphdr *udphdr =
      (struct udphdr *)(BPF_CORE_READ(skb, head) +
                        BPF_CORE_READ(skb, transport_header));
  size_t msglen = bpf_ntohs(BPF_CORE_READ(udphdr, len));

  return msglen;
}

/**
 * get_cgroupid - reads the cgroup ID from the given struct cgroup
 *
 * This function reads the cgroup ID from the given struct cgroup and returns
 * it. The function works on kernels v4.10 and above.
 *
 * @cgrp: the struct cgroup to read the cgroup ID from
 *
 * Returns: the cgroup ID as an unsigned 64-bit integer
 *
 * get_cgroupid() comes from aquasecurity/tracee, license: Apache-2.0
 */
static inline __attribute__((always_inline)) __u64
get_cgroup_id(struct cgroup *cgrp) {
  struct kernfs_node *kn = BPF_CORE_READ(cgrp, kn);

  if (kn == NULL)
    return 0;

  __u64 id; // was union kernfs_node_id before 5.5, can read it as u64 in both
            // situations

  if (bpf_core_type_exists(union kernfs_node_id)) {
    struct kernfs_node___older_v55 *kn_old = (void *)kn;
    struct kernfs_node___rh8 *kn_rh8 = (void *)kn;

    if (bpf_core_field_exists(kn_rh8->id)) {
      // RHEL8 has both types declared: union and u64:
      //     kn->id
      //     rh->rh_kabi_hidden_172->id
      // pointing to the same data
      bpf_core_read(&id, sizeof(__u64), &kn_rh8->id);
      id = id & 0xffffffff; // XXX: u32 is required
    } else {
      // all other regular kernels below v5.5
      bpf_core_read(&id, sizeof(__u64), &kn_old->id);
      id = id & 0xffffffff; // XXX: u32 is required
    }
  } else {
    // kernel v5.5 and above
    bpf_core_read(&id, sizeof(__u64), &kn->id);
  }

  return id;
}

/**
 * get_current_cgroup_id - get the current cgroup ID
 *
 * This function determines the current cgroup ID of the running process.
 * It first checks if the cgroup v2 pseudo-filesystem is present and
 * if so, calls the bpf_get_current_cgroup_id() helper function. If not,
 * it reads the cgroup ID from the task_struct structure. It returns the
 * cgroup ID as an unsigned 64-bit integer.
 *
 * @return the current cgroup ID as an unsigned 64-bit integer
 */
static inline __attribute__((always_inline)) __u64 get_current_cgroup_id(void) {
  __u32 zero_key = 0;
  __u64 cgrpfs_magic = 0;

  counter_cfg_value *cfg =
      (counter_cfg_value *)bpf_map_lookup_elem(&counter_cfg, &zero_key);
  if (cfg) {
    cgrpfs_magic = cfg->cgrpfs_magic;
  }

  // cgroup v2
  if (bpf_core_enum_value_exists(enum bpf_func_id,
                                 BPF_FUNC_get_current_cgroup_id) &&
      cgrpfs_magic == CGROUP2_FSMAGIC) {
    return bpf_get_current_cgroup_id();
  }

  // cgroup v1
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  struct cgroup *cgroup = BPF_CORE_READ(task, cgroups, subsys[0], cgroup);

  return get_cgroup_id(cgroup);
}
