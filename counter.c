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

#include <linux/bpf.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stddef.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define MAX_ENTRIES 4096

#define OK 1
#define NOK 0

// Map key struct for IP traffic
typedef struct statkey_t {
  struct in6_addr srcip; // source IPv6 address
  struct in6_addr dstip; // destination IPv6 address
  __u16 src_port;        // source port
  __u16 dst_port;        // destination port
  __u8 proto;            // transport protocol
} statkey;

// Map value struct with counters
typedef struct statvalue_t {
  __u64 packets; // packets ingress + egress
  __u64 bytes;   // bytes ingress + egress
} statvalue;

// Map definition
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH); // LRU hash requires 4.10 kernel
  __uint(max_entries, MAX_ENTRIES);
  __type(key, statkey);
  __type(value, statvalue);
} pkt_count SEC(".maps");

// IPv4-mapped IPv6 address prefix
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
static inline int process_ip4(struct iphdr *ip4, void *data_end, statkey *key) {
  // validate IPv4 size
  if ((void *)ip4 + sizeof(*ip4) > data_end) {
    return NOK;
  }

  // copy 4-in-6 prefix and rest of IPv4 source address
  __builtin_memcpy(key->srcip.s6_addr, ip4in6, sizeof(ip4in6));
  __builtin_memcpy(key->srcip.s6_addr + sizeof(ip4in6), &ip4->saddr,
                   sizeof(ip4->saddr));

  // copy 4-in-6 prefix and rest of IPv4 destination address
  __builtin_memcpy(key->dstip.s6_addr, ip4in6, sizeof(ip4in6));
  __builtin_memcpy(key->dstip.s6_addr + sizeof(ip4in6), &ip4->daddr,
                   sizeof(ip4->daddr));

  key->proto = ip4->protocol;

  switch (ip4->protocol) {
  case IPPROTO_TCP: {
    struct tcphdr *tcp = (void *)ip4 + sizeof(*ip4);

    // validate TCP size
    if ((void *)tcp + sizeof(*tcp) > data_end) {
      return NOK;
    }

    key->src_port = bpf_ntohs(tcp->source);
    key->dst_port = bpf_ntohs(tcp->dest);
  }

  break;
  case IPPROTO_UDP: {
    struct udphdr *udp = (void *)ip4 + sizeof(*ip4);

    // validate UDP size
    if ((void *)udp + sizeof(*udp) > data_end) {
      return NOK;
    }

    key->src_port = bpf_ntohs(udp->source);
    key->dst_port = bpf_ntohs(udp->dest);
  }

  break;
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
static inline int process_ip6(struct ipv6hdr *ip6, void *data_end,
                              statkey *key) {
  // validate IPv6 size
  if ((void *)ip6 + sizeof(*ip6) > data_end) {
    return NOK;
  }

  // IPv6 copy of source IP, destination IP and transport protocol
  key->srcip = ip6->saddr;
  key->dstip = ip6->daddr;
  key->proto = ip6->nexthdr;

  switch (ip6->nexthdr) {
  case IPPROTO_TCP: {
    struct tcphdr *tcp = (void *)ip6 + sizeof(*ip6);

    // validate TCP size
    if ((void *)tcp + sizeof(*tcp) > data_end) {
      return NOK;
    }

    key->src_port = bpf_ntohs(tcp->source);
    key->dst_port = bpf_ntohs(tcp->dest);
  }

  break;
  case IPPROTO_UDP: {
    struct udphdr *udp = (void *)ip6 + sizeof(*ip6);

    // validate UDP size
    if ((void *)udp + sizeof(*udp) > data_end) {
      return NOK;
    }

    key->src_port = bpf_ntohs(udp->source);
    key->dst_port = bpf_ntohs(udp->dest);
  }

  break;
  }

  return OK;
}

/**
 * Process the Ethernet header and extract relevant information to populate the
 * key.
 *
 * @param data pointer to the start of the Ethernet header
 * @param data_end pointer to the end of the packet data
 * @param pkt_len length of the packet
 *
 * @return none
 *
 * @throws none
 */
static inline void process_eth(void *data, void *data_end, __u64 pkt_len) {
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

    if (process_ip4(ip4, data_end, &key) == NOK)
      return;
  }

  break;
  case ETH_P_IPV6: {
    struct ipv6hdr *ip6 = (void *)eth + sizeof(*eth);

    if (process_ip6(ip6, data_end, &key) == NOK)
      return;
  }

  break;
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
 * @return TC_ACT_UNSPEC
 *
 * @throws none
 */
static inline void tc_process_packet(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  process_eth(data, data_end, skb->len);
}

/**
 * Process the packet for XDP (eXpress Data Path) and take necessary actions.
 *
 * @param ctx pointer to the XDP context
 *
 * @return XDP_PASS
 *
 * @throws none
 */
static inline void xdp_process_packet(struct xdp_md *xdp) {
  void *data = (void *)(long)xdp->data;
  void *data_end = (void *)(long)xdp->data_end;

  process_eth(data, data_end, data_end - data);
}

/*
 * Main eBPF XDP program
 */
SEC("xdp")
int xdp_count_packets(struct xdp_md *xdp) {
  xdp_process_packet(xdp);

  return XDP_PASS;
}

/*
 * Main eBPF TC program
 */
SEC("tc")
int tc_count_packets(struct __sk_buff *skb) {
  tc_process_packet(skb);

  return TC_ACT_UNSPEC;
}

char __license[] SEC("license") = "Dual MIT/GPL";
