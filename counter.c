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

// go:build ignore

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_ENTRIES 4096

#define s6_addr in6_u.u6_addr8
#define s6_addr16 in6_u.u6_addr16
#define s6_addr32 in6_u.u6_addr32

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define TC_ACT_UNSPEC -1
#define AF_INET 2
#define AF_INET6 10

#define OK 1
#define NOK 0

// Map key struct for IP traffic
typedef struct statkey_t {
  struct in6_addr srcip; // source IPv6 address
  struct in6_addr dstip; // destination IPv6 address
  __u16 src_port;        // source port
  __u16 dst_port;        // destination port
  __u8 proto;            // transport protocol
  pid_t pid;             // process ID
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
static inline int process_ip4(struct iphdr *ip4, void *data_end, statkey *key) {
  // validate IPv4 size
  if ((void *)ip4 + sizeof(*ip4) > data_end) {
    return NOK;
  }

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

/**
 * This function is a BPF program entry point for processing packets using
 * XDP (eXpress Data Path). It invokes the xdp_process_packet function to
 * handle the packet specified by the xdp parameter.
 *
 * @param xdp pointer to the XDP context
 *
 * @return XDP_PASS to indicate that the packet should be passed to the
 *         next processing stage in the network stack
 *
 * @throws none
 */
SEC("xdp")
int xdp_count_packets(struct xdp_md *xdp) {
  xdp_process_packet(xdp);

  return XDP_PASS;
}

/**
 * Process a packet for Traffic Control and update statistics.
 *
 * This function is a BPF program entry point for packet processing using
 * Traffic Control (TC) hooks. It invokes the tc_process_packet function
 * to handle the packet specified by the skb parameter.
 *
 * @param skb pointer to the packet buffer
 *
 * @return TC_ACT_UNSPEC to indicate no specific TC action is taken
 *
 * @throws none
 */
SEC("tc")
int tc_count_packets(struct __sk_buff *skb) {
  tc_process_packet(skb);

  return TC_ACT_UNSPEC;
}

/**
 * Process TCP socket information and populate the key structure with extracted
 * data.
 *
 * @param sk pointer to the socket structure
 * @param key pointer to the statkey structure to be populated
 * @param pid process ID associated with the socket
 *
 * This function reads the socket's address family and based on whether it is
 * IPv4 or IPv6, it extracts the source and destination IP addresses and ports.
 * It also sets the protocol to TCP and assigns the provided process ID to the
 * key.
 *
 * The function handles both IPv4 and IPv6 addresses by converting them to an
 * IPv6-mapped format for uniformity.
 *
 * @throws none
 */
static inline void process_tcp(struct sock *sk, statkey *key, pid_t pid) {
  __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);

  switch (family) {
  case AF_INET: {
    // convert to V4MAPPED address
    __be32 ip4_src = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    key->srcip.s6_addr16[5] = bpf_htons(0xffff);
    __builtin_memcpy(&key->srcip.s6_addr32[3], &ip4_src, sizeof(ip4_src));

    // convert to V4MAPPED address
    __be32 ip4_dst = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    key->dstip.s6_addr16[5] = bpf_htons(0xffff);
    __builtin_memcpy(&key->dstip.s6_addr32[3], &ip4_dst, sizeof(ip4_dst));

    break;
  }
  case AF_INET6: {
    BPF_CORE_READ_INTO(&key->srcip, sk, __sk_common.skc_v6_rcv_saddr);
    BPF_CORE_READ_INTO(&key->dstip, sk, __sk_common.skc_v6_daddr);

    break;
  }
  default: {

    return;
  }
  }

  __u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
  if (sport == 0) {
    struct inet_sock *isk = (struct inet_sock *)sk;
    BPF_CORE_READ_INTO(&sport, isk, inet_sport);
  }
  key->src_port = bpf_ntohs(sport);
  key->dst_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

  key->proto = IPPROTO_TCP;
  key->pid = pid;
}

/**
 * Process UDP socket information from a sk_buff and populate the key structure.
 *
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
static inline void process_udp_recv(struct sk_buff *skb, statkey *key,
                                    pid_t pid) {
  struct udphdr *udphdr =
      (struct udphdr *)(BPF_CORE_READ(skb, head) +
                        BPF_CORE_READ(skb, transport_header));
  struct iphdr *iphdr = (struct iphdr *)(BPF_CORE_READ(skb, head) +
                                         BPF_CORE_READ(skb, network_header));

  __u16 proto = BPF_CORE_READ(skb, protocol);

  switch (bpf_ntohs(proto)) {
  case ETH_P_IP: {
    // convert to V4MAPPED address
    __be32 ip4_src = BPF_CORE_READ(iphdr, saddr);
    key->srcip.s6_addr16[5] = bpf_htons(0xffff);
    __builtin_memcpy(&key->srcip.s6_addr32[3], &ip4_src, sizeof(ip4_src));

    // convert to V4MAPPED address
    __be32 ip4_dst = BPF_CORE_READ(iphdr, daddr);
    key->dstip.s6_addr16[5] = bpf_htons(0xffff);
    __builtin_memcpy(&key->dstip.s6_addr32[3], &ip4_dst, sizeof(ip4_dst));
    break;
  }
  case ETH_P_IPV6: {
    BPF_CORE_READ_INTO(&key->srcip, iphdr, saddr);
    BPF_CORE_READ_INTO(&key->dstip, iphdr, daddr);

    break;
  }
  }

  key->src_port = bpf_ntohs(BPF_CORE_READ(udphdr, source));
  key->dst_port = bpf_ntohs(BPF_CORE_READ(udphdr, dest));

  key->proto = IPPROTO_UDP;
  key->pid = pid;
}

/**
 * Process UDP socket information from a sk_buff and populate the key structure.
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
static inline size_t process_udp_send(struct sk_buff *skb, statkey *key,
                                      pid_t pid) {
  struct udphdr *udphdr =
      (struct udphdr *)(BPF_CORE_READ(skb, head) +
                        BPF_CORE_READ(skb, transport_header));

  process_udp_recv(skb, key, pid);
  size_t msglen = BPF_CORE_READ(udphdr, len);

  return msglen;
}

/**
 * Update the packet and byte counters for the given key in the packet count
 * map. If the key is not present, it is inserted with an initial value of 1
 * packet and the given size in bytes. If the key is already present, the
 * packet and byte counters are atomically incremented.
 *
 * @param key pointer to the statkey structure containing the key to be updated
 * @param size size of the packet to be counted
 *
 * @throws none
 */
static inline void update_val(statkey *key, size_t size) {
  // lookup value in hash
  statvalue *val = (statvalue *)bpf_map_lookup_elem(&pkt_count, key);
  if (val) {
    // atomic XADD, doesn't need bpf_spin_lock()
    __sync_fetch_and_add(&val->packets, 1);
    __sync_fetch_and_add(&val->bytes, size);
  } else {
    statvalue initval = {.packets = 1, .bytes = size};

    bpf_map_update_elem(&pkt_count, key, &initval, BPF_NOEXIST);
  }
}

/**
 * Hook function for kprobe on tcp_sendmsg function.
 *
 * Populates the statkey structure with information from the socket and the
 * process ID associated with the socket, and updates the packet and byte
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

  process_tcp(sk, &key, pid);
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

  process_tcp(sk, &key, pid);
  update_val(&key, copied);

  return 0;
}

/**
 * Hook function for kprobe on ip_send_skb function.
 *
 * Populates the statkey structure with information from the UDP packet and the
 * process ID associated with the packet, and updates the packet and byte
 * counters in the packet count map.
 *
 * @param net pointer to the network namespace
 * @param skb pointer to the socket buffer containing the UDP packet
 *
 * @return 0
 *
 * @throws none
 */
SEC("kprobe/ip_send_skb")
int BPF_KPROBE(ip_send_skb, struct net *net, struct sk_buff *skb) {
  __u16 protocol = BPF_CORE_READ(skb, protocol);
  if (protocol != IPPROTO_UDP) {
    return 0;
  }

  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  pid_t pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

  size_t msglen = process_udp_send(skb, &key, pid);
  update_val(&key, msglen);

  return 0;
}

/**
 * Hook function for kprobe on skb_consume_udp function.
 *
 * Populates the statkey structure with information from the UDP packet and the
 * process ID associated with the packet, and updates the packet and byte
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
  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  pid_t pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

  process_udp_recv(skb, &key, pid);
  update_val(&key, len);

  return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
