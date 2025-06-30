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
#define MAX_IPS 30
#define MAX_ALIASES 5

#define s6_addr in6_u.u6_addr8
#define s6_addr16 in6_u.u6_addr16
#define s6_addr32 in6_u.u6_addr32
#define inet_num sk.__sk_common.skc_num

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define TC_ACT_UNSPEC -1
#define AF_INET 2
#define AF_INET6 10
#define TASK_COMM_LEN 16
#define IPPROTO_ICMPV6 58

#define OK 1
#define NOK 0
#define ALLOW_PKT 1
#define ALLOW_SK 1

// Map key struct for IP traffic
typedef struct statkey_t {
  struct in6_addr srcip;    // source IPv6 address
  struct in6_addr dstip;    // destination IPv6 address
  __u16 src_port;           // source port
  __u16 dst_port;           // destination port
  __u8 proto;               // transport protocol
  pid_t pid;                // process ID
  char comm[TASK_COMM_LEN]; // process command
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

typedef struct sockinfo_t {
  __u8 comm[TASK_COMM_LEN];
  pid_t pid;
} sockinfo;

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, __u64);
  __type(value, sockinfo);
} sock_info SEC(".maps");

// IPv4-mapped IPv6 address prefix (for V4MAPPED conversion)
static const __u8 ip4in6[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

// DNS lookup event structure
typedef struct dns_lookup_event_t {
  __u32 addr_type;          // Address type (AF_INET or AF_INET6)
  __u8 ip[16];              // IP address (v4 or v6)
  char host[252];           // Hostname
  pid_t pid;                // Process ID
  char comm[TASK_COMM_LEN]; // Process command name
} dns_lookup_event;

// Structure to temporarily store getaddrinfo arguments
typedef struct addrinfo_args_cache_t {
  __u64 addrinfo_ptr; // Use a u64 instead of a double pointer
  char node[256];
  pid_t pid;
  char comm[TASK_COMM_LEN];
} addrinfo_args_cache;

// Map to store DNS lookup events
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} dns_events SEC(".maps");

// Map to temporarily store getaddrinfo arguments
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 256);
  __type(key, __u32); // thread ID
  __type(value, addrinfo_args_cache);
} addrinfo_args_hash SEC(".maps");

// Per-CPU array for storing large structures to avoid stack limits
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries,
         2); // Only need 2 slots: one for main event, one for alias
  __type(key, __u32);
  __type(value, dns_lookup_event);
} dns_lookup_heap SEC(".maps");

// Structs needed for uprobes
struct hostent {
  char *h_name;       // Official name of host
  char **h_aliases;   // Alias list
  int h_addrtype;     // Host address type
  int h_length;       // Length of address
  char **h_addr_list; // List of addresses
};

struct addrinfo {
  int ai_flags;             // Input flags
  int ai_family;            // Protocol family for socket
  int ai_socktype;          // Socket type
  int ai_protocol;          // Protocol for socket
  __u64 ai_addrlen;         // Length of socket address
  struct sockaddr *ai_addr; // Socket address for socket
  char *ai_canonname;       // Canonical name for service location
  struct addrinfo *ai_next; // Pointer to next in list
};

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

    break;
  }
  case IPPROTO_UDP: {
    struct udphdr *udp = (void *)ip4 + sizeof(*ip4);

    // validate UDP size
    if ((void *)udp + sizeof(*udp) > data_end) {
      return NOK;
    }

    key->src_port = bpf_ntohs(udp->source);
    key->dst_port = bpf_ntohs(udp->dest);

    break;
  }
  case IPPROTO_ICMP: {
    struct icmphdr *icmp = (void *)ip4 + sizeof(*ip4);

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

    break;
  }
  case IPPROTO_UDP: {
    struct udphdr *udp = (void *)ip6 + sizeof(*ip6);

    // validate UDP size
    if ((void *)udp + sizeof(*udp) > data_end) {
      return NOK;
    }

    key->src_port = bpf_ntohs(udp->source);
    key->dst_port = bpf_ntohs(udp->dest);

    break;
  }
  case IPPROTO_ICMPV6: {
    struct icmp6hdr *icmp = (void *)ip6 + sizeof(*ip6);

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
static inline void process_eth(void *data, void *data_end, __u64 pkt_len) {
  struct ethhdr *eth = data;

  // validate Ethernet size
  if ((void *)eth + sizeof(*eth) > data_end) {
    // size validation failure
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
    // wrong packet type
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
 * Process a socket buffer and extract relevant information to populate the key.
 *
 * @param skb pointer to the socket buffer
 *
 * @return none
 *
 * @throws none
 *
 * This function is called by the BPF program for each socket buffer received.
 * It extracts relevant information from the socket buffer (PID, command name,
 * src/dst IP, src/dst port, protocol) and stores it in the key. It then looks
 * up the value in the packet count hash and increments the packet count and
 * byte count if the key is found. If the key is not found, it creates a new
 * entry with the packet count and byte count set to 1.
 */
static inline void process_cgroup_skb(struct __sk_buff *skb) {
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
    // wrong packet type
    return;
  }

  __u64 cookie = bpf_get_socket_cookie(skb);
  sockinfo *ski = bpf_map_lookup_elem(&sock_info, &cookie);
  if (ski) {
    key.pid = ski->pid;
    __builtin_memcpy(key.comm, ski->comm, sizeof(key.comm));
  }

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
      .pid = bpf_get_current_pid_tgid(),
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

/**
 * Process TCP socket information and populate the key structure with
 * extracted data.
 *
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
 * type set to UDP and the associated process ID.
 *
 * @throws none
 */
static inline void process_udp_recv(struct sk_buff *skb, statkey *key,
                                    pid_t pid) {
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
    key->srcip.s6_addr16[5] = bpf_htons(0xffff);
    __builtin_memcpy(&key->srcip.s6_addr32[3], &ip4_src, sizeof(ip4_src));

    // convert to V4MAPPED address
    __be32 ip4_dst = BPF_CORE_READ(iphdr, daddr);
    key->dstip.s6_addr16[5] = bpf_htons(0xffff);
    __builtin_memcpy(&key->dstip.s6_addr32[3], &ip4_dst, sizeof(ip4_dst));
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
    return;
  }

  key->src_port = bpf_ntohs(BPF_CORE_READ(udphdr, source));
  key->dst_port = bpf_ntohs(BPF_CORE_READ(udphdr, dest));

  key->proto = IPPROTO_UDP;
  key->pid = pid;
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
static inline size_t process_icmp4(struct sk_buff *skb, statkey *key,
                                   pid_t pid) {
  struct icmphdr *icmphdr =
      (struct icmphdr *)(BPF_CORE_READ(skb, head) +
                         BPF_CORE_READ(skb, transport_header));
  struct iphdr *iphdr = (struct iphdr *)(BPF_CORE_READ(skb, head) +
                                         BPF_CORE_READ(skb, network_header));

  // convert to V4MAPPED address
  __be32 ip4_src = BPF_CORE_READ(iphdr, saddr);
  key->srcip.s6_addr16[5] = bpf_htons(0xffff);
  __builtin_memcpy(&key->srcip.s6_addr32[3], &ip4_src, sizeof(ip4_src));

  // convert to V4MAPPED address
  __be32 ip4_dst = BPF_CORE_READ(iphdr, daddr);
  key->dstip.s6_addr16[5] = bpf_htons(0xffff);
  __builtin_memcpy(&key->dstip.s6_addr32[3], &ip4_dst, sizeof(ip4_dst));

  // store ICMP type in src port
  key->src_port = BPF_CORE_READ(icmphdr, type);
  // store ICMP code in dst port
  key->dst_port = BPF_CORE_READ(icmphdr, code);

  key->proto = IPPROTO_ICMP;
  key->pid = pid;

  size_t msglen = bpf_ntohs(BPF_CORE_READ(iphdr, tot_len)) -
                  BPF_CORE_READ_BITFIELD_PROBED(iphdr, ihl) * 4;

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

static inline size_t process_icmp6(struct sk_buff *skb, statkey *key,
                                   pid_t pid) {
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
static inline size_t process_udp_send(struct sk_buff *skb, statkey *key,
                                      pid_t pid) {
  struct udphdr *udphdr =
      (struct udphdr *)(BPF_CORE_READ(skb, head) +
                        BPF_CORE_READ(skb, transport_header));

  process_udp_recv(skb, key, pid);
  size_t msglen = BPF_CORE_READ(udphdr, len);

  return msglen;
}

#if 0
/**
 * Process raw ICMP socket information for IPv4 and populate the key structure.
 *
 * @param sk pointer to the socket structure
 * @param msg pointer to the message header structure containing the packet
 * @param key pointer to the statkey structure to be populated
 * @param pid process ID associated with the packet
 *
 * This function extracts source and destination IPv4 addresses and ICMP type
 * and code from the raw socket message. It populates the provided statkey
 * structure with these details, converting IPv4 addresses to IPv6-mapped
 * format. The function only processes messages with the ICMP protocol.
 *
 * @throws none
 */

static inline void process_raw_sendmsg4(struct sock *sk, struct msghdr *msg,
                                        statkey *key, pid_t pid) {
  struct inet_sock *isk = (struct inet_sock *)sk;
  struct sockaddr_in *sin = (struct sockaddr_in *)BPF_CORE_READ(msg, msg_name);

  // raw sockets have the protocol number in inet_num
  __u16 proto = BPF_CORE_READ(isk, inet_num);
  if (proto != IPPROTO_ICMP) {
    return;
  }

  // convert to V4MAPPED address
  __be32 ip4_src = BPF_CORE_READ(isk, inet_saddr);
  key->srcip.s6_addr16[5] = bpf_htons(0xffff);
  __builtin_memcpy(&key->srcip.s6_addr32[3], &ip4_src, sizeof(ip4_src));

  // convert to V4MAPPED address
  __be32 ip4_dst = BPF_CORE_READ(sin, sin_addr.s_addr);
  key->dstip.s6_addr16[5] = bpf_htons(0xffff);
  __builtin_memcpy(&key->dstip.s6_addr32[3], &ip4_dst, sizeof(ip4_dst));

  struct iovec *iov = (struct iovec *)BPF_CORE_READ(msg, msg_iter.__iov);
  struct icmphdr *icmphdr = (struct icmphdr *)BPF_CORE_READ(iov, iov_base);

  // store ICMP type in src port
  key->src_port = BPF_CORE_READ(icmphdr, type);
  // store ICMP code in dst port
  key->dst_port = BPF_CORE_READ(icmphdr, code);

  key->proto = IPPROTO_ICMP;
  key->pid = pid;
}
#endif

#if 0
/**
 * Process raw ICMP socket information for IPv6 and populate the key structure.
 *
 * @param sk pointer to the socket structure
 * @param msg pointer to the message header structure containing the packet
 * @param key pointer to the statkey structure to be populated
 * @param pid process ID associated with the packet
 *
 * This function extracts source and destination IPv6 addresses and ICMPv6 type
 * and code from the raw socket message. It populates the provided statkey
 * structure with these details. The function only processes messages with the
 * ICMPv6 protocol.
 *
 * @throws none
 */

static inline void process_raw_sendmsg6(struct sock *sk, struct msghdr *msg,
                                        statkey *key, pid_t pid) {
  struct inet_sock *isk = (struct inet_sock *)sk;
  struct sockaddr_in6 *sin =
      (struct sockaddr_in6 *)BPF_CORE_READ(msg, msg_name);

  // raw sockets have the protocol number in inet_num
  __u16 proto = BPF_CORE_READ(isk, inet_num);
  if (proto != IPPROTO_ICMPV6) {
    return;
  }

  BPF_CORE_READ_INTO(&key->srcip, isk, inet_saddr);
  BPF_CORE_READ_INTO(&key->dstip, sin, sin6_addr);

  struct iovec *iov = (struct iovec *)BPF_CORE_READ(msg, msg_iter.__iov);
  struct icmp6hdr *icmphdr = (struct icmp6hdr *)BPF_CORE_READ(iov, iov_base);

  // store ICMP type in src port
  key->src_port = BPF_CORE_READ(icmphdr, icmp6_type);
  // store ICMP code in dst port
  key->dst_port = BPF_CORE_READ(icmphdr, icmp6_code);

  key->proto = IPPROTO_ICMPV6;
  key->pid = pid;
}
#endif

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
 * Populates the statkey structure with information from the UDP packet and
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
  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
  }

  process_tcp(sk, &key, pid);
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
  __u16 protocol = BPF_CORE_READ(skb, protocol);
  if (protocol != IPPROTO_UDP) {
    return 0;
  }

  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  pid_t pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
  }

  size_t msglen = process_udp_send(skb, &key, pid);
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
  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  pid_t pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
  }

  process_udp_recv(skb, &key, pid);
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

  size_t msglen = process_icmp4(skb, &key, pid);
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

  size_t msglen = process_icmp6(skb, &key, pid);
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

  size_t msglen = process_icmp4(skb, &key, pid);
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

  size_t msglen = process_icmp6(skb, &key, pid);
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
  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
  }

  process_raw_sendmsg4(sk, msg, &key, pid);
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
  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
  }

  process_raw_sendmsg6(sk, msg, &key, pid);
  update_val(&key, len);

  return 0;
}
#endif

/**
 * Hook function for kprobe on ip_local_out function.
 *
 * Intercepts packets at the start of local packet transmission
 * in the networking stack.
 *
 * @param skb pointer to the socket buffer
 * @param net pointer to the network namespace
 *
 * @return 0
 *
 * @throws none
 */
SEC("kprobe/ip_local_out")
int BPF_KPROBE(ip_local_out_fn, struct sk_buff *skb, struct net *net) {
  if (!skb)
    return 0;

  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  // Record process information
  pid_t pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
    key.pid = pid;
  }

  // Get packet size
  __u64 len = BPF_CORE_READ(skb, len);

  // Try to extract socket information if available
  struct sock *sk = BPF_CORE_READ(skb, sk);
  if (sk) {
    // Let's use the safer process_tcp function which already works in existing
    // kprobes
    process_tcp(sk, &key, pid);
    update_val(&key, len);
    return 0;
  }

  // Update with the basic information we have
  update_val(&key, len);
  return 0;
}

/**
 * Hook function for kprobe on ip_output function.
 *
 * Intercepts packets at the output stage of the IP stack,
 * which comes after ip_local_out.
 *
 * @param net pointer to the network namespace
 * @param sk pointer to the socket structure
 * @param skb pointer to the socket buffer
 *
 * @return 0
 *
 * @throws none
 */
SEC("kprobe/ip_output")
int BPF_KPROBE(ip_output_fn, struct net *net, struct sock *sk,
               struct sk_buff *skb) {
  if (!skb)
    return 0;

  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  // Record process information
  pid_t pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
    key.pid = pid;
  }

  // Get packet size
  __u64 len = BPF_CORE_READ(skb, len);

  // If we have a valid socket, use the established safe method
  if (sk) {
    // Use the existing process_tcp function which already works in other
    // kprobes
    process_tcp(sk, &key, pid);
    update_val(&key, len);
    return 0;
  }

  // Update with the basic information we have
  update_val(&key, len);
  return 0;
}

/**
 * Hook for getaddrinfo() calls to get DNS lookup events.
 */
SEC("uprobe/getaddrinfo")
int uprobe__getaddrinfo(struct pt_regs *ctx) {
  dns_lookup_event *data;

  data = bpf_ringbuf_reserve(&dns_events, sizeof(dns_lookup_event), 0);
  if (!data) {
    return 0;
  }

  data->pid = bpf_get_current_pid_tgid() >> 32;
  bpf_get_current_comm(&data->comm, sizeof(data->comm));

  bpf_probe_read_user_str(&data->host, sizeof(data->host),
                          (char *)PT_REGS_PARM1(ctx));

  bpf_ringbuf_submit(data, 0);

  return 0;
}

/**
 * Hook for gethostbyname() library call to capture DNS lookup events.
 */
SEC("uprobe/gethostbyname")
int uprobe__gethostbyname(struct pt_regs *ctx) {
  // Create a DNS lookup event
  dns_lookup_event data = {0};

  // Get process information and fill in command name
  u64 pid_tgid = bpf_get_current_pid_tgid();
  data.pid = pid_tgid >> 32; // Extract PID from pid_tgid
  bpf_get_current_comm(&data.comm, sizeof(data.comm)); // Get command name

  // Mark this as a pre-resolution event
  data.addr_type = 0;

  // Get the hostname from the first parameter
  char *hostname = (char *)PT_REGS_PARM1(ctx);
  if (!hostname) {
    return 0;
  }

  // Read the hostname into our event structure
  bpf_probe_read_user_str(&data.host, sizeof(data.host), hostname);

  // Output the event to the ring buffer
  bpf_ringbuf_output(&dns_events, &data, sizeof(data), 0);

  return 0;
}

/**
 * Hook for gethostbyname2() library call to capture DNS lookup events.
 */
SEC("uprobe/gethostbyname2")
int uprobe__gethostbyname2(struct pt_regs *ctx) {
  // Create a DNS lookup event
  dns_lookup_event data = {0};

  // Get process information and fill in command name
  u64 pid_tgid = bpf_get_current_pid_tgid();
  data.pid = pid_tgid >> 32; // Extract PID from pid_tgid
  bpf_get_current_comm(&data.comm, sizeof(data.comm)); // Get command name

  // Mark this as a pre-resolution event
  data.addr_type = 0;

  // Get the hostname from the first parameter (same as gethostbyname)
  char *hostname = (char *)PT_REGS_PARM1(ctx);
  if (!hostname) {
    return 0;
  }

  // Read the hostname into our event structure
  bpf_probe_read_user_str(&data.host, sizeof(data.host), hostname);

  // Output the event to the ring buffer
  bpf_ringbuf_output(&dns_events, &data, sizeof(data), 0);

  return 0;
}

/**
 * Hook for gethostbyname_r() library call to capture DNS lookup events.
 */
SEC("uprobe/gethostbyname_r")
int uprobe__gethostbyname_r(struct pt_regs *ctx) {
  // Create a DNS lookup event
  dns_lookup_event data = {0};

  // Get process information and fill in command name
  u64 pid_tgid = bpf_get_current_pid_tgid();
  data.pid = pid_tgid >> 32; // Extract PID from pid_tgid
  bpf_get_current_comm(&data.comm, sizeof(data.comm)); // Get command name

  // Mark this as a pre-resolution event
  data.addr_type = 0;

  // Get the hostname from the first parameter (same as gethostbyname)
  char *hostname = (char *)PT_REGS_PARM1(ctx);
  if (!hostname) {
    return 0;
  }

  // Read the hostname into our event structure
  bpf_probe_read_user_str(&data.host, sizeof(data.host), hostname);

  // Output the event to the ring buffer
  bpf_ringbuf_output(&dns_events, &data, sizeof(data), 0);

  return 0;
}

char __license[] SEC("license") = "GPL";
