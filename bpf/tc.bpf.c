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

#include "counter_common.h"

SEC("tc")
int tc_count_packets(struct __sk_buff *skb) {
  tc_process_packet(skb);

  return TC_ACT_UNSPEC;
}

char __license[] SEC("license") = "Dual MIT/GPL";
