// @license
// Copyright (C) 2024  Dinko Korunic
//
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/peterbourgon/ff/v4"
	"github.com/peterbourgon/ff/v4/ffhelp"
)

const (
	defaultIface                          = "eth0"
	defaultTimeout                        = 10 * time.Minute
	defaultRefresh                        = 1 * time.Second
	defaultXDPMode                        = "auto"
	XDPAttachModeNone link.XDPAttachFlags = 0
)

var (
	ifname, xdpMode, useCGroup                                      *string
	jsonOutput, version, help, useXDP, useKProbes, enableTUI, noARP *bool
	timeout, refresh                                                *time.Duration
	maxEntries                                                      *uint
	xdpAttachFlags                                                  link.XDPAttachFlags
)

func parseFlags() {
	fs := ff.NewFlagSet("pktstat-bpf")

	help = fs.Bool('?', "help", "display help")
	jsonOutput = fs.Bool('j', "json", "if true, output in JSON format")
	useCGroup = fs.String('c', "cgroup", "", "the path to a CGroup V2 to measure statistics on")
	useXDP = fs.Bool('x', "xdp", "if true, use XDP instead of TC (this disables egress statistics)")
	useKProbes = fs.Bool('k', "kprobes", "if true, use KProbes for per-process TCP/UDP statistics")
	enableTUI = fs.Bool('g', "tui", "if true, enable TUI")

	version = fs.BoolLong("version", "display program version")

	ifname = fs.String('i', "iface", findFirstEtherIface(), "interface to read from")
	xdpMode = fs.StringLong("xdp_mode", defaultXDPMode, "XDP attach mode (auto, generic, native or offload; native and offload require NIC driver support)")

	refresh = fs.Duration('r', "refresh", defaultRefresh, "refresh interval in TUI")
	timeout = fs.Duration('t', "timeout", defaultTimeout, "timeout for packet capture in CLI")

	maxEntries = fs.UintLong("max-entries", 0, "override pkt_count map max_entries (0 = compile-time default)")
	noARP = fs.BoolLong("no-arp", "disable ARP capture in TC/XDP modes (skips parse_arp dispatch)")

	var err error

	if err = ff.Parse(fs, os.Args[1:]); err != nil {
		fmt.Printf("%s\n", ffhelp.Flags(fs))
		fmt.Printf("Error: %v\n", err)

		os.Exit(1)
	}

	if *help {
		fmt.Printf("%s\n", ffhelp.Flags(fs))

		os.Exit(0)
	}

	if *version {
		fmt.Printf("pktstat-bpf %v %v%v, built on: %v\n", GitTag, GitCommit, GitDirty, BuildTime)

		os.Exit(0)
	}

	switch *xdpMode {
	case "", "auto", "best":
		// Kernel picks Native, falls back to Generic.
		xdpAttachFlags = XDPAttachModeNone
	case "generic":
		xdpAttachFlags = link.XDPGenericMode
	case "native", "driver":
		// Requires NIC driver XDP support.
		xdpAttachFlags = link.XDPDriverMode
	case "offload", "hardware":
		// Requires HW XDP support.
		xdpAttachFlags = link.XDPOffloadMode
	default:
		fmt.Printf("Error invalid XDP mode: %v, pick from: auto, generic, native or offload\n", *xdpMode)

		os.Exit(1)
	}

	if *enableTUI {
		*timeout = 0
	}
}
