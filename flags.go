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
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

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
	defaultXDPMode                        = "auto"
	XDPAttachModeNone link.XDPAttachFlags = 0
)

var (
	ifname, xdpMode                               *string
	jsonOutput, version, help, useXDP, useKprobes *bool
	timeout                                       *time.Duration
	xdpAttachFlags                                link.XDPAttachFlags
)

func parseFags() {
	fs := ff.NewFlagSet("pktstat-bpf")

	help = fs.Bool('?', "help", "display help")
	jsonOutput = fs.Bool('j', "json", "if true, output in JSON format")
	useXDP = fs.Bool('x', "xdp", "if true, use XDP instead of TC (this disables egress statistics)")
	useKprobes = fs.Bool('k', "kprobes", "if true, use kprobes for per-proces TCP/UDP statistics")

	version = fs.BoolLong("version", "display program version")

	ifname = fs.String('i', "iface", findFirstEtherIface(), "interface to read from")
	xdpMode = fs.StringLong("xdp_mode", defaultXDPMode, "XDP attach mode (auto, generic, native or offload; native and offload require NIC driver support)")

	timeout = fs.Duration('t', "timeout", defaultTimeout, "timeout for packet capture")

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
		// kernel will select the best mode starting with Native and fallback to Generic
		xdpAttachFlags = XDPAttachModeNone
	case "generic":
		// SKB generic XDP mode
		xdpAttachFlags = link.XDPGenericMode
	case "native", "driver":
		// XDP support from NIC driver required
		xdpAttachFlags = link.XDPDriverMode
	case "offload", "hardware":
		// only for NICs with HW XDP support
		xdpAttachFlags = link.XDPOffloadMode
	default:
		fmt.Printf("Error invalid XDP mode: %v, pick from: auto, generic, native or offload\n", *xdpMode)

		os.Exit(1)
	}
}
