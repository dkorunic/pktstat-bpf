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
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

var (
	GitTag    = ""
	GitCommit = ""
	GitDirty  = ""
	BuildTime = ""
)

//nolint:gochecknoinits
func init() {
	GitTag = strings.TrimSpace(GitTag)
	GitCommit = strings.TrimSpace(GitCommit)
	GitDirty = strings.TrimSpace(GitDirty)
	BuildTime = strings.TrimSpace(BuildTime)
}

func main() {
	parseFags()

	// Remove resource limits for kernels <5.11
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Error removing memlock: %v", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel
	var objs counterObjects
	if err := loadCounterObjects(&objs, nil); err != nil {
		log.Fatalf("Error loading eBPF objects: %v", err)
	}
	defer objs.Close()

	iface, err := net.InterfaceByName(*ifname)
	if err != nil {
		log.Fatalf("Error getting interface %q: %v", *ifname, err) //nolint:gocritic
	}

	var linkIngress, linkEgress link.Link

	if *useXDP {
		err = features.HaveProgramType(ebpf.XDP)
		if errors.Is(err, ebpf.ErrNotSupported) {
			log.Fatalf("XDP not supported on this kernel")
		}

		if err != nil {
			log.Fatalf("Error checking XDP support: %v", err)
		}

		// Attach count_packets to the network interface ingress, uses BPF_XDP
		// NOTE: no egress support yet for BPF_XDP path
		// NOTE: BPF_LINK_CREATE for XDP requires v5.9 kernel, but might work with older RHEL kernels
		linkIngress, err = link.AttachXDP(link.XDPOptions{
			Program:   objs.XdpCountPackets,
			Interface: iface.Index,
			Flags:     xdpAttachFlags,
		})
		if err != nil {
			log.Fatalf("Error attaching %q XDP ingress: %v", *ifname, err)
		}
	} else {
		err = features.HaveProgramType(ebpf.SchedACT)
		if errors.Is(err, ebpf.ErrNotSupported) {
			log.Fatalf("SchedACT not supported on this kernel")
		}

		if err != nil {
			log.Fatalf("Error checking SchedACT support: %v", err)
		}

		// NOTE: BPF_TCX_INGRESS and BPF_TCX_EGRESS require v6.6 kernel
		// Attach count_packets to the network interface ingress, uses BPF_TCX_INGRESS
		linkIngress, err = link.AttachTCX(link.TCXOptions{
			Program:   objs.TcCountPackets,
			Attach:    ebpf.AttachTCXIngress,
			Interface: iface.Index,
		})
		if err != nil {
			log.Fatalf("Error attaching %q TCX ingress: %v", *ifname, err)
		}

		// Attach count_packets to the network interface egresss, uses BPF_TCX_EGRESS
		linkEgress, err = link.AttachTCX(link.TCXOptions{
			Program:   objs.TcCountPackets,
			Attach:    ebpf.AttachTCXEgress,
			Interface: iface.Index,
		})
		if err != nil {
			log.Fatalf("Error attaching %q TCX egress: %v", *ifname, err)
		}
	}

	defer func() {
		if linkIngress != nil {
			linkIngress.Close()
		}

		if linkEgress != nil {
			linkEgress.Close()
		}
	}()

	if *useXDP {
		log.Printf("Starting on interface %q using XDP (eXpress Data Path) eBPF mode", *ifname)
		log.Printf("Due to XDP mode, egress statistics are not available. Upon program exit, interface reset is possible.")
	} else {
		log.Printf("Starting on interface %q using TC (Traffic Control) eBPF mode", *ifname)
	}

	c1, cancel := context.WithCancel(context.Background())
	defer cancel()

	startTime := time.Now()

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		s := <-signalCh
		fmt.Fprintf(os.Stderr, "Received %v signal, trying to exit...\n", s)
		cancel()
	}()

	if *timeout > 0 {
		go func() {
			time.Sleep(*timeout)
			cancel()
		}()
	}

	<-c1.Done()

	m, err := processMap(objs.PktCount, startTime)
	if err != nil {
		log.Fatalf("Error reading eBPF map: %v", err)
	}

	if *jsonOutput {
		outputJSON(m)
	} else {
		outputPlain(m)
	}
}
