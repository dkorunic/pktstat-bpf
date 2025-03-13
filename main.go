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
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/hako/durafmt"
)

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
	defer func() { _ = objs.Close() }()

	iface, err := net.InterfaceByName(*ifname)
	if err != nil {
		log.Fatalf("Error getting interface %q: %v", *ifname, err) //nolint:gocritic
	}

	var links []link.Link

	defer func() {
		for _, l := range links {
			_ = l.Close()
		}
	}()

	switch {
	case *useCGroup != "":
		links = startCgroup(objs, *useCGroup, links)
	// KProbes w/ PID tracking
	case *useKProbes:
		hooks := []kprobeHook{
			{kprobe: "tcp_sendmsg", prog: objs.TcpSendmsg},
			{kprobe: "tcp_cleanup_rbuf", prog: objs.TcpCleanupRbuf},
			{kprobe: "ip_send_skb", prog: objs.IpSendSkb},
			{kprobe: "skb_consume_udp", prog: objs.SkbConsumeUdp},
			{kprobe: "__icmp_send", prog: objs.IcmpSend},
			{kprobe: "icmp6_send", prog: objs.Icmp6Send},
			{kprobe: "icmp_rcv", prog: objs.IcmpRcv},
			{kprobe: "icmpv6_rcv", prog: objs.Icmpv6Rcv},
		}

		links = startKProbes(hooks, links)
	// XDP
	case *useXDP:
		links = startXDP(objs, iface, links)
	// TC
	default:
		links = startTC(objs, iface, links)
	}

	c1, cancel := context.WithCancel(context.Background())
	defer cancel()

	startTime := time.Now()

	if *enableTUI {
		drawTUI(objs, startTime)
	} else {
		signalCh := make(chan os.Signal, 1)
		signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

		go func() {
			s := <-signalCh
			_, _ = fmt.Fprintf(os.Stderr, "Received %v signal, trying to exit...\n", s)
			cancel()
		}()

		if *timeout > 0 {
			log.Printf("Listening for %v before exiting", durafmt.Parse(*timeout))

			go func() {
				time.Sleep(*timeout)
				cancel()
			}()
		}

		<-c1.Done()

		m, err := processMap(objs.PktCount, startTime, bitrateSort)
		if err != nil {
			log.Fatalf("Error reading eBPF map: %v", err)
		}

		if *jsonOutput {
			fmt.Println(outputJSON(m))
		} else {
			fmt.Printf(outputPlain(m))
		}
	}
}

// startKProbes attaches a series of eBPF programs to kernel functions using KProbes.
//
// This function iterates over a slice of kprobeHook structs, each containing a kernel function
// name (kprobe) and an associated eBPF program. It attempts to attach each eBPF program to its
// respective kernel function using KProbes. If a Kprobe cannot be attached, an error message
// is logged, but the function continues with the next Kprobe.
//
// The function first checks if KProbes are supported by the current kernel. If not supported,
// it logs a fatal error and terminates the program.
//
// Parameters:
//
//	hooks []kprobeHook: A slice of kprobeHook structs, where each struct contains a kernel
//	function name and an associated eBPF program.
//
//	links []link.Link: A slice of link.Link objects to which successfully attached KProbes
//	are appended.
//
// Returns:
//
//	[]link.Link: The updated slice of link.Link objects, including any newly attached KProbes.
func startKProbes(hooks []kprobeHook, links []link.Link) []link.Link {
	var l link.Link

	err := features.HaveProgramType(ebpf.Kprobe)
	if errors.Is(err, ebpf.ErrNotSupported) {
		log.Fatalf("KProbes are not supported on this kernel")
	}

	if err != nil {
		log.Fatalf("Error checking KProbes support: %v", err)
	}

	for _, kp := range hooks {
		l, err = link.Kprobe(kp.kprobe, kp.prog, nil)
		if err != nil {
			log.Printf("Unable to attach %q KProbe: %v", kp.kprobe, err)

			continue
		}

		links = append(links, l)
	}

	log.Printf("Using KProbes mode w/ PID/comm tracking")

	return links
}

// startXDP attaches an eBPF XDP program to a network interface for packet counting.
//
// This function checks if the XDP program type is supported by the kernel. If supported,
// it attaches the XDP program to the specified network interface's ingress path. Note that
// egress support is not available for XDP, and the function requires at least a v5.9 kernel
// for BPF_LINK_CREATE, though it might work with older RHEL kernels.
//
// Parameters:
//
//	objs counterObjects: Contains the eBPF programs, including the XDP program to be attached.
//	iface *net.Interface: The network interface to which the XDP program should be attached.
//	links []link.Link: A slice of existing link.Link objects to which the newly attached XDP link
//	                    will be appended.
//
// Returns:
//
//	[]link.Link: The updated slice of link.Link objects, now including the newly attached XDP link.
func startXDP(objs counterObjects, iface *net.Interface, links []link.Link) []link.Link {
	var l link.Link

	err := features.HaveProgramType(ebpf.XDP)
	if errors.Is(err, ebpf.ErrNotSupported) {
		log.Fatalf("XDP not supported on this kernel")
	}

	if err != nil {
		log.Fatalf("Error checking XDP support: %v", err)
	}

	// Attach count_packets to the network interface ingress, uses BPF_XDP
	// NOTE: no egress support yet for BPF_XDP path
	// NOTE: BPF_LINK_CREATE for XDP requires v5.9 kernel, but might work with older RHEL kernels
	l, err = link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpCountPackets,
		Interface: iface.Index,
		Flags:     xdpAttachFlags,
	})
	if err != nil {
		log.Fatalf("Error attaching %q XDP ingress: %v", *ifname, err)
	}

	links = append(links, l)

	log.Printf("Starting on interface %q using XDP (eXpress Data Path) eBPF mode", *ifname)
	log.Printf("Due to XDP mode, egress statistics are not available. Upon program exit, interface reset may happen on some cards.")

	return links
}

// startTC attaches an eBPF program to a network interface for packet counting using
// the Traffic Control (TC) eBPF mode. The function checks if the TC eBPF mode is
// supported by the kernel. If supported, it attaches the program to both the ingress
// and egress paths of the specified network interface. Note that TC eBPF mode requires
// at least a v6.6 kernel.
//
// Parameters:
//
//	objs counterObjects: Contains the eBPF programs, including the TC program to be
//	                      attached.
//	iface *net.Interface: The network interface to which the TC program should be
//	                      attached.
//	links []link.Link: A slice of existing link.Link objects to which the newly
//	                    attached TC links will be appended.
//
// Returns:
//
//	[]link.Link: The updated slice of link.Link objects, now including the newly
//	             attached TC links.
func startTC(objs counterObjects, iface *net.Interface, links []link.Link) []link.Link {
	var l link.Link

	err := features.HaveProgramType(ebpf.SchedACT)
	if errors.Is(err, ebpf.ErrNotSupported) {
		log.Fatalf("SchedACT not supported on this kernel")
	}

	if err != nil {
		log.Fatalf("Error checking SchedACT support: %v", err)
	}

	// NOTE: BPF_TCX_INGRESS and BPF_TCX_EGRESS require v6.6 kernel
	// Attach count_packets to the network interface ingress, uses BPF_TCX_INGRESS
	l, err = link.AttachTCX(link.TCXOptions{
		Program:   objs.TcCountPackets,
		Attach:    ebpf.AttachTCXIngress,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("Error attaching %q TCX ingress: %v", *ifname, err)
	}

	links = append(links, l)

	// Attach count_packets to the network interface egresss, uses BPF_TCX_EGRESS
	l, err = link.AttachTCX(link.TCXOptions{
		Program:   objs.TcCountPackets,
		Attach:    ebpf.AttachTCXEgress,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("Error attaching %q TCX egress: %v", *ifname, err)
	}

	links = append(links, l)

	log.Printf("Starting on interface %q using TC (Traffic Control) eBPF mode", *ifname)

	return links
}

func startCgroup(objs counterObjects, cgroupPath string, links []link.Link) []link.Link {
	var l link.Link

	err := features.HaveProgramType(ebpf.CGroupSKB)
	if errors.Is(err, ebpf.ErrNotSupported) {
		log.Fatalf("CgroupSKB not supported on this kernel")
	}

	if err != nil {
		log.Fatalf("Error checking CGroupSKB support: %v", err)
	}

	l, err = link.AttachCgroup(link.CgroupOptions{
		Program: objs.CgroupSockCreate,
		Attach:  ebpf.AttachCGroupInetSockCreate,
		Path:    cgroupPath,
	})
	if err != nil {
		log.Fatalf("Error attaching CgroupSockCreate to %s: %v", cgroupPath, err)
	}

	l, err = link.AttachCgroup(link.CgroupOptions{
		Program: objs.CgroupSkbIngress,
		Attach:  ebpf.AttachCGroupInetIngress,
		Path:    cgroupPath,
	})
	if err != nil {
		log.Fatalf("Error attaching CgroupSkbIngress to %s: %v", cgroupPath, err)
	}

	l, err = link.AttachCgroup(link.CgroupOptions{
		Program: objs.CgroupSkbEgress,
		Attach:  ebpf.AttachCGroupInetEgress,
		Path:    cgroupPath,
	})
	if err != nil {
		log.Fatalf("Error attaching CgroupSkbEgress to %s: %v", cgroupPath, err)
	}

	links = append(links, l)

	log.Printf("Starting on CGroup %s", cgroupPath)

	return links
}
