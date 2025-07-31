// @license
// Copyright (C) 2025  Dinko Korunic
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
	"errors"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
)

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

// startCgroup attaches eBPF programs to a specified cgroup for monitoring and control of socket
// creation and packet ingress/egress.
//
// This function checks if the CGroupSKB program type is supported by the kernel. If supported,
// it attaches the provided eBPF programs to the specified cgroup path, facilitating monitoring
// of socket creation and ingress/egress traffic within the cgroup.
//
// Parameters:
//
//	objs counterObjects: Contains the eBPF programs, including those for socket creation and
//	                     ingress/egress packet handling.
//	cgroupPath string: The filesystem path to the target cgroup where the eBPF programs will be
//	                   attached.
//	links []link.Link: A slice of existing link.Link objects, to which the newly attached cgroup
//	                   links will be appended.
//
// Returns:
//
//	[]link.Link: The updated slice of link.Link objects, now including the newly attached cgroup
//	             links.
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

	links = append(links, l)

	l, err = link.AttachCgroup(link.CgroupOptions{
		Program: objs.CgroupSkbIngress,
		Attach:  ebpf.AttachCGroupInetIngress,
		Path:    cgroupPath,
	})
	if err != nil {
		log.Fatalf("Error attaching CgroupSkbIngress to %s: %v", cgroupPath, err)
	}

	links = append(links, l)

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

// startCGroupTrace attaches a raw tracepoint eBPF program to a kernel tracepoint.
//
// This function checks if the RawTracepoint program type is supported by the kernel.
// If supported, it attaches the TraceCgroupMkdir eBPF program to the "cgroup_mkdir" tracepoint.
//
// Parameters:
//
//	objs cgroupObjects: Contains the eBPF programs, including the TraceCgroupMkdir program to be attached.
//	links []link.Link: A slice of existing link.Link objects to which the newly attached tracepoint link will be appended.
//
// Returns:
//
//	[]link.Link: The updated slice of link.Link objects, now including the newly attached tracepoint link.
func startCGroupTrace(objs cgroupObjects, links []link.Link) []link.Link {
	var l link.Link

	err := features.HaveProgramType(ebpf.RawTracepoint)
	if errors.Is(err, ebpf.ErrNotSupported) {
		log.Printf("RawTracepoint not supported on this kernel")

		return links
	}

	l, err = link.AttachRawTracepoint(link.RawTracepointOptions{
		Program: objs.TraceCgroupMkdir,
		Name:    "cgroup_mkdir",
	})
	if err != nil {
		log.Fatalf("Error attaching TraceCgroupMkdirSignal: %v", err)
	}

	links = append(links, l)

	return links
}
