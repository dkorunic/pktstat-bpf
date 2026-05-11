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
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/hako/durafmt"
)

// main is the entry point of the program.
//
// It loads the appropriate eBPF object file on demand based on the selected
// capture mode, removes resource limits for kernels <5.11, and attaches the
// eBPF programs to the relevant hooks.
//
// The packet capture methods are:
//
//   - XDP (if *useXDP is set)
//   - TC (if *useXDP is not set, default)
//   - KProbes w/ PID tracking (if *useKProbes is set)
//   - cgroup tracing (if *useCGroup is set)
//
// After starting the packet capture method, it waits for the context to be
// canceled, and then closes all the links and prints the final statistics.
func main() {
	parseFlags()

	// Remove resource limits for kernels <5.11
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Error removing memlock: %v", err)
	}

	var links []link.Link

	defer func() {
		for _, l := range links {
			_ = l.Close()
		}
	}()

	// Warn when multiple mutually-exclusive capture modes are combined.
	// The switch below silently picks the first matching case, so the user
	// might not realise one of their flags is being ignored.
	{
		captureModes := 0

		if *useCGroup != "" {
			captureModes++
		}

		if *useKProbes {
			captureModes++
		}

		if *useXDP {
			captureModes++
		}

		if captureModes > 1 {
			log.Printf("Warning: multiple capture modes specified; precedence is --cgroup > --kprobes > --xdp > TC (default)")
		}
	}

	// pktCount is the eBPF map used to store packet statistics; it comes from
	// whichever mode-specific object is loaded below.
	var pktCount *ebpf.Map

	switch {
	case *useCGroup != "":
		// Detect cgroup fs magic once for both objects we are about to load.
		// On failure we still proceed with 0, in which case the BPF programs
		// fall back to the cgroup-v1 task-walk path.
		cgroupFsMagic, err := getCgroupFsMagic()
		if err != nil {
			log.Printf("Unable to identify cgroup fs magic: %v", err)
		}

		// Load CGroup SKB eBPF object (cgroup_sock_create + cgroup_skb hooks)
		cgroupSkbSpec, err := loadCgroupSkb()
		if err != nil {
			log.Fatalf("Error loading CGroupSKB eBPF spec: %v", err) //nolint:gocritic
		}
		if err := applyCgrpfsMagic(cgroupSkbSpec, cgroupFsMagic); err != nil {
			log.Printf("Unable to set cgrpfs_magic on CGroupSKB spec: %v", err)
		}
		applyMaxEntries(cgroupSkbSpec)

		var objsCgroupSkb cgroupSkbObjects
		if err := cgroupSkbSpec.LoadAndAssign(&objsCgroupSkb, nil); err != nil {
			log.Fatalf("Error loading CGroupSKB eBPF objects: %v", err)
		}

		defer func() { _ = objsCgroupSkb.Close() }()

		pktCount = objsCgroupSkb.PktCount

		// Load the cgroup_mkdir tracepoint object for cgroup path tracking
		cgroupSpec, err := loadCgroup()
		if err != nil {
			log.Fatalf("Error loading cgroup eBPF spec: %v", err)
		}
		if err := applyCgrpfsMagic(cgroupSpec, cgroupFsMagic); err != nil {
			log.Printf("Unable to set cgrpfs_magic on cgroup spec: %v", err)
		}

		var objsCgroup cgroupObjects
		if err := cgroupSpec.LoadAndAssign(&objsCgroup, nil); err != nil {
			log.Fatalf("Error loading cgroup eBPF objects: %v", err)
		}

		defer func() { _ = objsCgroup.Close() }()

		cGroupCacheInit()

		links = startCgroup(objsCgroupSkb, *useCGroup, links)
		links = startCGroupTrace(objsCgroup, links)

		rd, err := cGroupWatcher(objsCgroup)
		if err != nil {
			log.Printf("Error starting cgroup watcher: %v", err)
		} else {
			defer func() { _ = rd.Close() }()
		}

	// KProbes w/ PID tracking
	case *useKProbes:
		// Detect cgroup fs magic once for both objects we are about to load.
		cgroupFsMagic, err := getCgroupFsMagic()
		if err != nil {
			log.Printf("Unable to identify cgroup fs magic: %v", err)
		}

		// Load KProbe eBPF object
		kprobeSpec, err := loadKprobe()
		if err != nil {
			log.Fatalf("Error loading KProbe eBPF spec: %v", err)
		}
		if err := applyCgrpfsMagic(kprobeSpec, cgroupFsMagic); err != nil {
			log.Printf("Unable to set cgrpfs_magic on KProbe spec: %v", err)
		}
		applyMaxEntries(kprobeSpec)

		var objsKprobe kprobeObjects
		if err := kprobeSpec.LoadAndAssign(&objsKprobe, nil); err != nil {
			log.Fatalf("Error loading KProbe eBPF objects: %v", err)
		}

		defer func() { _ = objsKprobe.Close() }()

		pktCount = objsKprobe.PktCount

		// Load the cgroup_mkdir tracepoint object for cgroup path tracking
		cgroupSpec, err := loadCgroup()
		if err != nil {
			log.Fatalf("Error loading cgroup eBPF spec: %v", err)
		}
		if err := applyCgrpfsMagic(cgroupSpec, cgroupFsMagic); err != nil {
			log.Printf("Unable to set cgrpfs_magic on cgroup spec: %v", err)
		}

		var objsCgroup cgroupObjects
		if err := cgroupSpec.LoadAndAssign(&objsCgroup, nil); err != nil {
			log.Fatalf("Error loading cgroup eBPF objects: %v", err)
		}

		defer func() { _ = objsCgroup.Close() }()

		hooks := []kprobeHook{
			{kprobe: "tcp_sendmsg", prog: objsKprobe.TcpSendmsg},
			{kprobe: "tcp_cleanup_rbuf", prog: objsKprobe.TcpCleanupRbuf},
			{kprobe: "tcp_retransmit_skb", prog: objsKprobe.TcpRetransmitSkb},
			{kprobe: "ip_send_skb", prog: objsKprobe.IpSendSkb},
			{kprobe: "ip6_send_skb", prog: objsKprobe.Ip6SendSkb},
			{kprobe: "skb_consume_udp", prog: objsKprobe.SkbConsumeUdp},
			{kprobe: "__icmp_send", prog: objsKprobe.IcmpSend},
			{kprobe: "icmp6_send", prog: objsKprobe.Icmp6Send},
			{kprobe: "icmp_rcv", prog: objsKprobe.IcmpRcv},
			{kprobe: "icmpv6_rcv", prog: objsKprobe.Icmpv6Rcv},
			{kprobe: "ip_local_out", prog: objsKprobe.IpLocalOut},
			{kprobe: "ip6_local_out", prog: objsKprobe.Ip6LocalOut},
			{kprobe: "ip_rcv", prog: objsKprobe.IpRcv},
			{kprobe: "ipv6_rcv", prog: objsKprobe.Ipv6Rcv},
		}

		cGroupCacheInit()

		links = startKProbes(hooks, links)
		links = startCGroupTrace(objsCgroup, links)

		rd, err := cGroupWatcher(objsCgroup)
		if err != nil {
			log.Printf("Error starting cgroup watcher: %v", err)
		} else {
			defer func() { _ = rd.Close() }()
		}

	// XDP
	case *useXDP:
		iface, err := net.InterfaceByName(*ifname)
		if err != nil {
			log.Fatalf("Error getting interface %q: %v", *ifname, err)
		}

		// Load XDP eBPF object
		xdpSpec, err := loadXdp()
		if err != nil {
			log.Fatalf("Error loading XDP eBPF spec: %v", err)
		}

		applyMaxEntries(xdpSpec)
		applyArpEnabled(xdpSpec)

		var objsXDP xdpObjects
		if err := xdpSpec.LoadAndAssign(&objsXDP, nil); err != nil {
			log.Fatalf("Error loading XDP eBPF objects: %v", err)
		}

		defer func() { _ = objsXDP.Close() }()

		pktCount = objsXDP.PktCount

		links = startXDP(objsXDP, iface, links)

	// TC (default)
	default:
		iface, err := net.InterfaceByName(*ifname)
		if err != nil {
			log.Fatalf("Error getting interface %q: %v", *ifname, err)
		}

		// Load TC eBPF object
		tcSpec, err := loadTc()
		if err != nil {
			log.Fatalf("Error loading TC eBPF spec: %v", err)
		}

		applyMaxEntries(tcSpec)
		applyArpEnabled(tcSpec)

		var objsTC tcObjects
		if err := tcSpec.LoadAndAssign(&objsTC, nil); err != nil {
			log.Fatalf("Error loading TC eBPF objects: %v", err)
		}

		defer func() { _ = objsTC.Close() }()

		pktCount = objsTC.PktCount

		links = startTC(objsTC, iface, links)
	}

	c1, cancel := context.WithCancel(context.Background())
	defer cancel()

	startTime := time.Now()

	//nolint:nestif
	if *enableTUI {
		drawTUI(pktCount, startTime)
	} else {
		signalCh := make(chan os.Signal, 1)

		signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
		defer signal.Stop(signalCh)

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

		m, err := processMap(pktCount, startTime, bitrateSort, nil)
		if err != nil {
			// reads from BPF_MAP_TYPE_LRU_HASH maps might get interrupted
			if errors.Is(err, ebpf.ErrIterationAborted) {
				_, _ = fmt.Fprint(os.Stderr, "Iteration aborted while reading eBPF map, output may be incomplete\n")
			} else {
				log.Fatalf("Error reading eBPF map: %v", err)
			}
		}

		if *jsonOutput {
			outputJSON(m)
		} else {
			fmt.Print(outputPlain(m))
		}
	}
}

// applyCgrpfsMagic rewrites the BPF-side `cgrpfs_magic` global constant on a
// CollectionSpec before it is loaded into the kernel. The BPF programs use
// this value at runtime to pick between cgroup v1 and v2 code paths; because
// it is a load-time constant, the verifier dead-code-eliminates the
// unreached branch and the per-packet cost of a config map lookup vanishes.
//
// Specs that do not expose this variable (e.g. tc/xdp objects compiled
// without the cgroup helpers) are silently skipped.
func applyCgrpfsMagic(spec *ebpf.CollectionSpec, magic uint64) error {
	v, ok := spec.Variables["cgrpfs_magic"]
	if !ok || v == nil {
		return nil
	}

	return v.Set(magic)
}

// applyMaxEntries patches the pkt_count map's MaxEntries from the --max-entries
// flag. A zero value leaves the compile-time MAX_ENTRIES default in place.
// Specs without a pkt_count map are silently skipped.
func applyMaxEntries(spec *ebpf.CollectionSpec) {
	if *maxEntries == 0 {
		return
	}

	if m, ok := spec.Maps["pkt_count"]; ok && m != nil {
		m.MaxEntries = uint32(*maxEntries)
	}
}

// applyArpEnabled patches the BPF-side arp_enabled toggle. Only meaningful for
// specs that link counter_common.h (tc, xdp); silently no-ops elsewhere.
func applyArpEnabled(spec *ebpf.CollectionSpec) {
	if !*noARP {
		return
	}

	v, ok := spec.Variables["arp_enabled"]
	if !ok || v == nil {
		return
	}

	_ = v.Set(uint8(0))
}
