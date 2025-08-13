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
// It loads the eBPF object files, removes resource limits for kernels <5.11,
// and starts the appropriate packet capture method based on the flags passed.
//
// The packet capture methods are:
//
//   - XDP (if *useXDP is set)
//   - TC (if *useXDP is not set)
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

	// Load the compiled counter eBPF ELF and load it into the kernel
	var objsCounter counterObjects
	if err := loadCounterObjects(&objsCounter, nil); err != nil {
		log.Fatalf("Error loading eBPF objects: %v", err)
	}

	defer func() { _ = objsCounter.Close() }()

	// Load the compiled cgroup eBPF ELF and load it into the kernel
	var objsCgroup cgroupObjects
	if err := loadCgroupObjects(&objsCgroup, nil); err != nil {
		log.Fatalf("Error loading eBPF objects: %v", err) //nolint:gocritic
	}

	defer func() { _ = objsCgroup.Close() }()

	iface, err := net.InterfaceByName(*ifname)
	if err != nil {
		log.Fatalf("Error getting interface %q: %v", *ifname, err)
	}

	var links []link.Link

	defer func() {
		for _, l := range links {
			_ = l.Close()
		}
	}()

	switch {
	case *useCGroup != "":
		cGroupCacheInit()

		links = startCgroup(objsCounter, *useCGroup, links)
		links = startCGroupTrace(objsCgroup, links)

		rd, err := cGroupWatcher(objsCgroup)
		if err != nil {
			defer func() { _ = rd.Close() }()
		}
	// KProbes w/ PID tracking
	case *useKProbes:
		cGroupCacheInit()

		hooks := []kprobeHook{
			{kprobe: "tcp_sendmsg", prog: objsCounter.TcpSendmsg},
			{kprobe: "tcp_cleanup_rbuf", prog: objsCounter.TcpCleanupRbuf},
			{kprobe: "ip_send_skb", prog: objsCounter.IpSendSkb},
			{kprobe: "skb_consume_udp", prog: objsCounter.SkbConsumeUdp},
			{kprobe: "__icmp_send", prog: objsCounter.IcmpSend},
			{kprobe: "icmp6_send", prog: objsCounter.Icmp6Send},
			{kprobe: "icmp_rcv", prog: objsCounter.IcmpRcv},
			{kprobe: "icmpv6_rcv", prog: objsCounter.Icmpv6Rcv},
		}

		links = startKProbes(hooks, links)
		links = startCGroupTrace(objsCgroup, links)

		rd, err := cGroupWatcher(objsCgroup)
		if err != nil {
			defer func() { _ = rd.Close() }()
		}
	// XDP
	case *useXDP:
		links = startXDP(objsCounter, iface, links)
	// TC
	default:
		links = startTC(objsCounter, iface, links)
	}

	c1, cancel := context.WithCancel(context.Background())
	defer cancel()

	startTime := time.Now()

	//nolint:nestif
	if *enableTUI {
		drawTUI(objsCounter, startTime)
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

		var m []statEntry

		m, err = processMap(objsCounter.PktCount, startTime, bitrateSort)
		if err != nil {
			// reads from BPF_MAP_TYPE_LRU_HASH maps might get interrupted
			if errors.Is(err, ebpf.ErrIterationAborted) {
				_, _ = fmt.Fprint(os.Stderr, "Iteration aborted while reading eBPF map, output may be incomplete\n")
			} else {
				log.Fatalf("Error reading eBPF map: %v", err)
			}
		}

		if *jsonOutput {
			fmt.Println(outputJSON(m))
		} else {
			fmt.Print(outputPlain(m))
		}
	}
}
