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
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
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

	// Attach count_packets to the network interface ingress (BPF_TCX_INGRESS)
	linkIngress, err := link.AttachTCX(link.TCXOptions{
		Program:   objs.CountPackets,
		Attach:    ebpf.AttachTCXIngress,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("Error attaching %q TCX ingress: %v", *ifname, err)
	}
	defer linkIngress.Close()

	// Attach count_packets to the network interface egresss (BPF_TCX_EGRESS)
	linkEgress, err := link.AttachTCX(link.TCXOptions{
		Program:   objs.CountPackets,
		Attach:    ebpf.AttachTCXEgress,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("Error attaching %q TCX egress: %v", *ifname, err)
	}
	defer linkEgress.Close()

	log.Printf("Starting on interface %q", *ifname)

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
