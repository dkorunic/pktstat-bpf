//go:build linux
// +build linux

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
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	json "github.com/goccy/go-json"
)

// Global variables for DNS tracking
var (
	// Track DNS service IPs
	dnsServiceIPs []string
)

func main() {
	parseFlags()

	// Remove resource limits for kernels <5.11
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Error removing memlock: %v", err)
	}

	// Create context for the application
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize Kubernetes client
	if kubeconfig != nil && *kubeconfig != "" {
		// Explicit kubeconfig provided - use it directly
		log.Printf("Using explicit kubeconfig: %s", *kubeconfig)
		if err := initKubernetesClient(*kubeconfig); err != nil {
			log.Fatalf("Error initializing Kubernetes client: %v", err)
		}

		// Start cache cleanup goroutine
		go cleanupIPToPodCache()

		// Detect DNS services in the cluster
		detectDNSServices()
	} else {
		// No explicit kubeconfig - start auto-discovery
		log.Printf("No kubeconfig specified, starting auto-discovery")
		discovery := NewConfigDiscovery()

		// Subscribe to config changes
		discovery.Subscribe(func(configPath string) {
			if configPath == "" {
				log.Printf("Kubeconfig removed, Kubernetes features disabled")
				if err := initKubernetesClient(""); err != nil {
					log.Printf("Error disabling Kubernetes client: %v", err)
				}
				return
			}

			log.Printf("Kubeconfig discovered/changed: %s", configPath)
			if err := initKubernetesClient(configPath); err != nil {
				log.Printf("Error initializing Kubernetes client with %s: %v", configPath, err)
			} else {
				// Detect DNS services when client is initialized
				detectDNSServices()
			}
		})

		// Start discovery in background
		if err := discovery.Start(ctx); err != nil {
			log.Printf("Failed to start config discovery: %v", err)
			log.Printf("Kubernetes features will be disabled")
		} else {
			// Start cache cleanup goroutine (runs even before client is available)
			go cleanupIPToPodCache()
		}
	}

	// Load the compiled eBPF ELF and load it into the kernel
	var objs counterObjects
	if err := loadCounterObjects(&objs, nil); err != nil {
		log.Fatalf("Error loading eBPF objects: %v", err)
	}
	defer func() { _ = objs.Close() }()

	var links []link.Link

	defer func() {
		for _, l := range links {
			_ = l.Close()
		}
	}()

	// Set up kprobes for packet tracking
	hooks := []kprobeHook{
		{kprobe: "tcp_sendmsg", prog: objs.TcpSendmsg},
		{kprobe: "tcp_cleanup_rbuf", prog: objs.TcpCleanupRbuf},
		{kprobe: "ip_send_skb", prog: objs.IpSendSkb},
		{kprobe: "ip_local_out", prog: objs.IpLocalOutFn},
		{kprobe: "ip_output", prog: objs.IpOutputFn},
		{kprobe: "skb_consume_udp", prog: objs.SkbConsumeUdp},
		{kprobe: "__icmp_send", prog: objs.IcmpSend},
		{kprobe: "icmp6_send", prog: objs.Icmp6Send},
		{kprobe: "icmp_rcv", prog: objs.IcmpRcv},
		{kprobe: "icmpv6_rcv", prog: objs.Icmpv6Rcv},
	}

	links = startKProbes(hooks, links)
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	// Create a ticker to process the map every second
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	// Set up signal handler
	go func() {
		s := <-signalCh
		_, _ = fmt.Fprintf(os.Stderr, "Received %v signal, exiting...\n", s)
		cancel()
	}()

	// Create DNS lookup map and mutex for sharing between goroutines
	dnsLookupMap := make(map[uint32]string)
	dnsLookupMapMutex := &sync.RWMutex{}

	udpPktReader, err := ringbuf.NewReader(objs.UdpPkts)
	if err != nil {
		log.Printf("Failed to create ringbuf reader for UDP packets: %v", err)
	} else {
		log.Printf("Created UDP packet ringbuf reader successfully")
		go processUDPPackets(ctx, udpPktReader)
		defer udpPktReader.Close()
	}

	// Run the main loop
	seenEntries := make(map[string]bool)
	for {
		select {
		case <-ticker.C:
			// Process the map
			entries, err := processMap(objs.PktCount, timeDateSort)
			if err != nil {
				log.Printf("Error reading eBPF map: %v", err)
				continue
			}

			// Filter out entries we've already seen and enrich with DNS data
			var newEntries []statEntry
			for _, entry := range entries {
				// For --unique tracking (without timestamp)
				uniqueKey := fmt.Sprintf("%s:%d->%s:%d:%s:%d:%s",
					entry.SrcIP, entry.SrcPort, entry.DstIP, entry.DstPort,
					entry.Proto, entry.Pid, entry.Comm)

				// Determine if we should include this entry
				shouldInclude := false

				if uniqueOutput != nil && *uniqueOutput {
					// When using --unique, filter by the connection pattern without timestamp
					if !seenEntries[uniqueKey] {
						seenEntries[uniqueKey] = true
						shouldInclude = true
					}
				} else {
					// Normal mode, processMap will remove the last events processed, so always include events we see
					shouldInclude = true
				}

				if shouldInclude {
					newEntries = append(newEntries, entry)
				}
			}

			// Process DNS flow correlation
			correlatedDNSEvents := processDNSFlow(entries, dnsLookupMap, dnsLookupMapMutex)

			// Skip if no new entries or correlated DNS events
			if len(newEntries) == 0 && len(correlatedDNSEvents) == 0 {
				continue
			}

			// Output correlated DNS events first if any
			if len(correlatedDNSEvents) > 0 {
				for _, dnsEvent := range correlatedDNSEvents {
					dnsJSON, _ := json.Marshal(dnsEvent)
					fmt.Println(string(dnsJSON))
				}
			}

			// Skip regular output if no new entries
			if len(newEntries) == 0 {
				continue
			}

			// Format output as JSON Lines
			output := outputJSON(newEntries)

			// Add newline if needed
			if output != "" && !strings.HasSuffix(output, "\n") {
				output += "\n"
			}

			// Write output to stdout
			fmt.Print(output)

		case <-ctx.Done():
			return
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
		log.Printf("Attaching %q KProbe", kp.kprobe)
		l, err = link.Kprobe(kp.kprobe, kp.prog, nil)
		if err != nil {
			log.Printf("Unable to attach %q KProbe: %v", kp.kprobe, err)

			continue
		}

		links = append(links, l)
	}

	return links
}
