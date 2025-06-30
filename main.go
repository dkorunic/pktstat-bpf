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

	// Maps to track DNS requests and their origins
	dnsRequestOrigins = make(map[string]*dnsOrigin) // key: "srcIP:srcPort-dstIP:dstPort", value: origin info
	dnsRequestsMutex  = &sync.RWMutex{}

	// DNS hostnames to IP mappings
	dnsHostToIP    = make(map[string][]dnsOriginMapping) // key: hostname, value: slice of IPs
	dnsIPToHost    = make(map[string][]dnsOriginMapping) // key: IP string, value: slice of hostnames
	dnsHostIPMutex = &sync.RWMutex{}
)

func main() {
	parseFlags()

	// Remove resource limits for kernels <5.11
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Error removing memlock: %v", err)
	}

	// Initialize Kubernetes client if kubeconfig is provided
	if kubeconfig != nil && *kubeconfig != "" {
		if err := initKubernetesClient(); err != nil {
			log.Fatalf("Error initializing Kubernetes client: %v", err)
		}

		// Start cache cleanup goroutine
		go cleanupIPToPodCache()

		// Detect DNS services in the cluster
		detectDNSServices()
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

	// Set up uprobes for DNS tracking
	// Try multiple potential libc locations
	libcLocations := []string{
		"/lib64/libc.so.6",                // Common on some systems
		"/lib/x86_64-linux-gnu/libc.so.6", // Debian/Ubuntu
		"/usr/lib/libc.so.6",              // Potential fallback
		"/usr/lib64/libc.so.6",            // Another potential location
	}

	var libcLocation string
	var libcExists bool

	for _, loc := range libcLocations {
		if _, err := os.Stat(loc); err == nil {
			libcLocation = loc
			libcExists = true
			log.Printf("Found libc at: %s", libcLocation)
			break
		}
	}

	if !libcExists {
		log.Fatalf("Error: Could not find libc.so.6 in any standard locations, cannot attach uprobes")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	upHooks := []uprobeHook{
		{
			symbol: "getaddrinfo",
			prog:   objs.UprobeGetaddrinfo,
		},
		{
			symbol: "gethostbyname",
			prog:   objs.UprobeGethostbyname2,
		},
		{
			symbol: "gethostbyname2",
			prog:   objs.UprobeGethostbyname2,
		},
		{
			symbol: "gethostbyname_r",
			prog:   objs.UprobeGethostbynameR,
		},
	}

	// Open the executable once outside the loop
	ex, err := link.OpenExecutable(libcLocation)
	if err != nil {
		log.Fatalf("Failed to open executable: %v", err)
	}

	for _, up := range upHooks {
		log.Printf("Attaching UProbe: %s", up.symbol)

		var l link.Link
		l, err = ex.Uprobe(up.symbol, up.prog, nil)
		if err != nil {
			log.Fatalf("Failed to attach uprobe: %v", err)
		}

		defer l.Close()

		links = append(links, l)
	}

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

	// Start a goroutine to process DNS events from the ringbuffer
	dnsReader, err := ringbuf.NewReader(objs.DnsEvents)
	if err != nil {
		log.Printf("Failed to create ringbuf reader for DNS events: %v", err)
	} else {
		log.Printf("Created DNS events ringbuf reader successfully")
		go processDNSEvents(ctx, dnsReader, dnsLookupMap, dnsLookupMapMutex)
		defer dnsReader.Close()
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
				// Enrich entry with DNS hostname if available
				if entry.Pid != 0 {
					dnsLookupMapMutex.RLock()
					if hostname, exists := dnsLookupMap[uint32(entry.Pid)]; exists {
						entry.DNSQueryName = hostname
					}
					dnsLookupMapMutex.RUnlock()
				}

				// Create unique keys for tracking seen entries
				// For regular tracking (with timestamp)
				timeKey := fmt.Sprintf("%s:%d->%s:%d:%s:%d:%s:%s",
					entry.SrcIP, entry.SrcPort, entry.DstIP, entry.DstPort,
					entry.Proto, entry.Pid, entry.Comm, entry.Timestamp.Format(time.RFC3339Nano))

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
						seenEntries[timeKey] = true
						shouldInclude = true
					}
				} else {
					// Normal mode, filter only exact duplicates with timestamp
					if !seenEntries[timeKey] {
						seenEntries[timeKey] = true
						shouldInclude = true
					}
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
