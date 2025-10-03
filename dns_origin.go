package main

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Global variables for enhanced DNS tracking
var (
	// Store internal DNS requests (client -> CoreDNS)
	internalDNSRequests      = make(map[string]*dnsOrigin) // key: "srcIP:srcPort-dstIP:dstPort"
	internalDNSRequestsMutex = &sync.RWMutex{}

	// Store correlated DNS events
	correlatedDNSEvents      = make([]dnsCorrelatedEvent, 0)
	correlatedDNSEventsMutex = &sync.RWMutex{}
)

// detectDNSServices tries to identify DNS services in the Kubernetes cluster
func detectDNSServices() {
	// Get the current client safely
	client := getKubeClient()
	if client == nil {
		log.Printf("Kubernetes client not available, skipping DNS service detection")
		return
	}

	ips, err := getDNSServiceIPs()
	if err != nil {
		log.Printf("Error detecting DNS services: %v", err)
	} else if len(ips) > 0 {
		dnsServiceIPs = ips
		log.Printf("Detected DNS service IPs: %v", dnsServiceIPs)
	}

	if len(dnsServiceIPs) == 0 {
		log.Printf("Warning: No DNS service IPs detected, will not track internal DNS queries")
	}
}

// getDNSServiceIPs returns IPs of services listening on UDP port 53
func getDNSServiceIPs() ([]string, error) {
	client := getKubeClient()
	if client == nil {
		return nil, fmt.Errorf("Kubernetes client not initialized")
	}

	var ips []string

	// Query services in all namespaces
	services, err := client.CoreV1().Services("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list services: %v", err)
	}

	// Look for services with port 53
	for _, svc := range services.Items {
		for _, port := range svc.Spec.Ports {
			if port.Port == 53 && (port.Protocol == "UDP" || port.Protocol == "TCP") {
				if svc.Spec.ClusterIP != "" && svc.Spec.ClusterIP != "None" {
					ips = append(ips, svc.Spec.ClusterIP)
					log.Printf("Found DNS service: %s/%s at %s, will track internal DNS queries", svc.Namespace, svc.Name, svc.Spec.ClusterIP)
				}
			}
		}
	}

	return ips, nil
}

// isDNSServiceIP checks if the given IP is a known DNS service IP
func isDNSServiceIP(ip string) bool {
	for _, dnsIP := range dnsServiceIPs {
		if ip == dnsIP {
			return true
		}
	}
	return false
}

// processDNSFlow processes network entries to track and correlate DNS flows
func processDNSFlow(entries []statEntry, dnsLookupMap map[uint32]string, dnsLookupMapMutex *sync.RWMutex) []dnsCorrelatedEvent {
	internalDNSRequestsMutex.Lock()
	defer internalDNSRequestsMutex.Unlock()

	correlatedDNSEventsMutex.Lock()
	defer correlatedDNSEventsMutex.Unlock()

	var newCorrelatedEvents []dnsCorrelatedEvent

	for _, entry := range entries {
		// Track internal DNS requests (client -> CoreDNS)
		if (entry.Proto == "UDP" || entry.Proto == "TCP") && entry.DstPort == 53 && isDNSServiceIP(entry.DstIP.String()) {
			key := fmt.Sprintf("%s:%d-%s:%d", entry.SrcIP.String(), entry.SrcPort, entry.DstIP.String(), entry.DstPort)
			internalDNSRequests[key] = &dnsOrigin{
				SrcIP:     entry.SrcIP.String(),
				SrcPort:   entry.SrcPort,
				Pid:       uint32(entry.Pid),
				Comm:      entry.Comm,
				Timestamp: entry.Timestamp,
				PodName:   entry.SourcePod,
			}
			log.Printf("Tracking internal DNS request: %s:%d -> %s:%d (PID: %d, Comm: %s, Pod: %s)",
				entry.SrcIP, entry.SrcPort, entry.DstIP, entry.DstPort, entry.Pid, entry.Comm, entry.SourcePod)
			continue
		}

		// Track external DNS requests (CoreDNS -> External DNS)
		if (entry.Proto == "UDP" || entry.Proto == "TCP") && entry.DstPort == 53 && isExternalIP(entry.DstIP) {
			// This could be CoreDNS making an external request
			// Try to correlate with a recent internal request

			// Look for matching internal requests that could have triggered this external request
			for internalKey, origin := range internalDNSRequests {
				// Check if this external request happened soon after the internal one
				if time.Since(origin.Timestamp) < 10*time.Second {
					// Get DNS query name if available
					var queryName string
					if origin.Pid > 0 {
						dnsLookupMapMutex.RLock()
						if hostname, exists := dnsLookupMap[origin.Pid]; exists {
							queryName = hostname
						}
						dnsLookupMapMutex.RUnlock()
					}

					// Create a correlated event
					correlatedEvent := dnsCorrelatedEvent{
						OriginalSrcIP:   origin.SrcIP,
						OriginalSrcPort: origin.SrcPort,
						OriginalPod:     origin.PodName,
						OriginalComm:    origin.Comm,
						OriginalPid:     int32(origin.Pid),
						Timestamp:       entry.Timestamp,
						DNSServerIP:     entry.SrcIP.String(),
						DNSServerComm:   entry.Comm,
						DNSServerPid:    entry.Pid,
						ExternalDstIP:   entry.DstIP.String(),
						ExternalDstPort: entry.DstPort,
						Proto:           entry.Proto,
						LikelyService:   entry.LikelyService,
						DNSQueryName:    queryName,
					}

					correlatedDNSEvents = append(correlatedDNSEvents, correlatedEvent)
					newCorrelatedEvents = append(newCorrelatedEvents, correlatedEvent)

					log.Printf("DNS Flow Correlation: Client %s:%d (%s, %s) -> DNS Server %s (%s, PID:%d) -> External %s:%d [Query: %s]",
						origin.SrcIP, origin.SrcPort, origin.Comm, origin.PodName,
						entry.SrcIP.String(), entry.Comm, entry.Pid,
						entry.DstIP.String(), entry.DstPort, queryName)

					// Remove the internal request as it's been correlated
					delete(internalDNSRequests, internalKey)
					break
				}
			}
		}
	}

	// Clean up old internal DNS requests (older than 30 seconds)
	now := time.Now()
	for key, origin := range internalDNSRequests {
		if now.Sub(origin.Timestamp) > 30*time.Second {
			delete(internalDNSRequests, key)
		}
	}

	return newCorrelatedEvents
}
