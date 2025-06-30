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
	"log"
	"net/netip"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	// kubeClient is the Kubernetes client used for pod lookups
	kubeClient *kubernetes.Clientset

	// ipToPodCache is a cache of IP address to pod name mappings
	ipToPodCache = make(map[string]string)

	// cacheMutex protects the IP to pod cache
	cacheMutex sync.RWMutex

	// cacheExpiry is the time after which a cache entry expires
	cacheExpiry = 5 * time.Minute
)

// ipPodCacheEntry represents an entry in the IP to pod cache
type ipPodCacheEntry struct {
	pod       string
	timestamp time.Time
}

// initKubernetesClient initializes the Kubernetes client if enabled
func initKubernetesClient() error {
	// Don't initialize if kubeconfig is empty
	if kubeconfig == nil || *kubeconfig == "" {
		return nil
	}

	var config *rest.Config
	var err error

	// Out-of-cluster configuration
	config, err = clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		return err
	}

	// Create Kubernetes client
	kubeClient, err = kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	log.Printf("Kubernetes client initialized with kubeconfig: %s", *kubeconfig)
	return nil
}

// lookupPodForIP looks up the pod name for a given IP address
// It caches results to avoid excessive API calls
func lookupPodForIP(ip netip.Addr) string {
	// Skip lookup if kubeconfig is empty or client not initialized
	if kubeconfig == nil || *kubeconfig == "" || kubeClient == nil {
		return ""
	}

	ipStr := ip.String()

	// Check cache first
	cacheMutex.RLock()
	if pod, ok := ipToPodCache[ipStr]; ok {
		cacheMutex.RUnlock()
		return pod
	}
	cacheMutex.RUnlock()

	// Cache miss, perform API lookup
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// List all pods across all namespaces to find matching IP
	pods, err := kubeClient.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: "status.podIP=" + ipStr,
	})
	if err != nil {
		log.Printf("Error looking up pod for IP %s: %v", ipStr, err)
		return ""
	}

	var pod string
	if len(pods.Items) > 0 {
		pod = pods.Items[0].Namespace + "/" + pods.Items[0].Name
	}

	// Update cache
	cacheMutex.Lock()
	ipToPodCache[ipStr] = pod
	cacheMutex.Unlock()

	return pod
}

// cleanupIPToPodCache periodically cleans up expired entries in the IP to pod cache
func cleanupIPToPodCache() {
	for {
		time.Sleep(cacheExpiry)

		// Skip cleanup if kubeconfig is empty or client not initialized
		if kubeconfig == nil || *kubeconfig == "" || kubeClient == nil {
			continue
		}

		cacheMutex.Lock()
		// Rebuild cache with only valid entries
		newCache := make(map[string]string)
		for ip, pod := range ipToPodCache {
			if pod != "" {
				newCache[ip] = pod
			}
		}
		ipToPodCache = newCache
		cacheMutex.Unlock()
	}
}
