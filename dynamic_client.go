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
	"log"
	"sync"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// DynamicKubeClient wraps kubernetes.Clientset with dynamic behavior
type DynamicKubeClient interface {
	// GetClient returns current client or nil if unavailable
	GetClient() *kubernetes.Clientset

	// Refresh attempts to reinitialize the client with a new config path
	Refresh(configPath string) error

	// IsAvailable indicates if client is ready for use
	IsAvailable() bool

	// Shutdown gracefully closes the client
	Shutdown()
}

// dynamicKubeClient is the concrete implementation
type dynamicKubeClient struct {
	client     *kubernetes.Clientset
	configPath string
	mutex      sync.RWMutex
}

// NewDynamicKubeClient creates a new DynamicKubeClient
func NewDynamicKubeClient() DynamicKubeClient {
	return &dynamicKubeClient{}
}

// GetClient returns the current Kubernetes client or nil if unavailable
func (d *dynamicKubeClient) GetClient() *kubernetes.Clientset {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	return d.client
}

// Refresh reinitializes the client with a new config path
func (d *dynamicKubeClient) Refresh(configPath string) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	// If configPath is empty, shutdown the client
	if configPath == "" {
		log.Printf("Shutting down Kubernetes client (no config available)")
		d.client = nil
		d.configPath = ""
		return nil
	}

	// If this is the same path and client is already initialized, no action needed
	if d.configPath == configPath && d.client != nil {
		log.Printf("Reloading Kubernetes client with config: %s", configPath)
		// Even if it's the same path, the file might have been modified
		// So we proceed with reinitialization
	}

	// Build config from the provided path
	var config *rest.Config
	var err error

	config, err = clientcmd.BuildConfigFromFlags("", configPath)
	if err != nil {
		log.Printf("Failed to build Kubernetes config from %s: %v", configPath, err)
		return err
	}

	// Create new client
	newClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Printf("Failed to create Kubernetes client: %v", err)
		return err
	}

	// Close existing client if present (graceful shutdown)
	if d.client != nil {
		// The kubernetes.Clientset doesn't have an explicit Close method,
		// but we can nil it out to allow garbage collection
		d.client = nil
	}

	// Update to new client
	d.client = newClient
	d.configPath = configPath

	log.Printf("Kubernetes client initialized with kubeconfig: %s", configPath)
	return nil
}

// IsAvailable indicates if the client is ready for use
func (d *dynamicKubeClient) IsAvailable() bool {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	return d.client != nil
}

// Shutdown gracefully closes the client
func (d *dynamicKubeClient) Shutdown() {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if d.client != nil {
		log.Printf("Shutting down Kubernetes client")
		d.client = nil
		d.configPath = ""
	}
}
