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
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// TestDynamicClient_Initialization tests basic client initialization
func TestDynamicClient_Initialization(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "kubeconfig-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	kubeconfigPath := filepath.Join(tmpDir, "config")

	// Create a valid kubeconfig file
	validKubeconfig := `apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://127.0.0.1:6443
  name: test-cluster
contexts:
- context:
    cluster: test-cluster
    user: test-user
  name: test-context
current-context: test-context
users:
- name: test-user
  user:
    token: test-token
`
	if err := os.WriteFile(kubeconfigPath, []byte(validKubeconfig), 0600); err != nil {
		t.Fatalf("Failed to write kubeconfig: %v", err)
	}

	// Create dynamic client
	client := NewDynamicKubeClient()

	// Initially should not be available
	if client.IsAvailable() {
		t.Error("Expected client to not be available before initialization")
	}

	if client.GetClient() != nil {
		t.Error("Expected GetClient to return nil before initialization")
	}

	// Initialize with kubeconfig
	err = client.Refresh(kubeconfigPath)
	if err != nil {
		t.Fatalf("Failed to initialize client: %v", err)
	}

	// Should now be available
	if !client.IsAvailable() {
		t.Error("Expected client to be available after initialization")
	}

	if client.GetClient() == nil {
		t.Error("Expected GetClient to return non-nil after initialization")
	}
}

// TestDynamicClient_Reinitialize tests client reinitialization
func TestDynamicClient_Reinitialize(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "kubeconfig-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	kubeconfigPath1 := filepath.Join(tmpDir, "config1")
	kubeconfigPath2 := filepath.Join(tmpDir, "config2")

	// Create two valid kubeconfig files
	validKubeconfig1 := `apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://127.0.0.1:6443
  name: test-cluster-1
contexts:
- context:
    cluster: test-cluster-1
    user: test-user
  name: test-context
current-context: test-context
users:
- name: test-user
  user:
    token: test-token-1
`
	validKubeconfig2 := `apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://127.0.0.1:6444
  name: test-cluster-2
contexts:
- context:
    cluster: test-cluster-2
    user: test-user
  name: test-context
current-context: test-context
users:
- name: test-user
  user:
    token: test-token-2
`
	if err := os.WriteFile(kubeconfigPath1, []byte(validKubeconfig1), 0600); err != nil {
		t.Fatalf("Failed to write kubeconfig1: %v", err)
	}
	if err := os.WriteFile(kubeconfigPath2, []byte(validKubeconfig2), 0600); err != nil {
		t.Fatalf("Failed to write kubeconfig2: %v", err)
	}

	// Create dynamic client
	client := NewDynamicKubeClient()

	// Initialize with first kubeconfig
	err = client.Refresh(kubeconfigPath1)
	if err != nil {
		t.Fatalf("Failed to initialize client with config1: %v", err)
	}

	if !client.IsAvailable() {
		t.Error("Expected client to be available after first initialization")
	}

	firstClient := client.GetClient()
	if firstClient == nil {
		t.Fatal("Expected GetClient to return non-nil after first initialization")
	}

	// Reinitialize with second kubeconfig
	err = client.Refresh(kubeconfigPath2)
	if err != nil {
		t.Fatalf("Failed to reinitialize client with config2: %v", err)
	}

	if !client.IsAvailable() {
		t.Error("Expected client to be available after reinitialization")
	}

	secondClient := client.GetClient()
	if secondClient == nil {
		t.Fatal("Expected GetClient to return non-nil after reinitialization")
	}

	// The clients should be different instances
	if firstClient == secondClient {
		t.Error("Expected different client instances after reinitialization")
	}
}

// TestDynamicClient_ConcurrentAccess tests concurrent access to the client
func TestDynamicClient_ConcurrentAccess(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "kubeconfig-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	kubeconfigPath := filepath.Join(tmpDir, "config")

	// Create a valid kubeconfig file
	validKubeconfig := `apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://127.0.0.1:6443
  name: test-cluster
contexts:
- context:
    cluster: test-cluster
    user: test-user
  name: test-context
current-context: test-context
users:
- name: test-user
  user:
    token: test-token
`
	if err := os.WriteFile(kubeconfigPath, []byte(validKubeconfig), 0600); err != nil {
		t.Fatalf("Failed to write kubeconfig: %v", err)
	}

	// Create dynamic client
	client := NewDynamicKubeClient()

	// Initialize client
	err = client.Refresh(kubeconfigPath)
	if err != nil {
		t.Fatalf("Failed to initialize client: %v", err)
	}

	// Perform concurrent reads and writes
	var wg sync.WaitGroup
	iterations := 100

	// Concurrent readers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_ = client.GetClient()
				_ = client.IsAvailable()
			}
		}()
	}

	// Concurrent writers (reinitializing)
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations/10; j++ {
				_ = client.Refresh(kubeconfigPath)
			}
		}()
	}

	// Wait for all goroutines to complete
	wg.Wait()

	// Client should still be available after concurrent access
	if !client.IsAvailable() {
		t.Error("Expected client to be available after concurrent access")
	}
}

// TestDynamicClient_GracefulShutdown tests graceful shutdown
func TestDynamicClient_GracefulShutdown(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "kubeconfig-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	kubeconfigPath := filepath.Join(tmpDir, "config")

	// Create a valid kubeconfig file
	validKubeconfig := `apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://127.0.0.1:6443
  name: test-cluster
contexts:
- context:
    cluster: test-cluster
    user: test-user
  name: test-context
current-context: test-context
users:
- name: test-user
  user:
    token: test-token
`
	if err := os.WriteFile(kubeconfigPath, []byte(validKubeconfig), 0600); err != nil {
		t.Fatalf("Failed to write kubeconfig: %v", err)
	}

	// Create dynamic client
	client := NewDynamicKubeClient()

	// Initialize client
	err = client.Refresh(kubeconfigPath)
	if err != nil {
		t.Fatalf("Failed to initialize client: %v", err)
	}

	if !client.IsAvailable() {
		t.Error("Expected client to be available after initialization")
	}

	// Shutdown the client
	client.Shutdown()

	// Client should not be available after shutdown
	if client.IsAvailable() {
		t.Error("Expected client to not be available after shutdown")
	}

	if client.GetClient() != nil {
		t.Error("Expected GetClient to return nil after shutdown")
	}

	// Test refresh with empty path (similar to shutdown)
	err = client.Refresh(kubeconfigPath)
	if err != nil {
		t.Fatalf("Failed to reinitialize after shutdown: %v", err)
	}

	if !client.IsAvailable() {
		t.Error("Expected client to be available after reinitialization")
	}

	// Refresh with empty path should disable client
	err = client.Refresh("")
	if err != nil {
		t.Fatalf("Failed to disable client: %v", err)
	}

	if client.IsAvailable() {
		t.Error("Expected client to not be available after empty path refresh")
	}
}
