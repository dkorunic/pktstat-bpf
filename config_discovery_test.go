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
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestConfigDiscovery_StandardPaths tests that config discovery scans standard paths
func TestConfigDiscovery_StandardPaths(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "kubeconfig-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a valid kubeconfig file
	kubeconfigPath := filepath.Join(tmpDir, "config")
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

	// Create discovery with custom paths
	discovery := &configDiscovery{
		standardPaths: []string{kubeconfigPath},
		callbacks:     make([]ConfigChangeCallback, 0),
	}

	// Scan for config
	foundPath := discovery.scanStandardPaths()
	if foundPath == "" {
		t.Fatal("Expected to find kubeconfig, but none was found")
	}

	if foundPath != kubeconfigPath {
		t.Errorf("Expected path %s, got %s", kubeconfigPath, foundPath)
	}
}

// TestConfigDiscovery_FileAppears tests that discovery detects when a kubeconfig file is created
func TestConfigDiscovery_FileAppears(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "kubeconfig-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	kubeconfigPath := filepath.Join(tmpDir, "config")

	// Create discovery with custom paths
	discovery := &configDiscovery{
		standardPaths: []string{kubeconfigPath},
		callbacks:     make([]ConfigChangeCallback, 0),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Channel to signal when callback is invoked
	callbackChan := make(chan string, 1)

	// Subscribe to changes
	discovery.Subscribe(func(configPath string) {
		callbackChan <- configPath
	})

	// Start discovery
	if err := discovery.Start(ctx); err != nil {
		t.Fatalf("Failed to start discovery: %v", err)
	}

	// Give watcher time to initialize
	time.Sleep(100 * time.Millisecond)

	// Create the kubeconfig file
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

	// Wait for callback
	select {
	case path := <-callbackChan:
		if path != kubeconfigPath {
			t.Errorf("Expected callback with path %s, got %s", kubeconfigPath, path)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for callback after file creation")
	}
}

// TestConfigDiscovery_FileRemoved tests that discovery handles file removal
func TestConfigDiscovery_FileRemoved(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "kubeconfig-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	kubeconfigPath := filepath.Join(tmpDir, "config")

	// Create initial kubeconfig
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

	// Create discovery with custom paths
	discovery := &configDiscovery{
		standardPaths: []string{kubeconfigPath},
		callbacks:     make([]ConfigChangeCallback, 0),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Channel to signal when callback is invoked
	callbackChan := make(chan string, 2)

	// Subscribe to changes
	discovery.Subscribe(func(configPath string) {
		callbackChan <- configPath
	})

	// Start discovery
	if err := discovery.Start(ctx); err != nil {
		t.Fatalf("Failed to start discovery: %v", err)
	}

	// Wait for initial callback
	select {
	case path := <-callbackChan:
		if path != kubeconfigPath {
			t.Errorf("Expected initial callback with path %s, got %s", kubeconfigPath, path)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for initial callback")
	}

	// Remove the file
	if err := os.Remove(kubeconfigPath); err != nil {
		t.Fatalf("Failed to remove kubeconfig: %v", err)
	}

	// Wait for callback after removal
	select {
	case path := <-callbackChan:
		if path != "" {
			t.Errorf("Expected callback with empty path after removal, got %s", path)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for callback after file removal")
	}

	// Verify current path is empty
	if discovery.GetCurrentPath() != "" {
		t.Errorf("Expected current path to be empty, got %s", discovery.GetCurrentPath())
	}
}

// TestConfigDiscovery_FileModified tests that discovery detects file modifications
func TestConfigDiscovery_FileModified(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "kubeconfig-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	kubeconfigPath := filepath.Join(tmpDir, "config")

	// Create initial kubeconfig
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

	// Create discovery with custom paths
	discovery := &configDiscovery{
		standardPaths: []string{kubeconfigPath},
		callbacks:     make([]ConfigChangeCallback, 0),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Channel to signal when callback is invoked
	callbackChan := make(chan string, 2)

	// Subscribe to changes
	discovery.Subscribe(func(configPath string) {
		callbackChan <- configPath
	})

	// Start discovery
	if err := discovery.Start(ctx); err != nil {
		t.Fatalf("Failed to start discovery: %v", err)
	}

	// Wait for initial callback
	select {
	case <-callbackChan:
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for initial callback")
	}

	// Modify the file
	modifiedKubeconfig := `apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://127.0.0.1:6444
  name: test-cluster-modified
contexts:
- context:
    cluster: test-cluster-modified
    user: test-user
  name: test-context
current-context: test-context
users:
- name: test-user
  user:
    token: test-token-modified
`
	if err := os.WriteFile(kubeconfigPath, []byte(modifiedKubeconfig), 0600); err != nil {
		t.Fatalf("Failed to modify kubeconfig: %v", err)
	}

	// Wait for callback after modification
	select {
	case path := <-callbackChan:
		if path != kubeconfigPath {
			t.Errorf("Expected callback with path %s after modification, got %s", kubeconfigPath, path)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for callback after file modification")
	}
}

// TestConfigDiscovery_InvalidConfig tests handling of invalid kubeconfig files
func TestConfigDiscovery_InvalidConfig(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "kubeconfig-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	kubeconfigPath := filepath.Join(tmpDir, "config")

	// Create invalid kubeconfig
	invalidKubeconfig := `this is not valid yaml: {[[`
	if err := os.WriteFile(kubeconfigPath, []byte(invalidKubeconfig), 0600); err != nil {
		t.Fatalf("Failed to write kubeconfig: %v", err)
	}

	// Create discovery with custom paths
	discovery := &configDiscovery{
		standardPaths: []string{kubeconfigPath},
		callbacks:     make([]ConfigChangeCallback, 0),
	}

	// Scan for config - should not find invalid config
	foundPath := discovery.scanStandardPaths()
	if foundPath != "" {
		t.Errorf("Expected not to find invalid kubeconfig, but found: %s", foundPath)
	}

	// Verify validation rejects invalid config
	if discovery.validateKubeconfig(kubeconfigPath) {
		t.Error("Expected validateKubeconfig to reject invalid config")
	}
}
