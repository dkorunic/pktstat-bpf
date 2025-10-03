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
	"os"
	"path/filepath"
	"sync"

	"github.com/fsnotify/fsnotify"
	"k8s.io/client-go/tools/clientcmd"
)

// ConfigChangeCallback is called when a valid kubeconfig is found or changed
type ConfigChangeCallback func(configPath string)

// ConfigDiscovery manages kubeconfig discovery and monitoring
type ConfigDiscovery interface {
	// Start begins watching for kubeconfig files
	Start(ctx context.Context) error

	// GetCurrentPath returns the active kubeconfig path
	GetCurrentPath() string

	// Subscribe registers a callback for config changes
	Subscribe(callback ConfigChangeCallback)
}

// configDiscovery is the concrete implementation of ConfigDiscovery
type configDiscovery struct {
	// Standard paths to scan for kubeconfig files
	standardPaths []string

	// Current active kubeconfig path
	currentPath string

	// Mutex to protect currentPath
	pathMutex sync.RWMutex

	// Callbacks to invoke when config changes
	callbacks []ConfigChangeCallback

	// Mutex to protect callbacks
	callbackMutex sync.RWMutex

	// Filesystem watcher
	watcher *fsnotify.Watcher

	// Whether discovery is running
	running bool

	// Mutex to protect running state
	runningMutex sync.Mutex
}

// NewConfigDiscovery creates a new ConfigDiscovery instance
func NewConfigDiscovery() ConfigDiscovery {
	homeDir, _ := os.UserHomeDir()

	return &configDiscovery{
		standardPaths: []string{
			os.Getenv("KUBECONFIG"),
			filepath.Join(homeDir, ".kube", "config"),
			"/tmp/kubeconfig-local",                               // kind
			"/var/lib/rancher/k3s/agent/k3scontroller.kubeconfig", // k3s secondary nodes (must be before k3s control plane)
			"/etc/rancher/k3s/k3s.yaml",                           // k3s control plane
			"/etc/rancher/rke2/rke2.yaml",                         // rke2
			"/var/lib/embedded-cluster/k0s/pki/admin.conf",        // embedded-cluster control plane
			"/var/lib/embedded-cluster/k0s/kubelet.conf",          // embedded-cluster secondary nodes
			"/var/home/core/kubeconfig",                           // openshift
			"/etc/kubernetes/admin.conf",                          // kurl control plane
			"/etc/kubernetes/kubelet.conf",                        // kurl secondary nodes
		},
		callbacks: make([]ConfigChangeCallback, 0),
	}
}

// Start begins watching for kubeconfig files
func (cd *configDiscovery) Start(ctx context.Context) error {
	cd.runningMutex.Lock()
	if cd.running {
		cd.runningMutex.Unlock()
		return fmt.Errorf("config discovery already running")
	}
	cd.running = true
	cd.runningMutex.Unlock()

	// Initialize filesystem watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		cd.runningMutex.Lock()
		cd.running = false
		cd.runningMutex.Unlock()
		return fmt.Errorf("failed to create filesystem watcher: %v", err)
	}
	cd.watcher = watcher

	// Scan standard paths immediately
	initialPath := cd.scanStandardPaths()
	if initialPath != "" {
		cd.setCurrentPath(initialPath)
		cd.notifyCallbacks(initialPath)
	}

	// Watch directories for file creation/modification
	cd.setupWatchers()

	// Start watching goroutine
	go cd.watchLoop(ctx)

	return nil
}

// GetCurrentPath returns the active kubeconfig path
func (cd *configDiscovery) GetCurrentPath() string {
	cd.pathMutex.RLock()
	defer cd.pathMutex.RUnlock()
	return cd.currentPath
}

// Subscribe registers a callback for config changes
func (cd *configDiscovery) Subscribe(callback ConfigChangeCallback) {
	cd.callbackMutex.Lock()
	defer cd.callbackMutex.Unlock()
	cd.callbacks = append(cd.callbacks, callback)
}

// scanStandardPaths scans all standard paths and returns the first valid kubeconfig
func (cd *configDiscovery) scanStandardPaths() string {
	for _, path := range cd.standardPaths {
		if path == "" {
			continue
		}

		// Check if file exists
		if _, err := os.Stat(path); err != nil {
			continue
		}

		// Validate the kubeconfig
		if cd.validateKubeconfig(path) {
			log.Printf("Found valid kubeconfig at: %s", path)
			return path
		} else {
			log.Printf("Found kubeconfig at %s but it is invalid", path)
		}
	}

	return ""
}

// validateKubeconfig checks if a file is a valid kubeconfig
func (cd *configDiscovery) validateKubeconfig(path string) bool {
	// Try to load the config
	_, err := clientcmd.LoadFromFile(path)
	if err != nil {
		log.Printf("Invalid kubeconfig at %s: %v", path, err)
		return false
	}

	return true
}

// setupWatchers sets up filesystem watchers for kubeconfig directories
func (cd *configDiscovery) setupWatchers() {
	// Watch directories that might contain kubeconfig files
	watchDirs := make(map[string]bool)

	for _, path := range cd.standardPaths {
		if path == "" {
			continue
		}

		dir := filepath.Dir(path)
		if _, ok := watchDirs[dir]; ok {
			continue
		}
		watchDirs[dir] = true

		// Check if directory exists
		if _, err := os.Stat(dir); err != nil {
			// Directory doesn't exist yet, try to watch parent
			parentDir := filepath.Dir(dir)
			if _, err := os.Stat(parentDir); err == nil {
				_ = cd.watcher.Add(parentDir)
				log.Printf("Watching parent directory for kubeconfig: %s", parentDir)
			}
			continue
		}

		// Watch the directory
		err := cd.watcher.Add(dir)
		if err != nil {
			log.Printf("Failed to watch directory %s: %v", dir, err)
		} else {
			log.Printf("Watching directory for kubeconfig: %s", dir)
		}
	}
}

// watchLoop processes filesystem events
func (cd *configDiscovery) watchLoop(ctx context.Context) {
	defer cd.watcher.Close()

	for {
		select {
		case <-ctx.Done():
			log.Printf("Config discovery stopped")
			cd.runningMutex.Lock()
			cd.running = false
			cd.runningMutex.Unlock()
			return

		case event, ok := <-cd.watcher.Events:
			if !ok {
				return
			}

			// Check if this event is for one of our watched paths
			if cd.isWatchedPath(event.Name) {
				if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create {
					log.Printf("Detected kubeconfig change: %s (op: %s)", event.Name, event.Op)

					// Validate and potentially update current path
					if cd.validateKubeconfig(event.Name) {
						currentPath := cd.GetCurrentPath()
						if currentPath != event.Name {
							log.Printf("Switching to kubeconfig: %s", event.Name)
							cd.setCurrentPath(event.Name)
							cd.notifyCallbacks(event.Name)
						} else {
							log.Printf("Kubeconfig modified, reloading: %s", event.Name)
							cd.notifyCallbacks(event.Name)
						}
					}
				} else if event.Op&fsnotify.Remove == fsnotify.Remove {
					currentPath := cd.GetCurrentPath()
					if currentPath == event.Name {
						log.Printf("Current kubeconfig removed: %s, searching for alternative", event.Name)
						cd.setCurrentPath("")

						// Try to find another valid config
						newPath := cd.scanStandardPaths()
						if newPath != "" {
							cd.setCurrentPath(newPath)
							cd.notifyCallbacks(newPath)
						} else {
							log.Printf("No alternative kubeconfig found")
							// Notify callbacks with empty path to disable Kubernetes features
							cd.notifyCallbacks("")
						}
					}
				}
			}

			// If a directory was created, set up watchers for it
			if event.Op&fsnotify.Create == fsnotify.Create {
				if info, err := os.Stat(event.Name); err == nil && info.IsDir() {
					if cd.shouldWatchDir(event.Name) {
						_ = cd.watcher.Add(event.Name)
						log.Printf("Started watching newly created directory: %s", event.Name)
					}
				}
			}

		case err, ok := <-cd.watcher.Errors:
			if !ok {
				return
			}
			log.Printf("Filesystem watcher error: %v", err)
		}
	}
}

// isWatchedPath checks if a path matches one of our standard paths
func (cd *configDiscovery) isWatchedPath(path string) bool {
	for _, standardPath := range cd.standardPaths {
		if standardPath == "" {
			continue
		}
		if path == standardPath {
			return true
		}
	}
	return false
}

// shouldWatchDir checks if we should watch a directory
func (cd *configDiscovery) shouldWatchDir(dir string) bool {
	for _, standardPath := range cd.standardPaths {
		if standardPath == "" {
			continue
		}
		if filepath.Dir(standardPath) == dir {
			return true
		}
	}
	return false
}

// setCurrentPath sets the current kubeconfig path
func (cd *configDiscovery) setCurrentPath(path string) {
	cd.pathMutex.Lock()
	defer cd.pathMutex.Unlock()
	cd.currentPath = path
}

// notifyCallbacks invokes all registered callbacks
func (cd *configDiscovery) notifyCallbacks(path string) {
	cd.callbackMutex.RLock()
	callbacks := make([]ConfigChangeCallback, len(cd.callbacks))
	copy(callbacks, cd.callbacks)
	cd.callbackMutex.RUnlock()

	for _, callback := range callbacks {
		callback(path)
	}
}
