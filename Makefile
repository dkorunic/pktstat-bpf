# Variables
TARGET := pktstat-bpf
VERSION ?= $(shell git describe --abbrev=0 --tags 2>/dev/null || echo latest)
GIT_HEAD_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
GIT_TAG_COMMIT := $(shell git rev-parse --short $(VERSION) 2>/dev/null || echo unknown)
GIT_MODIFIED1 := $(shell git diff $(GIT_HEAD_COMMIT) $(GIT_TAG_COMMIT) --quiet 2>/dev/null || echo .dev)
GIT_MODIFIED2 := $(shell git diff --quiet 2>/dev/null || echo .dirty)
GIT_MODIFIED := $(GIT_MODIFIED1)$(GIT_MODIFIED2)
BUILD_DATE := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')

# Environment variables
export CGO_ENABLED := 0

# Targets
.PHONY: generate build

generate:
	go generate

build:
	go build -trimpath -pgo=auto -ldflags="-s -w -X main.GitTag=$(VERSION) -X main.GitCommit=$(GIT_HEAD_COMMIT) -X main.GitDirty=$(GIT_MODIFIED) -X main.BuildTime=$(BUILD_DATE)" -o $(TARGET) 