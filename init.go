// @license
// Copyright (C) 2024  Dinko Korunic
//
// SPDX-License-Identifier: MIT

package main

import "strings"

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
