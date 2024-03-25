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
	"fmt"
	"os"
	"time"

	"github.com/peterbourgon/ff/v4"
	"github.com/peterbourgon/ff/v4/ffhelp"
)

const (
	defaultIface   = "eth0"
	defaultTimeout = 1 * time.Hour
)

var (
	ifname                    *string
	jsonOutput, version, help *bool
	timeout                   *time.Duration
)

func parseFags() {
	fs := ff.NewFlagSet("pktstat-bpf")

	help = fs.Bool('?', "help", "display help")
	jsonOutput = fs.Bool('j', "json", "if true, output in JSON format")

	version = fs.BoolLong("version", "display program version")

	ifname = fs.String('i', "iface", findFirstEtherIface(), "interface to read from")

	timeout = fs.Duration('t', "timeout", defaultTimeout, "timeout for packet capture")

	var err error

	if err = ff.Parse(fs, os.Args[1:]); err != nil {
		fmt.Printf("%s\n", ffhelp.Flags(fs))
		fmt.Printf("Error: %v\n", err)

		os.Exit(1)
	}

	if *help {
		fmt.Printf("%s\n", ffhelp.Flags(fs))

		os.Exit(0)
	}

	if *version {
		fmt.Printf("pktstat-bpf %v %v%v, built on: %v\n", GitTag, GitCommit, GitDirty, BuildTime)

		os.Exit(0)
	}
}
