// @license
// Copyright (C) 2026  Dinko Korunic
//
// SPDX-License-Identifier: MIT

package main

import "testing"

func TestOSPFTypeName(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   uint16
		want string
	}{
		{1, "Hello"},
		{2, "DBDesc"},
		{3, "LSReq"},
		{4, "LSUpd"},
		{5, "LSAck"},
		{0, "0"},
		{6, "6"},
		{255, "255"},
	}

	for _, c := range cases {
		got := ospfTypeName(c.in)
		if got != c.want {
			t.Errorf("ospfTypeName(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestARPOpName(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   uint16
		want string
	}{
		{1, "request"},
		{2, "reply"},
		{3, "rev-req"},
		{4, "rev-reply"},
		{0, "0"},
		{5, "5"},
	}

	for _, c := range cases {
		got := arpOpName(c.in)
		if got != c.want {
			t.Errorf("arpOpName(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestGREInnerName(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   uint16
		want string
	}{
		{0x0800, "IPv4"},
		{0x86DD, "IPv6"},
		{0x6558, "TransEth"},
		{0x8847, "MPLS"},
		{0x8848, "MPLS-MC"},
		{0x0806, "ARP"},
		{0x1234, "0x1234"},
	}

	for _, c := range cases {
		got := greInnerName(c.in)
		if got != c.want {
			t.Errorf("greInnerName(0x%04x) = %q, want %q", c.in, got, c.want)
		}
	}
}
