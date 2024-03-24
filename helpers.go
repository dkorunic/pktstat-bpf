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

import "net/netip"

// protoToString converts a protocol number to its corresponding name.
//
// p: the protocol number to convert.
// string: the name of the protocol.
func protoToString(p uint8) string {
	switch p {
	case 0x01:
		return "ICMPv4"
	case 0x02:
		return "IGMP"
	case 0x3a:
		return "ICMPv6"
	case 0x06:
		return "TCP"
	case 0x11:
		return "UDP"
	case 0x21:
		return "DCCP"
	case 0x2f:
		return "GRE"
	case 0x84:
		return "SCTP"
	case 0xFF:
		return "Fragment"
	default:
		return "Unsupported"
	}
}

// bytesToAddr converts a 16-byte address to a netip.Addr.
//
// It takes an addr parameter of type [16]byte and returns a netip.Addr.
func bytesToAddr(addr [16]byte) netip.Addr {
	return netip.AddrFrom16(addr).Unmap()
}
