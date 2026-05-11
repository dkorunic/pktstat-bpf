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
	"net"
	"net/netip"
	"strconv"
	"strings"
)

var protoNames = func() [256]string {
	var a [256]string

	for k, v := range map[uint8]string{
		0:   "IPv4",
		1:   "ICMPv4",
		2:   "IGMP",
		3:   "GGP",
		4:   "IP-ENCAP",
		5:   "ST",
		6:   "TCP",
		8:   "EGP",
		9:   "IGP",
		12:  "PUP",
		17:  "UDP",
		20:  "HMP",
		22:  "XNS-IDP",
		27:  "RDP",
		29:  "ISO-TP4",
		33:  "DCCP",
		36:  "XTP",
		37:  "DDP",
		38:  "IDPR-CMTP",
		41:  "IPv6",
		43:  "IPv6-Route",
		44:  "IPv6-Frag",
		45:  "IDRP",
		46:  "RSVP",
		47:  "GRE",
		50:  "IPSEC-ESP",
		51:  "IPSEC-AH",
		57:  "SKIP",
		58:  "IPv6-ICMP",
		59:  "IPv6-NoNxt",
		60:  "IPv6-Opts",
		73:  "RSPF",
		81:  "VMTP",
		88:  "EIGRP",
		89:  "OSPFIGP",
		93:  "AX.25",
		94:  "IPIP",
		97:  "ETHERIP",
		98:  "ENCAP",
		99:  "Tailscale", // TSMP
		103: "PIM",
		108: "IPCOMP",
		112: "VRRP",
		115: "L2TP",
		124: "ISIS",
		132: "SCTP",
		133: "FC",
		135: "Mobility-Header",
		136: "UDPLite",
		137: "MPLS-in-IP",
		138: "MANET",
		139: "HIP",
		140: "Shim6",
		141: "WESP",
		142: "ROHC",
		143: "Ethernet",
		253: "TCP-RETX", // synthetic; TCP retransmission
		254: "ARP",      // synthetic; not a real IP protocol
		255: "Fragment",
	} {
		a[k] = v
	}

	return a
}()

// protoToString converts a protocol number to its corresponding name.
//
// p: the protocol number to convert.
// string: the name of the protocol.
func protoToString(p uint8) string {
	if s := protoNames[p]; s != "" {
		return s
	}

	return "Unknown"
}

// ospfTypeNames indexes 1..5 to OSPF packet type names (RFC 2328 §A.3).
var ospfTypeNames = [...]string{"", "Hello", "DBDesc", "LSReq", "LSUpd", "LSAck"}

// ospfTypeName returns the name for an OSPF packet type. Out-of-range values
// fall back to the numeric string.
func ospfTypeName(t uint16) string {
	if int(t) >= 1 && int(t) < len(ospfTypeNames) {
		return ospfTypeNames[t]
	}

	return strconv.FormatUint(uint64(t), 10)
}

// arpOpNames indexes ARP/RARP opcodes 1..4 (RFC 826 / RFC 903).
var arpOpNames = [...]string{"", "request", "reply", "rev-req", "rev-reply"}

func arpOpName(op uint16) string {
	if int(op) >= 1 && int(op) < len(arpOpNames) {
		return arpOpNames[op]
	}

	return strconv.FormatUint(uint64(op), 10)
}

// greInnerNames maps known EtherTypes used as the GRE inner-protocol field.
var greInnerNames = map[uint16]string{
	0x0800: "IPv4",
	0x86DD: "IPv6",
	0x6558: "TransEth",
	0x8847: "MPLS",
	0x8848: "MPLS-MC",
	0x0806: "ARP",
}

func greInnerName(t uint16) string {
	if s, ok := greInnerNames[t]; ok {
		return s
	}

	return "0x" + strconv.FormatUint(uint64(t), 16)
}

// bytesToAddr converts a 16-byte address to a netip.Addr.
//
// It takes an addr parameter of type [16]byte and returns a netip.Addr.
func bytesToAddr(addr [16]byte) netip.Addr {
	return netip.AddrFrom16(addr).Unmap()
}

// findFirstEtherIface returns the name of the first non-loopback, up Ethernet interface.
//
// It iterates over all network interfaces and checks if each interface is up and not a loopback interface.
// If an interface meets these criteria, its name is returned. If no suitable interface is found, the default
// interface name is returned.
//
// Returns:
//
//	string: The name of the first non-loopback, up Ethernet interface.
func findFirstEtherIface() string {
	i, err := net.Interfaces()
	if err != nil {
		return defaultIface
	}

	for _, f := range i {
		if (f.Flags&net.FlagUp == 0) || (f.Flags&net.FlagLoopback) != 0 {
			continue
		}

		if strings.Contains(f.Name, "docker") {
			continue
		}

		return f.Name
	}

	return defaultIface
}
