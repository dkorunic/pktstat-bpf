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
	"net/netip"
	"strings"
)

var protoNumbers = map[uint8]string{
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
	255: "Fragment",
}

// Map of well-known ports to service names
var wellKnownPorts = map[uint16]string{
	1:     "tcpmux",
	5:     "rje",
	7:     "echo",
	9:     "discard",
	11:    "systat",
	13:    "daytime",
	17:    "qotd",
	18:    "msp",
	19:    "chargen",
	20:    "ftp-data",
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	37:    "time",
	42:    "nameserver",
	43:    "nicname",
	49:    "tacacs",
	53:    "dns",
	67:    "bootps",
	68:    "bootpc",
	69:    "tftp",
	70:    "gopher",
	79:    "finger",
	80:    "http",
	81:    "hosts2-ns",
	88:    "kerberos",
	95:    "supdup",
	101:   "hostname",
	102:   "iso-tsap",
	105:   "csnet-ns",
	107:   "rtelnet",
	109:   "pop2",
	110:   "pop3",
	111:   "sunrpc",
	113:   "auth",
	115:   "sftp",
	117:   "uucp-path",
	119:   "nntp",
	123:   "ntp",
	137:   "netbios-ns",
	138:   "netbios-dgm",
	139:   "netbios-ssn",
	143:   "imap",
	161:   "snmp",
	162:   "snmptrap",
	163:   "cmip-man",
	164:   "cmip-agent",
	174:   "mailq",
	177:   "xdmcp",
	178:   "nextstep",
	179:   "bgp",
	191:   "prospero",
	194:   "irc",
	199:   "smux",
	201:   "at-rtmp",
	202:   "at-nbp",
	204:   "at-echo",
	206:   "at-zis",
	209:   "qmtp",
	210:   "z39.50",
	213:   "ipx",
	220:   "imap3",
	245:   "link",
	347:   "fatserv",
	363:   "rsvp_tunnel",
	369:   "rpc2portmap",
	370:   "codaauth2",
	372:   "ulistproc",
	389:   "ldap",
	427:   "svrloc",
	434:   "mobileip-agent",
	435:   "mobilip-mn",
	443:   "https",
	444:   "snpp",
	445:   "microsoft-ds",
	464:   "kpasswd",
	468:   "photuris",
	487:   "saft",
	488:   "gss-http",
	496:   "pim-rp-disc",
	500:   "isakmp",
	538:   "gdomap",
	546:   "dhcpv6-client",
	547:   "dhcpv6-server",
	554:   "rtsp",
	563:   "nntps",
	565:   "whoami",
	587:   "submission",
	610:   "npmp-local",
	611:   "npmp-gui",
	612:   "hmmp-ind",
	631:   "ipp",
	636:   "ldaps",
	674:   "acap",
	694:   "ha-cluster",
	749:   "kerberos-adm",
	750:   "kerberos4",
	751:   "kerberos-master",
	752:   "passwd-server",
	754:   "krb-prop",
	760:   "krbupdate",
	765:   "webster",
	767:   "phonebook",
	808:   "omirr",
	873:   "rsync",
	901:   "swat",
	989:   "ftps-data",
	990:   "ftps",
	992:   "telnets",
	993:   "imaps",
	994:   "ircs",
	995:   "pop3s",
	1080:  "socks",
	1194:  "openvpn",
	1433:  "ms-sql-s",
	1434:  "ms-sql-m",
	1521:  "oracle",
	1723:  "pptp",
	1755:  "wms",
	1863:  "msnp",
	3000:  "node-dev",
	3128:  "squid",
	3306:  "mysql",
	3389:  "ms-wbt-server",
	5060:  "sip",
	5061:  "sips",
	5222:  "xmpp-client",
	5223:  "xmpp-client-ssl",
	5269:  "xmpp-server",
	5432:  "postgresql",
	5984:  "couchdb",
	6379:  "redis",
	6667:  "irc",
	8000:  "http-alt",
	8008:  "http-alt",
	8009:  "ajp13",
	8080:  "http-proxy",
	8443:  "https-alt",
	8883:  "secure-mqtt",
	9090:  "websm",
	9200:  "elasticsearch",
	9418:  "git",
	27017: "mongodb",
	33060: "mysqlx",
}

// protoToString converts a protocol number to its corresponding name.
//
// p: the protocol number to convert.
// string: the name of the protocol.
func protoToString(p uint8) string {
	if v, ok := protoNumbers[p]; ok {
		return v
	}

	return "Unknown"
}

// bytesToAddr converts a 16-byte address to a netip.Addr.
//
// It takes an addr parameter of type [16]byte and returns a netip.Addr.
func bytesToAddr(addr [16]byte) netip.Addr {
	return netip.AddrFrom16(addr).Unmap()
}

// parseInternalNetworks parses a comma-separated list of CIDR strings
// into a slice of netip.Prefix objects
func parseInternalNetworks(cidrs string) ([]netip.Prefix, error) {
	networks := []netip.Prefix{}

	// If no networks specified, return empty list
	if cidrs == "" {
		return networks, nil
	}

	// Split by comma
	cidrList := strings.Split(cidrs, ",")

	// Parse each CIDR
	for _, cidr := range cidrList {
		cidr = strings.TrimSpace(cidr)
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %v", cidr, err)
		}
		networks = append(networks, prefix)
	}

	return networks, nil
}

// isInternalIP checks if the given IP is within any of the provided internal networks
func isInternalIP(ip netip.Addr, networks []netip.Prefix) bool {
	// If no networks defined, consider all IPs external
	if len(networks) == 0 {
		return false
	}

	// Filter out unspecified addresses (0.0.0.0 and ::)
	if ip.IsUnspecified() {
		return true
	}

	// Check if IP is in any of the internal networks
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}

	// IP is not in any internal network
	return false
}

// portToLikelyServiceName converts a port number to its corresponding service name.
//
// port: the port number to convert.
// string: the name of the service or empty string if not found.
func portToLikelyServiceName(port uint16) string {
	if v, ok := wellKnownPorts[port]; ok {
		return v
	}
	return ""
}

// isExternalIP checks if an IP is external (not in common internal ranges)
func isExternalIP(ip netip.Addr) bool {
	// Check if it's in common internal ranges
	internalPrefixes := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16", // link-local
		"224.0.0.0/4",    // multicast
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local
	}

	for _, prefix := range internalPrefixes {
		if p, err := netip.ParsePrefix(prefix); err == nil {
			if p.Contains(ip) {
				return false
			}
		}
	}
	return true
}
