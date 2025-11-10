package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func processUDPPackets(ctx context.Context, reader *ringbuf.Reader) {
	seenDNSPackets := map[statEntry]struct{}{}
	resetSeenPacketsTick := time.NewTicker(time.Minute)
	defer resetSeenPacketsTick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-resetSeenPacketsTick.C:
			// Reset the seenDNSPacketIDs map every once in a while so it doesn't grow unbounded,
			// as well the unlikely case a random ID gets re-used. There is a small chance we reset
			// this in between processing packets that would result in a duplicate entry, but that's fine.
			seenDNSPackets = map[statEntry]struct{}{}
		default:
			record, err := reader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}

				log.Printf("Error reading UDP Packet: %v", err)
				continue
			}

			udpPktDetails, packet, err := parseUDPPacketRecord(record)
			if err != nil {
				log.Printf("Error handling UDP Packet: %v", err)
				continue
			}

			layer := packet.Layer(layers.LayerTypeDNS)
			if layer == nil {
				log.Printf("Skipping udp packet: does not contain a dns layer")
				continue
			}

			dnsLayer, ok := layer.(*layers.DNS)
			if !ok {
				log.Printf("Skipping udp packet: couldn't convert to dns layer")
				continue
			}

			if len(dnsLayer.Questions) == 0 {
				log.Printf("Skipping dns packet: no questions")
			}

			if len(dnsLayer.Questions) > 0 && dnsLayer.Questions[0].Type == layers.DNSTypeHINFO {
				continue // Skip HINFO queries
			}

			// Skip DNS queries for the current hostname
			if len(dnsLayer.Questions) > 0 {
				queryName := strings.TrimSuffix(string(dnsLayer.Questions[0].Name), ".")
				if hostname, err := os.Hostname(); err == nil {
					if strings.EqualFold(queryName, hostname) {
						continue // Skip queries for current hostname
					}
				}
			}

			entry := statEntry{
				SrcPort:       udpPktDetails.SrcPort,
				SrcIP:         bytesToAddr(udpPktDetails.Srcip.In6U.U6Addr8),
				DstPort:       udpPktDetails.DstPort,
				DstIP:         bytesToAddr(udpPktDetails.Dstip.In6U.U6Addr8),
				Proto:         "UDP",
				Pid:           udpPktDetails.Pid,
				Comm:          comm2String(udpPktDetails.Comm[:]),
				DNSQueryName:  string(dnsLayer.Questions[0].Name),
				LikelyService: "dns",
			}

			if getKubeClient() != nil {
				entry.SourcePod = lookupPodForIP(entry.SrcIP)
				entry.DstPod = lookupPodForIP(entry.DstIP)
			}

			// Currently we see the same DNS packet make it's journey from the originating process,
			// to the local dns resolver, and on it's way out of the VM's network. This results in
			// quite a few duplicate events being printed to stdout. So check if this would cause
			// a duplicate output and skip printing it if so.
			if _, ok := seenDNSPackets[entry]; ok {
				log.Printf("Skipping DNS packet we've already seen")
				continue
			} else {
				seenDNSPackets[entry] = struct{}{}
			}

			entry.Timestamp = time.Now().UTC()
			fmt.Print(outputJSON([]statEntry{entry}))
		}
	}
}

func parseUDPPacketRecord(rec ringbuf.Record) (counterUdpPkt, gopacket.Packet, error) {
	udpPkt := counterUdpPkt{}
	if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &udpPkt); err != nil {
		return udpPkt, nil, fmt.Errorf("reading record: %w", err)
	}

	pktBytes := [4096]byte(udpPkt.Pkt)
	parsedPacket := gopacket.NewPacket(pktBytes[:], layers.LayerTypeDNS, gopacket.DecodeOptions{NoCopy: true})
	return udpPkt, parsedPacket, nil
}
