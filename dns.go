package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func processUDPPackets(ctx context.Context, reader *ringbuf.Reader, dnsLookupMap map[uint32]string, dnsLookupMapMutex *sync.RWMutex) {
	for {
		select {
		case <-ctx.Done():
			return
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

			// just grab the first question for now
			dnsLookupMapMutex.Lock()
			dnsLookupMap[uint32(udpPktDetails.Pid)] = string(dnsLayer.Questions[0].Name)
			dnsLookupMapMutex.Unlock()
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
