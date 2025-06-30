package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/cilium/ebpf/ringbuf"
)

func processDNSEvents(ctx context.Context, reader *ringbuf.Reader, dnsLookupMap map[uint32]string, dnsLookupMapMutex *sync.RWMutex) error {
	perfChan := make(chan []byte, 0)

	go func(perfChan chan []byte, reader *ringbuf.Reader) {
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
					log.Printf("Error reading DNS event: %v", err)
					continue
				}
				perfChan <- record.RawSample
			}
		}
	}(perfChan, reader)

	var event dnsLookupEvent

	for {
		select {
		case <-time.After(1 * time.Millisecond):
			continue
		case <-ctx.Done():
			return nil
		default:
			record, ok := <-perfChan
			if !ok {
				panic("perfChan closed")
			}
			err := binary.Read(bytes.NewReader(record), binary.LittleEndian, &event)
			if err != nil {
				log.Printf("Error reading DNS event: %v", err)
				continue
			}

			hostname := nullTerminatedString(event.Host[:])

			// Store PID to hostname mapping for all DNS events that have a hostname
			if hostname != "" {
				dnsLookupMapMutex.Lock()
				dnsLookupMap[event.Pid] = hostname
				dnsLookupMapMutex.Unlock()
			}
		}
	}
}

// Helper function to extract null-terminated strings from byte arrays
func nullTerminatedString(data []byte) string {
	for i, b := range data {
		if b == 0 {
			return string(data[:i])
		}
	}
	return string(data)
}
