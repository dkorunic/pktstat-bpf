// @license
// Copyright (C) 2025  Dinko Korunic
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

//nolint:mnd
package main

import (
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

const (
	naviText = `[white]↑/k[-] up • [white]↓/j[-] down • [white]q/x[-] exit • [white]r[-] redraw & jump on top • [white]0[-] sort by bitrate • [white]1[-] sort by packets • [white]2[-] sort by bytes • [white]3[-] sort by source IP • [white]4[-] sort by dest IP`
)

// drawTUI displays a TUI (text-based user interface) with a table displaying
// packet statistics. The TUI is updated in real time with the latest packet
// statistics. The table has the following columns:
//
//   - Bitrate (in Mbps)
//   - Number of packets
//   - Number of bytes
//   - Protocol (TCP, UDP, ICMP, or Other)
//   - Source IP
//   - Destination IP
//   - Type (ICMP echo request, ICMP echo reply, TCP SYN, TCP FIN, UDP, or Other)
//   - Code (ICMP code, or 0 for non-ICMP packets)
//   - PID (process ID)
//   - Comm (process name)
//   - CGroup (cgroup name)
//
// The TUI is interactive: pressing 'q' or 'x' will exit the program,
// pressing 'r' will redraw the TUI, and pressing any other key will
// do nothing.
// sortFuncs maps the atomic sort index to the corresponding sort function.
var sortFuncs = [...]func([]statEntry){
	bitrateSort, // 0
	packetSort,  // 1
	bytesSort,   // 2
	srcIPSort,   // 3
	dstIPSort,   // 4
}

func drawTUI(pktCount *ebpf.Map, l7 *ebpf.Map, startTime time.Time) {
	app := tview.NewApplication()

	var tableSortIdx atomic.Int32 // 0 = bitrateSort (default)

	statsTable := tview.NewTable().
		SetBorders(true).
		SetSelectable(true, false).
		Select(0, 0).
		SetFixed(1, 1)

	statsTable.SetTitle("Network traffic monitor").
		SetTitleAlign(tview.AlignLeft).
		SetBorder(true)

	statsTable.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Rune() {
		case '0':
			tableSortIdx.Store(0)

			statsTable.Select(0, 0)
		case '1':
			tableSortIdx.Store(1)

			statsTable.Select(0, 0)
		case '2':
			tableSortIdx.Store(2)

			statsTable.Select(0, 0)
		case '3':
			tableSortIdx.Store(3)

			statsTable.Select(0, 0)
		case '4':
			tableSortIdx.Store(4)

			statsTable.Select(0, 0)
		case 'q', 'x', 'Q', 'X':
			app.Stop()
		case 'r', 'R':
			statsTable.Select(0, 0)
			app.ForceDraw()
		}

		return event
	})

	infoView := tview.NewTextView().
		SetTextColor(tcell.ColorYellow)

	switch {
	case *useCGroup != "":
		infoView.SetText("CGroup eBPF mode w/ partial PID and comm tracking")
	case *useKProbes:
		infoView.SetText("KProbes eBPF mode w/ PID and comm tracking")
	case *useXDP:
		infoView.SetText(fmt.Sprintf("XDP (eXpress Data Path) eBPF mode %v on interface %v, only ingress stats",
			*xdpMode, *ifname))
	default:
		infoView.SetText(fmt.Sprintf("TC (Traffic Control) eBPF mode on interface %v", *ifname))
	}

	naviView := tview.NewTextView().
		SetTextColor(tcell.ColorDimGray).
		SetWrap(true).
		SetWordWrap(true).
		SetDynamicColors(true)
	naviView.SetText(naviText)

	grid := tview.NewGrid().SetRows(2, 0, 3).
		AddItem(infoView, 0, 0, 1, 1, 0, 0, false).
		AddItem(statsTable, 1, 0, 1, 1, 0, 0, true).
		AddItem(naviView, 2, 0, 1, 1, 0, 0, false)

	// Closed when app.Run() returns so the updater goroutine can exit.
	done := make(chan struct{})

	go updateStatsTable(app, statsTable, &tableSortIdx, pktCount, l7, startTime, done)

	_ = app.SetRoot(grid, true).
		SetFocus(statsTable).
		Run()

	close(done)
}

// updateStatsTable starts a loop that reads the BPF map and pushes table
// updates to the tview goroutine until done is closed.
//
// Allocation strategy:
//   - statsBufs is a 2-slot rotation; processMap reuses the slot's backing
//     array via the `buf` reuse hint, so steady-state snapshots are alloc-free.
//   - slotMu[i] guards the buffer in statsBufs[i] across the boundary between
//     "processMap is writing it" and "the most recent draw closure is still
//     reading it". This closes a race where, under a slow draw or two-tick
//     backlog, the next processMap would re-truncate the backing array
//     mid-render (listMapBatch does `buf[:0]` then appends).
//   - headerCells / bodyCells are lazily-grown tview cell pools, reused
//     across redraws. When the body row count shrinks we detach the surplus
//     rows from the table (RemoveRow from the bottom up) but keep them in
//     the pool for re-attachment if N grows again.
//
// Columns: bitrate, packets, bytes, proto, src, dst, type/spi/inner/opcode,
// code/flags/version, plus pid/comm/cgroup when --kprobes or --cgroup is set.
func updateStatsTable(app *tview.Application, table *tview.Table, tableSortIdx *atomic.Int32,
	pktCount *ebpf.Map, l7 *ebpf.Map, startTime time.Time, done <-chan struct{},
) {
	ticker := time.NewTicker(*refresh)
	defer ticker.Stop()

	headers := []string{
		"bitrate", // column 0
		"packets", // column 1
		"bytes",   // column 2
		"proto",   // column 3
		"l7",      // column 4
		"src",     // column 5
		"dst",     // column 6
		"type",    // column 7
		"code",    // column 8
		"pid",     // column 9, only kprobes and cgroup
		"comm",    // column 10, only kprobes and cgroup
		"cgroup",  // column 11, only kprobes and cgroup
	}

	// Drop pid/comm/cgroup columns when not in --kprobes / --cgroup mode.
	if !*useKProbes && *useCGroup == "" {
		headers = headers[:9]
	}

	// Hoisted: flags are immutable after startup.
	showProcInfo := *useKProbes || *useCGroup != ""

	// 2-slot rotation; slotMu[i] is held from processMap-write until draw-done.
	var statsBufs [2][]statEntry
	var slotMu [2]sync.Mutex
	bufIdx := 0

	// Lazy cell pools; prevBodyRows tracks rows currently attached.
	var (
		headerCells  []*tview.TableCell
		bodyCells    [][]*tview.TableCell
		prevBodyRows int
	)

	numCols := len(headers)

	for {
		// Wait for the previous draw on this slot to finish before reusing it.
		// If the draw takes longer than one tick period the goroutine blocks
		// here rather than on the ticker, silently dropping that refresh cycle.
		// This is intentional: skipping a refresh is safer than reading a
		// partially-written snapshot. Effective refresh rate floors at
		// max(draw_time, tick_period).
		slotMu[bufIdx].Lock()

		// Read off the tview goroutine so it isn't blocked on the syscall.
		snapshot, _ := processMap(pktCount, l7, startTime, sortFuncs[tableSortIdx.Load()], statsBufs[bufIdx])
		statsBufs[bufIdx] = snapshot

		thisBuf := bufIdx
		bufIdx ^= 1

		// Skip queuing a draw if the app stopped during processMap.
		select {
		case <-done:
			slotMu[thisBuf].Unlock()
			return
		default:
		}

		app.QueueUpdateDraw(func() {
			defer slotMu[thisBuf].Unlock()
			// Build header cells once.
			if headerCells == nil {
				headerCells = make([]*tview.TableCell, numCols)
				for i, v := range headers {
					headerCells[i] = &tview.TableCell{
						Text:            v,
						NotSelectable:   true,
						Align:           tview.AlignLeft,
						Color:           tcell.ColorLightYellow,
						BackgroundColor: tcell.ColorDefault,
						Attributes:      tcell.AttrBold,
					}
					table.SetCell(0, i, headerCells[i])
				}
			}

			// Reused per row to avoid per-tick string allocations.
			var addrBuf []byte

			for i, v := range snapshot {
				switch {
				case i >= len(bodyCells):
					row := make([]*tview.TableCell, numCols)
					for c := range row {
						row[c] = tview.NewTableCell("").
							SetTextColor(tcell.ColorWhite).
							SetExpansion(1)
						table.SetCell(i+1, c, row[c])
					}
					bodyCells = append(bodyCells, row)
				case i >= prevBodyRows:
					// Re-attach a row detached by an earlier shrink.
					for c, cell := range bodyCells[i] {
						table.SetCell(i+1, c, cell)
					}
				}

				row := bodyCells[i]

				row[0].Text = formatBitrate(v.Bitrate)
				row[1].Text = strconv.FormatUint(v.Packets, 10)
				row[2].Text = strconv.FormatUint(v.Bytes, 10)
				row[3].Text = v.Proto
				row[4].Text = v.AppProto

				switch v.Proto {
				case protoICMPv4, protoICMPv6:
					addrBuf = v.SrcIP.AppendTo(addrBuf[:0])
					row[5].Text = string(addrBuf)
					addrBuf = v.DstIP.AppendTo(addrBuf[:0])
					row[6].Text = string(addrBuf)
					row[7].Text = strconv.Itoa(int(v.SrcPort))
					row[8].Text = strconv.Itoa(int(v.DstPort))
				case protoESP, protoAH:
					addrBuf = v.SrcIP.AppendTo(addrBuf[:0])
					row[5].Text = string(addrBuf)
					addrBuf = v.DstIP.AppendTo(addrBuf[:0])
					row[6].Text = string(addrBuf)
					spi := uint32(v.SrcPort)<<16 | uint32(v.DstPort)
					addrBuf = append(addrBuf[:0], '0', 'x')
					addrBuf = strconv.AppendUint(addrBuf, uint64(spi), 16)
					row[7].Text = string(addrBuf)
					row[8].Text = ""
				case protoGRE:
					addrBuf = v.SrcIP.AppendTo(addrBuf[:0])
					row[5].Text = string(addrBuf)
					addrBuf = v.DstIP.AppendTo(addrBuf[:0])
					row[6].Text = string(addrBuf)
					row[7].Text = greInnerName(v.SrcPort)
					addrBuf = append(addrBuf[:0], '0', 'x')
					addrBuf = appendHex16(addrBuf, v.DstPort)
					row[8].Text = string(addrBuf)
				case protoOSPF:
					addrBuf = v.SrcIP.AppendTo(addrBuf[:0])
					row[5].Text = string(addrBuf)
					addrBuf = v.DstIP.AppendTo(addrBuf[:0])
					row[6].Text = string(addrBuf)
					row[7].Text = ospfTypeName(v.SrcPort)
					addrBuf = append(addrBuf[:0], 'v')
					addrBuf = strconv.AppendUint(addrBuf, uint64(v.DstPort), 10)
					row[8].Text = string(addrBuf)
				case protoARP:
					addrBuf = v.SrcIP.AppendTo(addrBuf[:0])
					row[5].Text = string(addrBuf)
					addrBuf = v.DstIP.AppendTo(addrBuf[:0])
					row[6].Text = string(addrBuf)
					row[7].Text = arpOpName(v.SrcPort)
					row[8].Text = ""
				default:
					addrBuf = v.SrcIP.AppendTo(addrBuf[:0])
					addrBuf = append(addrBuf, ':')
					addrBuf = strconv.AppendUint(addrBuf, uint64(v.SrcPort), 10)
					row[5].Text = string(addrBuf)

					addrBuf = v.DstIP.AppendTo(addrBuf[:0])
					addrBuf = append(addrBuf, ':')
					addrBuf = strconv.AppendUint(addrBuf, uint64(v.DstPort), 10)
					row[6].Text = string(addrBuf)

					row[7].Text = ""
					row[8].Text = ""
				}

				if showProcInfo {
					pidStr := ""
					if v.Pid > 0 {
						pidStr = strconv.FormatInt(int64(v.Pid), 10)
					}

					row[9].Text = pidStr
					row[10].Text = v.Comm
					row[11].Text = v.CGroup
				}
			}

			// Detach surplus rows; cells stay pooled for later re-attach.
			for r := prevBodyRows; r > len(snapshot); r-- {
				table.RemoveRow(r)
			}

			prevBodyRows = len(snapshot)
		})

		select {
		case <-ticker.C:
		case <-done:
			return
		}
	}
}
