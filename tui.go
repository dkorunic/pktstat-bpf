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

package main

import (
	"fmt"
	"strconv"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
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
//
// The TUI is interactive: pressing 'q' or 'x' will exit the program,
// pressing 'r' or 'l' will redraw the TUI, and pressing any other key will
// do nothing.
func drawTUI(objs counterObjects, startTime time.Time) {
	app := tview.NewApplication()
	tableSort := bitrateSort

	// packet statistics
	statsTable := tview.NewTable().
		SetBorders(true).
		SetSelectable(true, false).
		Select(0, 0).
		SetFixed(1, 1)

	statsTable.SetTitle("Packet statistics").
		SetTitleAlign(tview.AlignLeft).
		SetBorder(true)

	statsTable.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Rune() {
		case '0':
			tableSort = bitrateSort
			statsTable.Select(0, 0)
		case '1':
			tableSort = packetSort
			statsTable.Select(0, 0)
		case '2':
			tableSort = bytesSort
			statsTable.Select(0, 0)
		case '3':
			tableSort = srcIPSort
			statsTable.Select(0, 0)
		case '4':
			tableSort = dstIPSort
			statsTable.Select(0, 0)
		case 'q', 'x', 'Q', 'X':
			app.Stop()
		case 'r', 'R':
			statsTable.Select(0, 0)
			app.ForceDraw()
		}

		return event
	})

	// info view
	infoView := tview.NewTextView().
		SetTextColor(tcell.ColorYellow)
	switch {
	case *useKProbes:
		infoView.SetText("KProbes eBPF mode w/ PID and comm tracking")
	case *useXDP:
		infoView.SetText(fmt.Sprintf("XDP (eXpress Data Path) eBPF mode %v on interface %v, only ingress stats",
			*xdpMode, *ifname))
	default:
		infoView.SetText(fmt.Sprintf("TC (Traffic Control) eBPF mode on interface %v", *ifname))

	}

	// navigation
	naviView := tview.NewTextView().
		SetTextColor(tcell.ColorYellow)
	naviView.SetText("Use cursor keys to move through the table. Press 'q' or 'x' to exit, 'r' for a jump to the beginning and a redraw.\nPress '0' for bitrate desc sort, '1' for packet desc sort, '2' for bytes desc sort, '3' for source IP asc sort, '4' for destination IP asc sort.")

	// grid layout
	grid := tview.NewGrid().SetRows(2, 0, 3).
		AddItem(infoView, 0, 0, 1, 1, 0, 0, false).
		AddItem(statsTable, 1, 0, 1, 1, 0, 0, true).
		AddItem(naviView, 2, 0, 1, 1, 0, 0, false)

	// start the update loop
	go updateStatsTable(app, statsTable, &tableSort, objs, startTime)

	_ = app.SetRoot(grid, true).
		SetFocus(statsTable).
		Run()
}

// updateStatsTable starts an infinite loop that updates the given table with
// packet statistics at regular intervals. The loop is stopped when the
// application is stopped.
//
// The table is populated with the following columns:
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
//
// Note that the table is cleared and recreated on each iteration, so any cell
// attributes are lost on each iteration.
func updateStatsTable(app *tview.Application, table *tview.Table, tableSort *func(stats []statEntry),
	objs counterObjects, startTime time.Time,
) {
	headers := []string{
		"bitrate", // column 0
		"packets", // column 1
		"bytes",   // column 2
		"proto",   // column 3
		"src",     // column 4
		"dst",     // column 5
		"type",    // column 6
		"code",    // column 7
		"pid",     // column 8
		"comm",    // column 9
	}

	for {
		table.Clear()

		for i, v := range headers {
			table.SetCell(0, i, &tview.TableCell{
				Text:            v,
				NotSelectable:   true,
				Align:           tview.AlignLeft,
				Color:           tcell.ColorLightYellow,
				BackgroundColor: tcell.ColorDefault,
				Attributes:      tcell.AttrBold,
			})
		}

		m, _ := processMap(objs.PktCount, startTime, *tableSort)

		for i, v := range m {
			// populate bitrate, packets, bytes and proto
			table.SetCell(i+1, 0, tview.NewTableCell(formatBitrate(v.Bitrate)).
				SetTextColor(tcell.ColorWhite).
				SetExpansion(1))

			table.SetCell(i+1, 1, tview.NewTableCell(strconv.FormatUint(v.Packets, 10)).
				SetTextColor(tcell.ColorWhite).
				SetExpansion(1))

			table.SetCell(i+1, 2, tview.NewTableCell(strconv.FormatUint(v.Bytes, 10)).
				SetTextColor(tcell.ColorWhite).
				SetExpansion(1))

			table.SetCell(i+1, 3, tview.NewTableCell(v.Proto).
				SetTextColor(tcell.ColorWhite).
				SetExpansion(1))

			// populate src, dst, src port, dst port, type and code
			switch v.Proto {
			case "ICMPv4", "IPv6-ICMP":
				table.SetCell(i+1, 4, tview.NewTableCell(v.SrcIP.String()).
					SetTextColor(tcell.ColorWhite).
					SetExpansion(1))

				table.SetCell(i+1, 5, tview.NewTableCell(v.DstIP.String()).
					SetTextColor(tcell.ColorWhite).
					SetExpansion(1))

				table.SetCell(i+1, 6, tview.NewTableCell(strconv.Itoa(int(v.SrcPort))).
					SetTextColor(tcell.ColorWhite).
					SetExpansion(1))

				table.SetCell(i+1, 7, tview.NewTableCell(strconv.Itoa(int(v.DstPort))).
					SetTextColor(tcell.ColorWhite).
					SetExpansion(1))
			default:
				table.SetCell(i+1, 4, tview.NewTableCell(fmt.Sprintf("%v:%d", v.SrcIP, v.SrcPort)).
					SetTextColor(tcell.ColorWhite).
					SetExpansion(1))

				table.SetCell(i+1, 5, tview.NewTableCell(fmt.Sprintf("%v:%d", v.DstIP, v.DstPort)).
					SetTextColor(tcell.ColorWhite).
					SetExpansion(1))

				table.SetCell(i+1, 6, tview.NewTableCell("").
					SetTextColor(tcell.ColorWhite).
					SetExpansion(1))

				table.SetCell(i+1, 7, tview.NewTableCell("").
					SetTextColor(tcell.ColorWhite).
					SetExpansion(1))
			}

			// populate pid and comm
			if *useKProbes {
				table.SetCell(i+1, 8, tview.NewTableCell(strconv.FormatInt(int64(v.Pid), 10)).
					SetTextColor(tcell.ColorWhite).
					SetExpansion(1))

				table.SetCell(i+1, 9, tview.NewTableCell(v.Comm).
					SetTextColor(tcell.ColorWhite).
					SetExpansion(1))
			} else {
				table.SetCell(i+1, 8, tview.NewTableCell("").
					SetTextColor(tcell.ColorWhite).
					SetExpansion(1))

				table.SetCell(i+1, 9, tview.NewTableCell("").
					SetTextColor(tcell.ColorWhite).
					SetExpansion(1))
			}
		}

		app.Draw()
		time.Sleep(*refresh)
	}
}
