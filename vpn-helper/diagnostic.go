package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// Each worker owns one session. Reports contain no payloads, endpoints or
// credentials. Flow keys exist only in a small transient in-memory map.
type diagnosticState struct {
	mu                sync.Mutex
	start             time.Time
	events            []string
	txTry, txOK, rxOK uint64
	localClose        bool
	vip               [4]byte
	flows             map[[13]byte]int
	packets           []string
}

var diag = &diagnosticState{start: time.Now()}

func (d *diagnosticState) noteLocked(label string) {
	if len(d.events) < 20 {
		d.events = append(d.events, fmt.Sprintf("%s@%dms", label, time.Since(d.start).Milliseconds()))
	}
}
func (d *diagnosticState) note(label string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.localClose {
		d.noteLocked(label)
	}
}
func (d *diagnosticState) sendBegin(packet []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.txTry++
	d.packetLocked("TX", packet)
	if d.txTry <= 3 {
		kind := "OTHER"
		if len(packet) >= 20 && packet[0]>>4 == 4 {
			switch packet[9] {
			case 1:
				kind = "ICMP"
			case 6:
				kind = "TCP"
			case 17:
				kind = "UDP"
			}
		}
		d.noteLocked("TX_BEGIN_" + kind)
	}
}
func (d *diagnosticState) sent() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.txOK++
	if d.txOK == 1 {
		d.noteLocked("TX_FIRST_OK")
	}
}
func (d *diagnosticState) received(packet []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.rxOK++
	d.packetLocked("RX", packet)
	if d.rxOK == 1 {
		d.noteLocked("RX_FIRST_OK")
	}
}
func (d *diagnosticState) closing() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.localClose {
		d.noteLocked("LOCAL_CLOSE")
		d.localClose = true
	}
}
func (d *diagnosticState) summary() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return fmt.Sprintf("D12 tx_try=%d tx_ok=%d rx_ok=%d age_ms=%d timeline=%s", d.txTry, d.txOK, d.rxOK, time.Since(d.start).Milliseconds(), strings.Join(d.events, ",")) + " packets=" + strings.Join(d.packets, ",")
}

// One observer per otherwise unread direction. Never writes a guessed reply,
// closes a connection, changes deadlines or treats a read boundary as a frame.
func (d *diagnosticState) observe(ctx context.Context, reader io.Reader, label string) {
	d.note(label + "_WATCH")
	first := true
	var scratch [4096]byte
	for {
		n, err := reader.Read(scratch[:])
		if ctx.Err() != nil {
			return
		}
		if n > 0 && first {
			prefix := "OTHER"
			switch scratch[0] {
			case 0x08:
				prefix = "08"
			case 0x0e:
				prefix = "0E"
			case 0x0f:
				prefix = "0F"
			}
			d.note(label + "_FIRST_PREFIX_" + prefix + "_UNPARSED")
			first = false
		}
		// No raw data is retained beyond this bounded scratch buffer.
		clear(scratch[:])
		if err != nil {
			kind := "READ_ERROR"
			if err == io.EOF {
				kind = "EOF"
			}
			d.note(label + "_" + kind)
			return
		}
		if n == 0 {
			d.note(label + "_EMPTY_READ")
			return
		}
	}
}

func (d *diagnosticState) setVIP(ip []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(ip) == 4 {
		copy(d.vip[:], ip)
	}
}
func (d *diagnosticState) packetLocked(direction string, packet []byte) {
	if len(d.packets) >= 12 || len(packet) < 20 || packet[0]>>4 != 4 {
		return
	}
	ihl := int(packet[0]&15) * 4
	if ihl < 20 || ihl > len(packet) {
		return
	}
	total := int(binary.BigEndian.Uint16(packet[2:4]))
	if total < ihl || total > len(packet) {
		return
	}
	source, peer := "OTHER", "OTHER"
	if string(packet[12:16]) == string(d.vip[:]) {
		source = "VIP"
	}
	if string(packet[16:20]) == string(d.vip[:]) {
		peer = "VIP"
	}
	proto := packet[9]
	fragment := binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0
	var left, right [6]byte
	copy(left[:4], packet[12:16])
	copy(right[:4], packet[16:20])
	flags := "NA"
	payload := total - ihl
	if !fragment && (proto == 6 || proto == 17) && total >= ihl+4 {
		copy(left[4:], packet[ihl:ihl+2])
		copy(right[4:], packet[ihl+2:ihl+4])
	}
	if !fragment && proto == 6 && total >= ihl+20 {
		header := int(packet[ihl+12]>>4) * 4
		if header >= 20 && ihl+header <= total {
			flags = fmt.Sprintf("%02X", packet[ihl+13])
			payload = total - ihl - header
		}
	}
	if !fragment && proto == 17 && total >= ihl+8 {
		payload = total - ihl - 8
	}
	if string(left[:]) > string(right[:]) {
		left, right = right, left
	}
	var key [13]byte
	copy(key[:6], left[:])
	copy(key[6:12], right[:])
	key[12] = proto
	if d.flows == nil {
		d.flows = make(map[[13]byte]int)
	}
	flow := d.flows[key]
	if flow == 0 {
		flow = len(d.flows) + 1
		d.flows[key] = flow
	}
	kind := fmt.Sprintf("P%d", proto)
	switch proto {
	case 6:
		kind = "TCP"
	case 17:
		kind = "UDP"
	case 1:
		kind = "ICMP"
	}
	if fragment {
		kind += "_FRAG"
	}
	d.packets = append(d.packets, fmt.Sprintf("%s_F%d_%s_FLAGS_%s_SRC_%s_DST_%s_LEN_%d_PAY_%d@%dms", direction, flow, kind, flags, source, peer, total, payload, time.Since(d.start).Milliseconds()))
}
func (d *diagnosticState) publishSnapshots(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			emit(map[string]string{"event": "diagnostic", "diagnostic": d.summary()})
		}
	}
}
