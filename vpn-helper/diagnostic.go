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
	anchors                              map[[13]byte]*tcpSequenceAnchor
	badIPTX, badTCPTX, badIPRX, badTCPRX uint64
	dropNotedTX, dropNotedRX             bool
	mu                                   sync.Mutex
	start                                time.Time
	events                               []string
	txTry, txOK, rxOK                    uint64
	localClose                           bool
	vip                                  [4]byte
	flows                                map[[13]byte]int
	packets                              []string
	guard                                *tcpSessionGuard
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
	result := fmt.Sprintf("D12 tx_try=%d tx_ok=%d rx_ok=%d age_ms=%d timeline=%s", d.txTry, d.txOK, d.rxOK, time.Since(d.start).Milliseconds(), strings.Join(d.events, ",")) + " packets=" + strings.Join(d.packets, ",")
	if d.guard != nil {
		d.guard.mu.Lock()
		result += fmt.Sprintf(" tcp_drop_tx=%d tcp_drop_rx=%d local_rst=%d", d.guard.droppedTX, d.guard.droppedRX, d.guard.resets)
		d.guard.mu.Unlock()
	}
	return result + fmt.Sprintf(" ip_bad_tx=%d tcp_bad_tx=%d ip_bad_rx=%d tcp_bad_rx=%d", d.badIPTX, d.badTCPTX, d.badIPRX, d.badTCPRX)
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
	if len(packet) < 20 || packet[0]>>4 != 4 {
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
	side := 0
	if string(left[:]) > string(right[:]) {
		side = 1
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
	if flow == 0 && len(d.flows) < 32 {
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
	ipCK := "GOOD"
	if packetChecksum(packet[:ihl]) != 0 {
		ipCK = "BAD"
		if direction == "TX" {
			d.badIPTX++
		} else if direction == "RX" {
			d.badIPRX++
		}
	}
	tcpCK, seqRel, ackRel := "NA", "NA", "NA"
	if proto == 6 && !fragment && flags != "NA" {
		pseudo := make([]byte, 12+total-ihl)
		copy(pseudo[:8], packet[12:20])
		pseudo[9] = 6
		binary.BigEndian.PutUint16(pseudo[10:12], uint16(total-ihl))
		copy(pseudo[12:], packet[ihl:total])
		tcpCK = "GOOD"
		if packetChecksum(pseudo) != 0 {
			tcpCK = "BAD"
			if direction == "TX" {
				d.badTCPTX++
			} else if direction == "RX" {
				d.badTCPRX++
			}
		}
		clear(pseudo)
		if flow != 0 {
			if d.anchors == nil {
				d.anchors = make(map[[13]byte]*tcpSequenceAnchor)
			}
			anchor := d.anchors[key]
			if anchor == nil {
				anchor = &tcpSequenceAnchor{}
				d.anchors[key] = anchor
			}
			seq := binary.BigEndian.Uint32(packet[ihl+4 : ihl+8])
			ack := binary.BigEndian.Uint32(packet[ihl+8 : ihl+12])
			tcpFlags := packet[ihl+13]
			if tcpFlags&2 != 0 {
				if tcpFlags&0x10 == 0 && anchor.seen[side] && anchor.base[side] != seq {
					*anchor = tcpSequenceAnchor{}
				}
				if !anchor.seen[side] {
					anchor.seen[side] = true
					anchor.base[side] = seq
				}
			}
			if anchor.seen[side] {
				seqRel = fmt.Sprint(seq - anchor.base[side])
			}
			if tcpFlags&0x10 != 0 && anchor.seen[1-side] {
				ackRel = fmt.Sprint(ack - anchor.base[1-side])
			}
		}
	}
	entry := fmt.Sprintf("%s_F%d_%s_FLAGS_%s_SRC_%s_DST_%s_LEN_%d_PAY_%d_IPCK_%s_TCPCK_%s_SEQREL_%s_ACKREL_%s@%dms", direction, flow, kind, flags, source, peer, total, payload, ipCK, tcpCK, seqRel, ackRel, time.Since(d.start).Milliseconds())
	if len(d.packets) < 12 {
		d.packets = append(d.packets, entry)
	} else {
		copy(d.packets[6:], d.packets[7:])
		d.packets[11] = entry
	}
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

func (d *diagnosticState) filtered(packet []byte, out bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if out {
		d.packetLocked("DROP_TX", packet)
		if !d.dropNotedTX {
			d.noteLocked("TCP_EPOCH_DROP_TX")
			d.dropNotedTX = true
		}
	} else {
		d.packetLocked("DROP_RX", packet)
		if !d.dropNotedRX {
			d.noteLocked("TCP_EPOCH_DROP_RX")
			d.dropNotedRX = true
		}
	}
}

type tcpSequenceAnchor struct {
	base [2]uint32
	seen [2]bool
}
