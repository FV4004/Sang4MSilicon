package main

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// Each privileged worker owns one session. No payloads, endpoints or credentials
// are retained; even unknown control bytes are represented only as OTHER.
type diagnosticState struct {
	mu                sync.Mutex
	start             time.Time
	events            []string
	txTry, txOK, rxOK uint64
	localClose        bool
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
func (d *diagnosticState) received() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.rxOK++
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
	return fmt.Sprintf("D12 tx_try=%d tx_ok=%d rx_ok=%d age_ms=%d timeline=%s", d.txTry, d.txOK, d.rxOK, time.Since(d.start).Milliseconds(), strings.Join(d.events, ","))
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
