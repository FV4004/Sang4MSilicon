package main

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDiagnosticIdleEOFPrecedesFirstWrite(t *testing.T) {
	d := &diagnosticState{start: time.Now()}
	r, w := io.Pipe()
	done := make(chan struct{})
	go func() { d.observe(context.Background(), r, "SEND"); close(done) }()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("observer did not detect idle EOF")
	}
	p := make([]byte, 20)
	p[0] = 0x45
	p[9] = 6
	d.sendBegin(p)
	text := d.summary()
	eof, write := strings.Index(text, "SEND_EOF@"), strings.Index(text, "TX_BEGIN_TCP@")
	if eof < 0 || write < eof || !strings.Contains(text, "tx_try=1 tx_ok=0 rx_ok=0") {
		t.Fatal(text)
	}
}
func TestDiagnosticNeverRetainsPayloadOrRawErrors(t *testing.T) {
	d := &diagnosticState{start: time.Now()}
	d.observe(context.Background(), strings.NewReader("password-session-private-address"), "CONTROL")
	text := d.summary()
	if strings.Contains(text, "password") || strings.Contains(text, "private") || !strings.Contains(text, "CONTROL_FIRST_PREFIX_OTHER_UNPARSED") {
		t.Fatal(text)
	}
	d.observe(context.Background(), errorReader{}, "SEND")
	if strings.Contains(d.summary(), "credentials") || !strings.Contains(d.summary(), "SEND_READ_ERROR") {
		t.Fatal(d.summary())
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("private credentials") }
func TestDiagnosticCancellationAndLocalCloseDoNotLookRemote(t *testing.T) {
	for _, local := range []bool{false, true} {
		d := &diagnosticState{start: time.Now()}
		ctx, cancel := context.WithCancel(context.Background())
		if local {
			d.closing()
		} else {
			cancel()
		}
		d.observe(ctx, strings.NewReader(""), "SEND")
		cancel()
		if strings.Contains(d.summary(), "SEND_EOF") {
			t.Fatal(d.summary())
		}
	}
}
func TestDiagnosticCountsAndBoundedConcurrentTimeline(t *testing.T) {
	d := &diagnosticState{start: time.Now()}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); d.sendBegin(nil); d.sent(); d.received(nil); d.note("RECONNECT_send") }()
	}
	wg.Wait()
	text := d.summary()
	if !strings.Contains(text, "tx_try=100 tx_ok=100 rx_ok=100") || len(d.events) > 20 || len(text) > 2048 {
		t.Fatal(text)
	}
}
