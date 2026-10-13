package easyconnect

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func TestMChipExpiredResourceReplyDoesNotPanic(t *testing.T) {
	c := NewClient(Options{})
	defer c.Close()
	if err := c.parseResources(`<Auth><ErrorCode>20026</ErrorCode></Auth>`); !errors.Is(err, ErrMChipSessionExpired) {
		t.Fatalf("expired response: %v", err)
	}
	if err := c.parseResources(`<Resource><Rcs><Rc/></Rcs><Dns data="" dnsserver="192.0.2.53"/></Resource>`); err != nil {
		t.Fatalf("optional attributes: %v", err)
	}
}

type deadlineRaceConn struct {
	net.Conn
	once             sync.Once
	entered, release chan struct{}
	mu               sync.Mutex
	deadline         time.Time
}

func (c *deadlineRaceConn) SetDeadline(v time.Time) error {
	if !v.IsZero() {
		c.once.Do(func() { close(c.entered); <-c.release })
	}
	c.mu.Lock()
	c.deadline = v
	c.mu.Unlock()
	return nil
}
func TestMChipCancellationDeadlineIsClearedAfterCallback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	c := &deadlineRaceConn{entered: make(chan struct{}), release: make(chan struct{})}
	clear, err := armConnectionContext(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-c.entered:
	case <-time.After(time.Second):
		t.Fatal("callback not entered")
	}
	done := make(chan struct{})
	go func() { clear(); close(done) }()
	select {
	case <-done:
		t.Fatal("clear returned before cancellation callback")
	case <-time.After(20 * time.Millisecond):
	}
	close(c.release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("callback not drained")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.deadline.IsZero() {
		t.Fatal("stale cancellation deadline survived handoff")
	}
}
