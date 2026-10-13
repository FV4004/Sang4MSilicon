package main

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

var errInvalidFrame = errors.New("invalid IPv4 frame")

// Reconnect at packet boundaries. Partial packets from a dead TLS stream are
// discarded, never spliced into a new stream or retransmitted ambiguously.
type packetTunnel struct {
	ctx      context.Context
	mu       sync.Mutex
	closed   bool
	send     io.WriteCloser
	recv     io.ReadCloser
	openSend func() (io.WriteCloser, error)
	openRecv func() (io.ReadCloser, error)
	retry    func(string)
}

func retryableStreamError(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.ErrShortWrite) {
		return true
	}
	var n net.Error
	return errors.As(err, &n)
}
func (t *packetTunnel) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	t.closed = true
	if t.send != nil {
		_ = t.send.Close()
	}
	if t.recv != nil {
		_ = t.recv.Close()
	}
}
func (t *packetTunnel) replace(direction string) error {
	for attempt := 0; attempt < 3; attempt++ {
		select {
		case <-t.ctx.Done():
			return t.ctx.Err()
		case <-time.After(time.Duration(attempt) * 200 * time.Millisecond):
		}
		t.mu.Lock()
		if t.closed {
			t.mu.Unlock()
			return net.ErrClosed
		}
		t.mu.Unlock()
		if t.retry != nil {
			t.retry(direction)
		}
		if direction == "recv" {
			conn, err := t.openRecv()
			if err != nil {
				if !retryableStreamError(err) {
					return err
				}
				continue
			}
			t.mu.Lock()
			if t.closed {
				t.mu.Unlock()
				_ = conn.Close()
				return net.ErrClosed
			}
			t.recv = conn
			t.mu.Unlock()
			return nil
		}
		conn, err := t.openSend()
		if err != nil {
			if !retryableStreamError(err) {
				return err
			}
			continue
		}
		t.mu.Lock()
		if t.closed {
			t.mu.Unlock()
			_ = conn.Close()
			return net.ErrClosed
		}
		t.send = conn
		t.mu.Unlock()
		return nil
	}
	return errors.New("data channel reconnect exhausted")
}
func (t *packetTunnel) ReadPacket(buf []byte) ([]byte, error) {
	for attempt := 0; attempt < 4; attempt++ {
		t.mu.Lock()
		conn := t.recv
		closed := t.closed
		t.mu.Unlock()
		if closed {
			return nil, net.ErrClosed
		}
		packet, err := readIPv4(conn, buf)
		if err == nil {
			return packet, nil
		}
		if !retryableStreamError(err) || attempt == 3 {
			return nil, err
		}
		_ = conn.Close()
		if err = t.replace("recv"); err != nil {
			return nil, err
		}
	}
	return nil, io.ErrUnexpectedEOF
}
func (t *packetTunnel) WritePacket(packet []byte) error {
	t.mu.Lock()
	conn := t.send
	closed := t.closed
	t.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	n, err := conn.Write(packet)
	if err == nil && n == len(packet) {
		return nil
	}
	if err == nil {
		err = io.ErrShortWrite
	}
	if !retryableStreamError(err) {
		return err
	}
	_ = conn.Close()
	// Drop the ambiguous packet. TCP retransmission belongs to the OS TCP stack.
	return t.replace("send")
}
