package main

import (
	"bytes"
	"context"
	"errors"
	easyconnect "github.com/mythologyli/zju-connect/client/easyconnect"
	"io"
	"net"
	"testing"
)

type testReadCloser struct{ io.Reader }

func (testReadCloser) Close() error { return nil }

type testWriteCloser struct {
	bytes.Buffer
	fail bool
}

func (w *testWriteCloser) Close() error { return nil }
func (w *testWriteCloser) Write(p []byte) (int, error) {
	if w.fail {
		return len(p) / 2, io.ErrUnexpectedEOF
	}
	return w.Buffer.Write(p)
}
func TestPacketReconnectDiscardsTruncatedOldFrame(t *testing.T) {
	a, b := packet([]byte("old packet")), packet([]byte("fresh response"))
	calls := 0
	tunnel := packetTunnel{ctx: context.Background(), recv: testReadCloser{bytes.NewReader(a[:23])}, openRecv: func() (io.ReadCloser, error) { calls++; return testReadCloser{fragmented{bytes.NewReader(b)}}, nil }}
	got, err := tunnel.ReadPacket(make([]byte, 65535))
	if err != nil || !bytes.Equal(got, b) || calls != 1 {
		t.Fatalf("packet handoff failed: %v calls=%d", err, calls)
	}
}
func TestPacketReconnectDoesNotReplayPartialWrite(t *testing.T) {
	fresh := &testWriteCloser{}
	calls := 0
	tunnel := packetTunnel{ctx: context.Background(), send: &testWriteCloser{fail: true}, openSend: func() (io.WriteCloser, error) { calls++; return fresh, nil }}
	if err := tunnel.WritePacket(packet([]byte("ambiguous"))); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || fresh.Len() != 0 {
		t.Fatal("partially sent frame replayed")
	}
	next := packet([]byte("next"))
	if err := tunnel.WritePacket(next); err != nil || !bytes.Equal(fresh.Bytes(), next) {
		t.Fatal("replacement stream unusable")
	}
}
func TestPacketReconnectStopsOnCancellationOrMalformedFrame(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	tunnel := packetTunnel{ctx: ctx, recv: testReadCloser{bytes.NewReader(nil)}, openRecv: func() (io.ReadCloser, error) { calls++; return nil, net.ErrClosed }}
	if _, err := tunnel.ReadPacket(make([]byte, 65535)); err != context.Canceled || calls != 0 {
		t.Fatal("cancelled reconnect attempted")
	}
	bad := packet(nil)
	bad[0] = 0x60
	tunnel.ctx = context.Background()
	tunnel.recv = testReadCloser{bytes.NewReader(bad)}
	if _, err := tunnel.ReadPacket(make([]byte, 65535)); err != errInvalidFrame || calls != 0 {
		t.Fatal("malformed frames were retried")
	}
}

func TestPacketReconnectRetriesDelayAndPreservesShutdown(t *testing.T) {
	fresh := packet([]byte("response"))
	calls := 0
	tunnel := packetTunnel{ctx: context.Background(), recv: testReadCloser{bytes.NewReader(nil)}, openRecv: func() (io.ReadCloser, error) {
		calls++
		if calls == 1 {
			return nil, easyconnect.ErrSangforReconnectLater
		}
		return testReadCloser{bytes.NewReader(fresh)}, nil
	}}
	got, err := tunnel.ReadPacket(make([]byte, 65535))
	if err != nil || calls != 2 || !bytes.Equal(got, fresh) {
		t.Fatalf("temporary rejection not recovered: %v", err)
	}
	calls = 0
	tunnel.recv = testReadCloser{bytes.NewReader(nil)}
	tunnel.openRecv = func() (io.ReadCloser, error) { calls++; return nil, easyconnect.ErrSangforShutdown }
	if _, err = tunnel.ReadPacket(make([]byte, 65535)); !errors.Is(err, easyconnect.ErrSangforShutdown) || calls != 1 {
		t.Fatal("terminal shutdown was retried or lost")
	}
}
func TestPacketReconnectExhaustionRetainsTemporaryReject(t *testing.T) {
	tunnel := packetTunnel{ctx: context.Background(), recv: testReadCloser{bytes.NewReader(nil)}, openRecv: func() (io.ReadCloser, error) { return nil, easyconnect.ErrSangforReconnectLater }}
	_, err := tunnel.ReadPacket(make([]byte, 65535))
	if !errors.Is(err, easyconnect.ErrSangforReconnectLater) {
		t.Fatal("temporary rejection misclassified after retries")
	}
}
