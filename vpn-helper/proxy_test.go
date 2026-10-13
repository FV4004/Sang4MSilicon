package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestConfigRejectsMalformedSessionsAndPorts(t *testing.T) {
	good := config{Server: "vpn.example.com:443", SessionID: "0123456789abcdef", SocksPort: 1080, HTTPPort: 1081}
	if validate(good) != nil {
		t.Fatal("valid config rejected")
	}
	for _, c := range []config{{Server: "bad\nhost:443", SessionID: good.SessionID, SocksPort: 1080, HTTPPort: 1081}, {Server: good.Server, SessionID: "short", SocksPort: 1080, HTTPPort: 1081}, {Server: good.Server, SessionID: good.SessionID, SocksPort: 1080, HTTPPort: 1080}, {Server: good.Server, SessionID: good.SessionID, SocksPort: 80, HTTPPort: 1081}} {
		if validate(c) == nil {
			t.Fatal("invalid config accepted")
		}
	}
}
func echoDial(t *testing.T, expect string) dialFunc {
	return func(_ context.Context, network, addr string) (net.Conn, error) {
		if network != "tcp" || addr != expect {
			t.Errorf("unexpected dial %q %q", network, addr)
		}
		a, b := net.Pipe()
		go func() { defer b.Close(); _, _ = io.Copy(b, b) }()
		return a, nil
	}
}
func TestSOCKSConnectTransfersDataThroughSelectedDialer(t *testing.T) {
	client, proxy := net.Pipe()
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	done := make(chan error, 1)
	go func() {
		defer proxy.Close()
		done <- handleSOCKS(context.Background(), proxy, echoDial(t, "internal.test:443"))
	}()
	_, _ = client.Write([]byte{5, 2, 2, 0})
	b := make([]byte, 2)
	if _, e := io.ReadFull(client, b); e != nil || b[1] != 0 {
		t.Fatal("greeting", e, b)
	}
	msg := append([]byte{5, 1, 0, 3, 13}, []byte("internal.test")...)
	msg = append(msg, 1, 187)
	_, _ = client.Write(msg)
	response := make([]byte, 10)
	if _, e := io.ReadFull(client, response); e != nil || response[1] != 0 {
		t.Fatal("CONNECT", e, response)
	}
	_, _ = client.Write([]byte("hello"))
	reply := make([]byte, 5)
	if _, e := io.ReadFull(client, reply); e != nil || string(reply) != "hello" {
		t.Fatal("relay", e, string(reply))
	}
	client.Close()
	<-done
}
func TestSOCKSRejectsUnsupportedAuth(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	go func() { defer b.Close(); _ = handleSOCKS(context.Background(), b, nil) }()
	_, _ = a.Write([]byte{5, 1, 2})
	q := make([]byte, 2)
	_, _ = io.ReadFull(a, q)
	if q[1] != 255 {
		t.Fatal("unsupported auth accepted")
	}
}
func TestHTTPProxyForwardsAndStripsProxyCredentials(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("X-Remove") != "" {
			t.Error("hop-by-hop credentials forwarded")
		}
		_, _ = w.Write([]byte("via VPN dialer"))
	}))
	defer target.Close()
	called := 0
	proxy := newHTTPProxy(func(ctx context.Context, n, a string) (net.Conn, error) {
		called++
		return (&net.Dialer{}).DialContext(ctx, n, a)
	})
	defer proxy.close()
	req := httptest.NewRequest("GET", target.URL+"/test", nil)
	req.Header.Set("Proxy-Authorization", "private-proxy-secret")
	req.Header.Set("Connection", "X-Remove")
	req.Header.Set("X-Remove", "value")
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)
	if rec.Code != 200 || rec.Body.String() != "via VPN dialer" || called != 1 {
		t.Fatalf("proxy not used: %d %q %d", rec.Code, rec.Body.String(), called)
	}
}
func TestHTTPConnectPreservesBufferedFirstPayload(t *testing.T) {
	handler := newHTTPProxy(echoDial(t, "internal.test:443"))
	defer handler.close()
	server := httptest.NewServer(handler)
	defer server.Close()
	conn, e := net.Dial("tcp", strings.TrimPrefix(server.URL, "http://"))
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.WriteString(conn, "CONNECT internal.test:443 HTTP/1.1\r\nHost: internal.test:443\r\n\r\nhello")
	reader := bufio.NewReader(conn)
	resp, e := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
	if e != nil || resp.StatusCode != 200 {
		t.Fatal("CONNECT failed", e)
	}
	payload := make([]byte, 5)
	if _, e = io.ReadFull(reader, payload); e != nil || string(payload) != "hello" {
		t.Fatal("buffered payload lost", e, string(payload))
	}
}
func TestHTTPProxyRejectsNonProxyURLs(t *testing.T) {
	p := newHTTPProxy(nil)
	defer p.close()
	for _, url := range []string{"/local", "https://internal.test/", "http://user:pass@internal.test/"} {
		r := httptest.NewRequest("GET", url, nil)
		w := httptest.NewRecorder()
		p.ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatalf("bad proxy URL accepted %s", url)
		}
	}
}
