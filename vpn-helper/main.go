// M Chip VPN helper, 2026. Licensed under AGPL-3.0; see ../LICENSE.
package main

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	clientpkg "github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/client/easyconnect"
	"github.com/mythologyli/zju-connect/dial"
	"github.com/mythologyli/zju-connect/resolve"
	"github.com/mythologyli/zju-connect/service"
	stackpkg "github.com/mythologyli/zju-connect/stack"
	"github.com/mythologyli/zju-connect/stack/gvisor"
	"github.com/mythologyli/zju-connect/stack/tcptunnel"
)

type config struct {
	Server    string `json:"server"`
	SessionID string `json:"sessionId"`
	SocksPort int    `json:"socksPort"`
	HTTPPort  int    `json:"httpPort"`
}
type dialFunc func(context.Context, string, string) (net.Conn, error)

var eventMu sync.Mutex

func emit(v any)       { eventMu.Lock(); defer eventMu.Unlock(); _ = json.NewEncoder(os.Stdout).Encode(v) }
func stage(s string)   { emit(map[string]string{"event": "stage", "stage": s}) }
func fail(code string) { emit(map[string]string{"event": "error", "code": code}) }
func validate(c config) error {
	host, port, err := net.SplitHostPort(c.Server)
	if err != nil || host == "" || strings.ContainsAny(host, "\r\n /\\") {
		return errors.New("invalid server")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return errors.New("invalid server port")
	}
	if len(c.SessionID) != 16 || strings.ContainsAny(c.SessionID, "\r\n") {
		return errors.New("unsupported session")
	}
	if c.SocksPort < 1024 || c.SocksPort > 65535 || c.HTTPPort < 1024 || c.HTTPPort > 65535 || c.SocksPort == c.HTTPPort {
		return errors.New("invalid proxy ports")
	}
	return nil
}

type underlay struct{ net.Dialer }

func (d *underlay) ExcludeIP(net.IP) {}

type preparedClient struct {
	*easyconnect.Client
	conn io.ReadWriteCloser
	once sync.Once
}

func (c *preparedClient) NewL3Conn() (io.ReadWriteCloser, error) {
	var initial bool
	c.once.Do(func() { initial = true })
	if initial {
		return c.conn, nil
	}
	return c.Client.NewL3Conn()
}
func certError(err error) bool {
	var unknown x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var hostname x509.HostnameError
	return errors.As(err, &unknown) || errors.As(err, &invalid) || errors.As(err, &hostname)
}
func run(c config) error {
	if err := validate(c); err != nil {
		fail("UNSUPPORTED_SESSION")
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	// Loopback listeners are reserved before contacting the VPN gateway.
	socks, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", c.SocksPort))
	if err != nil {
		fail("PORT_IN_USE")
		return err
	}
	defer socks.Close()
	web, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", c.HTTPPort))
	if err != nil {
		fail("PORT_IN_USE")
		return err
	}
	defer web.Close()
	// All upstream log output is disabled: it includes private tokens in normal log lines.
	stdlog.SetOutput(io.Discard)
	vpn := easyconnect.NewClient(easyconnect.Options{Server: c.Server, SessionID: c.SessionID, Resources: easyconnect.ResourceOptions{Fetch: true, IncludeDomains: true}, UnderlayDialer: &underlay{net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}}})
	defer vpn.Close()
	go func() { <-ctx.Done(); vpn.Close(); socks.Close(); web.Close() }()
	stage("token")
	if err = vpn.Setup(); err != nil {
		if certError(err) {
			fail("TLS_CERT_INVALID")
		} else {
			fail("CONNECT_FAILED")
		}
		return err
	}
	ips, ipe := vpn.IPResources()
	domains, de := vpn.DomainResources()
	static, se := vpn.DNSResource()
	if ipe != nil && de != nil && se != nil {
		fail("CONFIG_FAILED")
		return errors.New("server resources unavailable")
	}
	stage("ip")
	var st stackpkg.Stack
	var tunnel io.ReadWriteCloser
	mode := "l3"
	ip := ""
	if vpn.CanUseTCPTunnel() {
		mode = "tcp"
		st, err = tcptunnel.NewStack(vpn)
	} else {
		v, ipErr := vpn.IP()
		if ipErr != nil || v.To4() == nil {
			fail("TUNNEL_FAILED")
			return errors.New("virtual IP missing")
		}
		ip = v.String()
		stage("tunnel")
		tunnel, err = vpn.NewL3Conn()
		if err != nil {
			if certError(err) {
				fail("TLS_CERT_INVALID")
			} else {
				fail("TUNNEL_FAILED")
			}
			return err
		}
		defer tunnel.Close()
		st, err = gvisor.NewStack(&preparedClient{Client: vpn, conn: tunnel})
	}
	if err != nil {
		fail("TUNNEL_FAILED")
		return err
	}
	dnsServers, _ := vpn.DNSServers()
	remote := ""
	secondary := ""
	if len(dnsServers) > 0 {
		remote = dnsServers[0]
	}
	if len(dnsServers) > 1 {
		secondary = dnsServers[1]
	}
	resolver := resolve.NewResolver(st, remote, secondary, 300, domains, static, remote != "")
	defer resolver.Close()
	localDNS := service.NewDnsServer(resolver, dnsServers)
	st.SetupResolve(localDNS)
	st.SetupIPPool(resolver.IPPool)
	vpnDialer := dial.NewDialer(st, resolver, ips, false, "")
	// Panics in the packet reader become a tunnel failure, never a false ready signal.
	go func() {
		defer func() {
			if recover() != nil {
				fail("TUNNEL_FAILED")
				cancel()
			}
		}()
		st.Run()
	}()
	handler := newHTTPProxy(vpnDialer.Dial)
	httpServer := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
	defer httpServer.Close()
	defer handler.close()
	go func() { _ = httpServer.Serve(web) }()
	go serveSOCKS(ctx, socks, vpnDialer.Dial)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	emit(map[string]string{"event": "ready", "mode": mode, "ip": ip, "socksAddress": socks.Addr().String(), "httpAddress": web.Addr().String()})
	// When Electron disappears unexpectedly, terminate rather than leave an orphan proxy.
	parent := os.Getppid()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if os.Getppid() != parent {
				return nil
			}
		}
	}
}
func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Println("mchip-vpn-helper 0.2.0-beta.1; zju-connect c19eb4ed")
		return
	}
	// A single bounded stdin record carries the session; never argv, env or a file.
	scanner := bufio.NewScanner(io.LimitReader(os.Stdin, 8193))
	scanner.Buffer(make([]byte, 1024), 8192)
	var c config
	if !scanner.Scan() || json.Unmarshal(scanner.Bytes(), &c) != nil {
		fail("UNSUPPORTED_SESSION")
		os.Exit(1)
	}
	if err := run(c); err != nil {
		os.Exit(1)
	}
}

// SOCKS5 CONNECT only; domain names are resolved through the VPN policy resolver.
func serveSOCKS(ctx context.Context, ln net.Listener, dial dialFunc) {
	for {
		c, e := ln.Accept()
		if e != nil {
			return
		}
		go func() {
			defer c.Close()
			done := make(chan struct{})
			defer close(done)
			go func() {
				select {
				case <-ctx.Done():
					_ = c.Close()
				case <-done:
				}
			}()
			_ = handleSOCKS(ctx, c, dial)
		}()
	}
}
func handleSOCKS(ctx context.Context, c net.Conn, dial dialFunc) error {
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	h := make([]byte, 2)
	if _, e := io.ReadFull(c, h); e != nil {
		return e
	}
	if h[0] != 5 || h[1] == 0 {
		return errors.New("bad socks greeting")
	}
	methods := make([]byte, int(h[1]))
	if _, e := io.ReadFull(c, methods); e != nil {
		return e
	}
	hasNoAuth := false
	for _, m := range methods {
		if m == 0 {
			hasNoAuth = true
		}
	}
	if !hasNoAuth {
		_, _ = c.Write([]byte{5, 255})
		return errors.New("unsupported socks auth")
	}
	if _, e := c.Write([]byte{5, 0}); e != nil {
		return e
	}
	q := make([]byte, 4)
	if _, e := io.ReadFull(c, q); e != nil {
		return e
	}
	if q[0] != 5 || q[2] != 0 {
		return errors.New("invalid socks request")
	}
	reply := func(code byte) { _, _ = c.Write([]byte{5, code, 0, 1, 127, 0, 0, 1, 0, 0}) }
	if q[1] != 1 {
		reply(7)
		return errors.New("only CONNECT supported")
	}
	var host string
	switch q[3] {
	case 1:
		b := make([]byte, 4)
		if _, e := io.ReadFull(c, b); e != nil {
			return e
		}
		host = net.IP(b).String()
	case 3:
		b := make([]byte, 1)
		if _, e := io.ReadFull(c, b); e != nil {
			return e
		}
		if b[0] == 0 {
			reply(8)
			return errors.New("empty host")
		}
		name := make([]byte, int(b[0]))
		if _, e := io.ReadFull(c, name); e != nil {
			return e
		}
		host = string(name)
	default:
		reply(8)
		return errors.New("IPv4/domain only")
	}
	p := make([]byte, 2)
	if _, e := io.ReadFull(c, p); e != nil {
		return e
	}
	port := binary.BigEndian.Uint16(p)
	if port == 0 {
		reply(1)
		return errors.New("invalid port")
	}
	dialCtx, stop := context.WithTimeout(ctx, 20*time.Second)
	defer stop()
	remote, e := dial(dialCtx, "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if e != nil {
		reply(5)
		return e
	}
	defer remote.Close()
	reply(0)
	_ = c.SetDeadline(time.Time{})
	relay(c, c, remote)
	return nil
}
func relay(c net.Conn, reader io.Reader, remote net.Conn) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(remote, reader); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, remote); done <- struct{}{} }()
	<-done
	_ = c.Close()
	_ = remote.Close()
	<-done
}

type httpProxy struct {
	transport *http.Transport
	dial      dialFunc
	mu        sync.Mutex
	tunnels   map[net.Conn]net.Conn
}

func newHTTPProxy(dial dialFunc) *httpProxy {
	return &httpProxy{transport: &http.Transport{Proxy: nil, DialContext: dial, ResponseHeaderTimeout: 20 * time.Second, IdleConnTimeout: 60 * time.Second}, dial: dial, tunnels: make(map[net.Conn]net.Conn)}
}
func (p *httpProxy) close() {
	p.transport.CloseIdleConnections()
	p.mu.Lock()
	defer p.mu.Unlock()
	for c, r := range p.tunnels {
		c.Close()
		r.Close()
	}
}
func stripHop(h http.Header) {
	for _, v := range h.Values("Connection") {
		for _, k := range strings.Split(v, ",") {
			h.Del(strings.TrimSpace(k))
		}
	}
	for _, k := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		h.Del(k)
	}
}
func (p *httpProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		host, port, e := net.SplitHostPort(r.Host)
		n, _ := strconv.Atoi(port)
		if e != nil || host == "" || n < 1 || n > 65535 {
			http.Error(w, "Invalid CONNECT target", 400)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		remote, e := p.dial(ctx, "tcp", r.Host)
		if e != nil {
			http.Error(w, "VPN target unavailable", 502)
			return
		}
		c, b, e := w.(http.Hijacker).Hijack()
		if e != nil {
			remote.Close()
			return
		}
		p.mu.Lock()
		p.tunnels[c] = remote
		p.mu.Unlock()
		defer func() { p.mu.Lock(); delete(p.tunnels, c); p.mu.Unlock(); c.Close(); remote.Close() }()
		if _, e = b.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); e != nil {
			return
		}
		if b.Flush() != nil {
			return
		}
		relay(c, b, remote)
		return
	}
	if r.URL.Scheme != "http" || r.URL.Host == "" || r.URL.User != nil {
		http.Error(w, "Use an absolute HTTP proxy URL", 400)
		return
	}
	clone := r.Clone(r.Context())
	clone.RequestURI = ""
	stripHop(clone.Header)
	resp, e := p.transport.RoundTrip(clone)
	if e != nil {
		http.Error(w, "VPN target unavailable", 502)
		return
	}
	defer resp.Body.Close()
	stripHop(resp.Header)
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

var _ clientpkg.Client = (*preparedClient)(nil)
