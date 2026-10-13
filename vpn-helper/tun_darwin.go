//go:build darwin

package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/mythologyli/zju-connect/client/easyconnect"
	"golang.org/x/sys/unix"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const socketDir = "/var/run/mchip-vpn"
const resolverDir = "/private/etc/resolver"
const stateDir = "/Library/PrivilegedHelperTools/dev.connectlab.mchip-vpn-state"

func systemCommand(bin string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"}
	b, e := cmd.CombinedOutput()
	return string(b), e
}
func secureDirectory(path string) error {
	if e := os.Mkdir(path, 0755); e != nil && !os.IsExist(e) {
		return e
	}
	s, e := os.Lstat(path)
	if e != nil {
		return e
	}
	stat, ok := s.Sys().(*syscall.Stat_t)
	if !ok || !s.IsDir() || s.Mode()&os.ModeSymlink != 0 || stat.Uid != 0 || s.Mode().Perm()&022 != 0 {
		return errors.New("unsafe system directory")
	}
	return nil
}
func peerOwner(c *net.UnixConn, uid int) bool {
	raw, e := c.SyscallConn()
	if e != nil {
		return false
	}
	allowed := false
	_ = raw.Control(func(fd uintptr) {
		cred, e := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		allowed = e == nil && int(cred.Uid) == uid
	})
	return allowed
}
func tunControl(args []string) error {
	if os.Geteuid() != 0 || len(args) != 3 || args[1] != "--owner-uid" {
		return errors.New("invalid root invocation")
	}
	uid, e := strconv.Atoi(args[2])
	if e != nil || uid < 1 {
		return errors.New("invalid owner")
	}
	path := args[0]
	if !regexp.MustCompile(fmt.Sprintf(`^/var/run/mchip-vpn/%d-[a-f0-9]{32}\.sock$`, uid)).MatchString(path) {
		return errors.New("invalid socket")
	}
	if e = secureDirectory(stateDir); e != nil {
		return e
	}
	if e = secureDirectory(socketDir); e != nil {
		return e
	}
	lock, e := os.OpenFile(socketDir+"/active.lock", os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return e
	}
	defer lock.Close()
	if e = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return e
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	ln, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		return e
	}
	defer ln.Close()
	defer os.Remove(path)
	if e = os.Chmod(path, 0600); e != nil {
		return e
	}
	if e = os.Chown(path, uid, -1); e != nil {
		return e
	}
	_ = ln.SetDeadline(time.Now().Add(45 * time.Second))
	var conn *net.UnixConn
	for {
		conn, e = ln.AcceptUnix()
		if e != nil {
			return e
		}
		if peerOwner(conn, uid) {
			break
		}
		conn.Close()
	}
	defer conn.Close()
	eventOutput = conn
	_ = conn.SetReadDeadline(time.Now().Add(45 * time.Second))
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 1024), 8192)
	var c config
	if !scanner.Scan() || json.Unmarshal(scanner.Bytes(), &c) != nil {
		fail("UNSUPPORTED_SESSION")
		emit(map[string]string{"event": "stopped"})
		return errors.New("invalid config")
	}
	if c.Mode == "recover" {
		if e = secureDirectory(resolverDir); e == nil {
			e = cleanupLease(resolverDir, stateDir+"/resolver-lease.json")
		}
		if e != nil {
			fail("CLEANUP_FAILED")
			return e
		}
		_, _ = systemCommand("/usr/bin/dscacheutil", "-flushcache")
		emit(map[string]string{"event": "stopped"})
		return nil
	}
	if validate(c) != nil || c.Mode != "tun" {
		fail("UNSUPPORTED_SESSION")
		emit(map[string]string{"event": "stopped"})
		return errors.New("invalid config")
	}
	_ = conn.SetReadDeadline(time.Time{})
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	go func() { scanner.Scan(); cancel() }()
	e = runNativeTun(ctx, c, filepath.Base(path))
	c.SessionID = ""
	if e == nil {
		emit(map[string]string{"event": "stopped"})
	}
	return e
}

type nativeDevice struct {
	file *os.File
	name string
}

func openDevice(ip string) (*nativeDevice, error) {
	fd, e := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, 2)
	if e != nil {
		return nil, e
	}
	ok := false
	defer func() {
		if !ok {
			unix.Close(fd)
		}
	}()
	ctl := &unix.CtlInfo{}
	copy(ctl.Name[:], "com.apple.net.utun_control")
	if e = unix.IoctlCtlInfo(fd, ctl); e != nil {
		return nil, e
	}
	if e = unix.Connect(fd, &unix.SockaddrCtl{ID: ctl.Id, Unit: 0}); e != nil {
		return nil, e
	}
	name, e := unix.GetsockoptString(fd, 2, 2)
	name = strings.TrimRight(name, "\x00")
	if e != nil || !regexp.MustCompile(`^utun[0-9]+$`).MatchString(name) {
		return nil, errors.New("invalid UTUN name")
	}
	if e = unix.SetNonblock(fd, true); e != nil {
		return nil, e
	}
	unix.CloseOnExec(fd)
	f := os.NewFile(uintptr(fd), name)
	ok = true
	device := &nativeDevice{file: f, name: name}
	if _, e = systemCommand("/sbin/ifconfig", name, "inet", ip, ip, "netmask", "255.255.255.255", "mtu", "1400", "up"); e != nil {
		f.Close()
		return nil, e
	}
	return device, nil
}
func (d *nativeDevice) Close() error               { return d.file.Close() }
func (d *nativeDevice) Read(p []byte) (int, error) { return d.file.Read(p) }
func (d *nativeDevice) Write(p []byte) (int, error) {
	if !validIPv4(p) {
		return 0, errors.New("invalid packet")
	}
	frame := make([]byte, 4+len(p))
	binary.BigEndian.PutUint32(frame, unix.AF_INET)
	copy(frame[4:], p)
	n, e := d.file.Write(frame)
	if n != len(frame) && e == nil {
		e = io.ErrShortWrite
	}
	if e != nil {
		return 0, e
	}
	return len(p), nil
}

type gatewayDialer struct {
	host, port string
	addresses  []net.IP
	indexes    map[string]int
}

func originalGateway(ctx context.Context, server string) (*gatewayDialer, error) {
	host, port, e := net.SplitHostPort(server)
	if e != nil {
		return nil, e
	}
	addresses, e := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if e != nil || len(addresses) == 0 {
		return nil, errors.New("gateway IPv4 lookup failed")
	}
	if len(addresses) > 32 {
		addresses = addresses[:32]
	}
	d := &gatewayDialer{host: host, port: port, addresses: addresses, indexes: map[string]int{}}
	for _, ip := range addresses {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		text, e := systemCommand("/sbin/route", "-n", "get", "-inet", ip.String())
		if e != nil {
			return nil, e
		}
		for _, line := range strings.Split(text, "\n") {
			fields := strings.Fields(line)
			if len(fields) == 2 && fields[0] == "interface:" {
				iface, e := net.InterfaceByName(fields[1])
				if e != nil {
					return nil, e
				}
				d.indexes[ip.String()] = iface.Index
			}
		}
		if d.indexes[ip.String()] == 0 {
			return nil, errors.New("gateway interface missing")
		}
	}
	return d, nil
}
func (d *gatewayDialer) ExcludeIP(net.IP) {}
func (d *gatewayDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, e := net.SplitHostPort(address)
	if e != nil {
		return nil, e
	}
	if !strings.EqualFold(host, d.host) || port != d.port {
		return nil, errors.New("unexpected gateway destination")
	}
	var last error
	for _, ip := range d.addresses {
		index := d.indexes[ip.String()]
		dialer := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: func(_, _ string, raw syscall.RawConn) error {
			var controlErr error
			e := raw.Control(func(fd uintptr) { controlErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, index) })
			if e != nil {
				return e
			}
			return controlErr
		}}
		conn, e := dialer.DialContext(ctx, "tcp4", net.JoinHostPort(ip.String(), port))
		if e == nil {
			return conn, nil
		}
		last = e
	}
	return nil, last
}

type routeTable struct {
	mu       sync.Mutex
	device   string
	prefixes []netip.Prefix
	gateways map[netip.Addr]bool
	closed   bool
}

func (t *routeTable) add(p netip.Prefix) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return errors.New("routes stopping")
	}
	a := p.Addr()
	if t.gateways[a] && p.Bits() == 32 {
		return nil
	} // DNS may resolve the gateway; retain its physical bypass route.
	if !a.Is4() || a.IsLoopback() || a.IsMulticast() || a.IsUnspecified() || t.gateways[a] {
		return errors.New("invalid route")
	}
	for _, old := range t.prefixes {
		if old.Bits() <= p.Bits() && old.Contains(p.Addr()) {
			return nil
		}
	}
	if p.Bits() == 0 || len(t.prefixes) >= 4096 {
		return errors.New("route limit")
	}
	if _, e := systemCommand("/sbin/route", "-n", "add", "-net", p.String(), "-interface", t.device); e != nil {
		return e
	}
	t.prefixes = append(t.prefixes, p)
	return nil
}
func runNativeTun(ctx context.Context, c config, tag string) (result error) {
	log.SetOutput(io.Discard)
	journal := stateDir + "/resolver-lease.json"
	if e := secureDirectory(resolverDir); e != nil {
		fail("DNS_CONFLICT")
		return nil
	}
	if e := cleanupLease(resolverDir, journal); e != nil {
		fail("CLEANUP_FAILED")
		return e
	}
	lookupCtx, cancelLookup := context.WithTimeout(ctx, 15*time.Second)
	defer cancelLookup()
	underlay, e := originalGateway(lookupCtx, c.Server)
	if e != nil {
		fail("CONNECT_FAILED")
		return nil
	}
	vpn := easyconnect.NewClient(easyconnect.Options{Server: c.Server, SessionID: c.SessionID, Resources: easyconnect.ResourceOptions{Fetch: true, IncludeDomains: true}, UnderlayDialer: underlay})
	defer vpn.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			vpn.Close()
		case <-done:
		}
	}()
	stage("token")
	if e = vpn.Setup(); e != nil {
		if certError(e) {
			fail("TLS_CERT_INVALID")
		} else {
			fail("CONNECT_FAILED")
		}
		return nil
	}
	if ctx.Err() != nil {
		return nil
	}
	if vpn.CanUseTCPTunnel() {
		fail("TUN_UNSUPPORTED")
		return nil
	}
	ip, e := vpn.IP()
	if e != nil || ip.To4() == nil {
		fail("TUNNEL_FAILED")
		return nil
	}
	stage("ip")
	set, _ := vpn.IPSet()
	ranges, _ := vpn.IPResources()
	domains, _ := vpn.DomainResources()
	static, _ := vpn.DNSResource()
	servers, _ := vpn.DNSServers()

	if set == nil && ranges == nil && domains == nil && static == nil {
		fail("RESOURCE_FETCH_FAILED")
		return nil
	}
	set, e = resourceIPSet(set, ranges)
	if e != nil {
		fail("RESOURCE_PARSE_FAILED")
		return nil
	}
	policy, e := prepareDNSPolicy(domains, static, servers, underlay.addresses)
	if e != nil {
		fail("DNS_DOMAIN_LIMIT")
		return nil
	}
	names := policy.Names
	static = policy.Records
	servers = policy.Servers
	plan, e := routePlan(set, servers, static, underlay.addresses)
	if e != nil {
		if len(set.Prefixes()) == 0 && len(static) == 0 && len(servers) == 0 {
			fail("DNS_ROUTING_UNAVAILABLE")
		} else {
			fail("RESOURCE_ROUTES_UNSUPPORTED")
		}
		return nil
	}
	stage("tunnel")
	send, e := vpn.SendConn()
	if e != nil {
		fail("TUNNEL_FAILED")
		return nil
	}
	defer send.Close()
	recv, e := vpn.RecvConn()
	if e != nil {
		fail("TUNNEL_FAILED")
		return nil
	}
	defer recv.Close()
	device, e := openDevice(ip.String())
	if e != nil {
		fail("TUN_UNAVAILABLE")
		return nil
	}
	table := &routeTable{device: device.name, gateways: map[netip.Addr]bool{}}
	for _, v := range underlay.addresses {
		a, _ := netip.AddrFromSlice(v)
		table.gateways[a.Unmap()] = true
	}
	var dnsServer *splitDNS
	defer func() {
		table.mu.Lock()
		table.closed = true
		table.mu.Unlock()
		if dnsServer != nil {
			dnsServer.Close()
		}
		closeErr := device.Close()
		send.Close()
		recv.Close()
		cleanupErr := cleanupLease(resolverDir, journal)
		_, _ = systemCommand("/usr/bin/dscacheutil", "-flushcache")
		if closeErr != nil || cleanupErr != nil {
			fail("CLEANUP_FAILED")
			result = errors.New("network cleanup failed")
		}
	}()
	stage("routes")
	for _, p := range plan {
		if ctx.Err() != nil {
			return nil
		}
		if e = table.add(p); e != nil {
			fail("ROUTE_FAILED")
			return nil
		}
	}
	if len(names) > 0 {
		dnsServer, e = newSplitDNS(names, static, servers, func(a netip.Addr) error { return table.add(netip.PrefixFrom(a, 32)) })
		if e != nil {
			fail("DNS_CONFLICT")
			return nil
		}
		if e = installResolversContext(ctx, resolverDir, journal, names, dnsServer.port, tag); e != nil {
			fail("DNS_CONFLICT")
			return nil
		}
		_, _ = systemCommand("/usr/bin/dscacheutil", "-flushcache")
	}
	errs := make(chan error, 2)
	go func() {
		buf := make([]byte, 65539)
		for {
			n, e := device.Read(buf)
			if e != nil {
				errs <- e
				return
			}
			if n < 4 || binary.BigEndian.Uint32(buf[:4]) != unix.AF_INET {
				continue
			}
			packet := buf[4:n]
			if !validIPv4(packet) {
				errs <- errors.New("invalid local frame")
				return
			}
			if written, writeErr := send.Write(packet); writeErr != nil || written != len(packet) {
				e = writeErr
				if e == nil {
					e = io.ErrShortWrite
				}
				errs <- e
				return
			}
		}
	}()
	go func() {
		buf := make([]byte, 65535)
		for {
			p, e := readIPv4(recv, buf)
			if e != nil {
				errs <- e
				return
			}
			if _, e = device.Write(p); e != nil {
				errs <- e
				return
			}
		}
	}()
	if ctx.Err() != nil {
		return nil
	}
	emit(map[string]any{"event": "ready", "mode": "tun", "ip": ip.String(), "interface": device.name, "routeCount": len(plan), "dnsCount": len(names), "warnings": policy.Warnings})
	select {
	case <-ctx.Done():
		return nil
	case <-errs:
		fail("TUNNEL_FAILED")
		return nil
	}
}
