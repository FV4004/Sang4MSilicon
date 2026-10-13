package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
	clientpkg "github.com/mythologyli/zju-connect/client"
	"inet.af/netaddr"
)

func domainName(s string) (string, error) {
	s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	s = strings.TrimPrefix(s, "*.")
	s = strings.TrimPrefix(s, ".")
	if len(s) == 0 || len(s) > 253 {
		return "", errors.New("invalid DNS domain")
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid DNS domain")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "", errors.New("invalid DNS domain")
			}
		}
	}
	return s, nil
}

// Some gateways omit the DNS element. Upstream still provides parsed IP ranges
// but returns before constructing IPSet; retain those ranges for TUN routing.
func resourceIPSet(set *netaddr.IPSet, resources []clientpkg.IPResource) (*netaddr.IPSet, error) {
	if set != nil {
		return set, nil
	}
	if resources == nil {
		return nil, errors.New("IP resource parse unavailable")
	}
	var b netaddr.IPSetBuilder
	for _, r := range resources {
		a, ok := netaddr.FromStdIP(r.IPMin)
		if !ok || !a.Is4() {
			return nil, errors.New("invalid IPv4 range")
		}
		z, ok := netaddr.FromStdIP(r.IPMax)
		if !ok || !z.Is4() || z.Less(a) {
			return nil, errors.New("invalid IPv4 range")
		}
		b.AddRange(netaddr.IPRangeFrom(a, z))
	}
	return b.IPSet()
}

func routePlan(set *netaddr.IPSet, dnsIPs []string, static map[string][]net.IP, bypass []net.IP) ([]netip.Prefix, error) {
	var b netaddr.IPSetBuilder
	if set != nil {
		for _, p := range set.Prefixes() {
			if p.IP().Is4() {
				if p.Bits() == 0 {
					return nil, errors.New("default route unsupported")
				}
				b.AddPrefix(p)
			}
		}
	}
	for _, s := range dnsIPs {
		a, e := netip.ParseAddr(s)
		if e != nil || !a.Is4() || a.IsUnspecified() || a.IsMulticast() {
			return nil, errors.New("invalid policy DNS")
		}
		b.Add(netaddr.MustParseIP(a.String()))
	}
	for _, ips := range static {
		for _, ip := range ips {
			if v := ip.To4(); v != nil {
				a, _ := netaddr.FromStdIP(v)
				b.Add(a)
			}
		}
	}
	for _, ip := range bypass {
		if a, ok := netaddr.FromStdIP(ip); ok {
			b.Remove(a)
		}
	}
	// Loopback and multicast never belong in a TUN policy.
	b.RemovePrefix(netaddr.MustParseIPPrefix("127.0.0.0/8"))
	b.RemovePrefix(netaddr.MustParseIPPrefix("224.0.0.0/4"))
	b.Remove(netaddr.IPv4(0, 0, 0, 0))
	b.Remove(netaddr.MustParseIP("255.255.255.255"))
	result, e := b.IPSet()
	if e != nil {
		return nil, e
	}
	var out []netip.Prefix
	for _, p := range result.Prefixes() {
		out = append(out, netip.MustParsePrefix(p.String()))
	}
	if len(out) == 0 || len(out) > 4096 {
		return nil, errors.New("unsupported route count")
	}
	return out, nil
}

// DNS is optional for IP routing. Unsupported DNS rules must not erase usable IP resources.
type dnsPolicy struct {
	Names    []string
	Records  map[string][]net.IP
	Servers  []string
	Warnings []string
}

func prepareDNSPolicy(domains clientpkg.DomainResources, static map[string][]net.IP, servers []string, gateways []net.IP) (dnsPolicy, error) {
	p := dnsPolicy{Records: map[string][]net.IP{}}
	names := map[string]bool{}
	skipped := false
	for d := range domains {
		name, e := domainName(d)
		if e != nil {
			skipped = true
			continue
		}
		names[name] = true
	}
	for d, ips := range static {
		name, e := domainName(d)
		if e != nil {
			skipped = true
			continue
		}
		for _, ip := range ips {
			if v := ip.To4(); v != nil && v.IsGlobalUnicast() {
				p.Records[name] = append(p.Records[name], v)
			}
		}
		if len(p.Records[name]) > 0 {
			names[name] = true
		}
	}
	seen := map[string]bool{}
	for _, s := range servers {
		ip := net.ParseIP(strings.TrimSpace(s))
		if ip == nil || ip.To4() == nil || !ip.IsGlobalUnicast() {
			continue
		}
		bypass := false
		for _, gateway := range gateways {
			if ip.Equal(gateway) {
				bypass = true
				break
			}
		}
		if bypass {
			continue
		}
		s = ip.String()
		if !seen[s] {
			p.Servers = append(p.Servers, s)
			seen[s] = true
		}
		if len(p.Servers) == 2 {
			break
		}
	}
	if len(p.Servers) == 0 && len(names) > 0 {
		p.Warnings = append(p.Warnings, "DNS_UNAVAILABLE")
		// Install resolvers only for records the gateway supplied explicitly.
		names = map[string]bool{}
		for name := range p.Records {
			names[name] = true
		}
	}
	if skipped {
		p.Warnings = append(p.Warnings, "DOMAIN_RULE_SKIPPED")
	}
	for name := range names {
		covered := false
		suffix := name
		for {
			i := strings.IndexByte(suffix, '.')
			if i < 0 {
				break
			}
			suffix = suffix[i+1:]
			if names[suffix] {
				covered = true
				break
			}
		}
		if !covered {
			p.Names = append(p.Names, name)
		}
	}
	sort.Strings(p.Names)
	if len(p.Names) > 16384 {
		return p, errors.New("DNS domain limit exceeded")
	}
	return p, nil
}

// Read IPv4 packets from a TLS byte stream; TLS record boundaries are not packet boundaries.
func readIPv4(r io.Reader, buf []byte) ([]byte, error) {
	if len(buf) < 65535 {
		return nil, io.ErrShortBuffer
	}
	if _, e := io.ReadFull(r, buf[:20]); e != nil {
		return nil, e
	}
	n := int(binary.BigEndian.Uint16(buf[2:4]))
	h := int(buf[0]&15) * 4
	if buf[0]>>4 != 4 || h < 20 || n < h {
		return nil, errors.New("invalid IPv4 frame")
	}
	if _, e := io.ReadFull(r, buf[20:n]); e != nil {
		return nil, e
	}
	return buf[:n], nil
}
func validIPv4(p []byte) bool {
	return len(p) >= 20 && p[0]>>4 == 4 && int(p[0]&15)*4 >= 20 && int(p[0]&15)*4 <= len(p) && int(binary.BigEndian.Uint16(p[2:4])) == len(p)
}

type resolverLease struct {
	Files map[string]string `json:"files"`
}

func saveLease(path string, l resolverLease) error {
	b, e := json.Marshal(l)
	if e != nil {
		return e
	}
	f, e := os.OpenFile(path+".tmp", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	return os.Rename(path+".tmp", path)
}
func cleanupLease(dir, path string) error {
	b, e := os.ReadFile(path)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	if len(b) > 8<<20 {
		return errors.New("invalid recovery journal")
	}
	var l resolverLease
	if e = json.Unmarshal(b, &l); e != nil {
		return e
	}
	for name, expected := range l.Files {
		d, e := domainName(name)
		if e != nil || d != name || !strings.HasPrefix(expected, "# mchip-vpn ") {
			return errors.New("invalid recovery entry")
		}
		p := filepath.Join(dir, name)
		s, e := os.Lstat(p)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return e
		}
		if !s.Mode().IsRegular() {
			return errors.New("DNS recovery conflict")
		}
		data, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		if string(data) != expected {
			return errors.New("DNS configuration changed externally")
		}
		if e = os.Remove(p); e != nil {
			return e
		}
	}
	return os.Remove(path)
}
func installResolvers(dir, journal string, domains []string, port int, tag string) error {
	return installResolversContext(context.Background(), dir, journal, domains, port, tag)
}
func installResolversContext(ctx context.Context, dir, journal string, domains []string, port int, tag string) error {
	l := resolverLease{Files: map[string]string{}}
	if port < 1024 || port > 65535 {
		return errors.New("invalid resolver port")
	}
	content := fmt.Sprintf("# mchip-vpn %s\nnameserver 127.0.0.1\nport %d\n", tag, port)
	for _, d := range domains {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		name, e := domainName(d)
		if e != nil || name != d {
			return errors.New("invalid DNS domain")
		}
		if _, e = os.Lstat(filepath.Join(dir, d)); !os.IsNotExist(e) {
			return errors.New("existing DNS resolver")
		}
	}
	for _, d := range domains {
		l.Files[d] = content
	}
	// Persist the complete ownership plan once, before creating any resolver.
	if e := saveLease(journal, l); e != nil {
		return e
	}
	for _, d := range domains {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		f, e := os.OpenFile(filepath.Join(dir, d), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
		if e != nil {
			return e
		}
		_, e = f.WriteString(content)
		if e == nil {
			e = f.Sync()
		}
		ce := f.Close()
		if e != nil {
			return e
		}
		if ce != nil {
			return ce
		}
	}
	return nil
}

type splitDNS struct {
	cancel context.CancelFunc
	udp    *dns.Server
	tcp    *dns.Server
	port   int
}

func newSplitDNS(domains []string, static map[string][]net.IP, servers []string, addRoute func(netip.Addr) error) (*splitDNS, error) {
	udp, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		return nil, e
	}
	port := udp.LocalAddr().(*net.UDPAddr).Port
	tcp, e := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if e != nil {
		udp.Close()
		return nil, e
	}
	ctx, cancel := context.WithCancel(context.Background())
	records := map[string][]net.IP{}
	for d, v := range static {
		n, e := domainName(d)
		if e == nil {
			records[n] = v
		}
	}
	allowedDomains := map[string]bool{}
	for _, d := range domains {
		allowedDomains[d] = true
	}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(q)
		reply.Rcode = dns.RcodeRefused
		if len(q.Question) != 1 {
			_ = w.WriteMsg(reply)
			return
		}
		question := q.Question[0]
		name := strings.ToLower(strings.TrimSuffix(question.Name, "."))
		allowed := false
		suffix := name
		for {
			if allowedDomains[suffix] {
				allowed = true
				break
			}
			i := strings.IndexByte(suffix, '.')
			if i < 0 {
				break
			}
			suffix = suffix[i+1:]
		}
		if !allowed {
			_ = w.WriteMsg(reply)
			return
		}
		reply.Rcode = dns.RcodeSuccess
		// IPv6 is deliberately excluded from this IPv4-only tunnel.
		if question.Qtype == dns.TypeAAAA {
			_ = w.WriteMsg(reply)
			return
		}
		if ips, ok := records[name]; ok && question.Qtype == dns.TypeA {
			for _, ip := range ips {
				if ip.To4() != nil {
					reply.Answer = append(reply.Answer, &dns.A{Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: ip.To4()})
				}
			}
			_ = w.WriteMsg(reply)
			return
		}
		reply.Rcode = dns.RcodeServerFailure
		for _, ip := range servers {
			c := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
			r, _, e := c.ExchangeContext(ctx, q, net.JoinHostPort(ip, "53"))
			if e == nil && r.Truncated {
				c.Net = "tcp"
				r, _, e = c.ExchangeContext(ctx, q, net.JoinHostPort(ip, "53"))
			}
			if e != nil {
				continue
			}
			for _, rr := range r.Answer {
				if a, ok := rr.(*dns.A); ok {
					addr, ok := netip.AddrFromSlice(a.A)
					if !ok || addRoute(addr.Unmap()) != nil {
						r = nil
						break
					}
				}
			}
			if r != nil {
				reply = r
			}
			break
		}
		_ = w.WriteMsg(reply)
	})
	s := &splitDNS{cancel: cancel, port: port, udp: &dns.Server{PacketConn: udp, Handler: handler}, tcp: &dns.Server{Listener: tcp, Handler: handler}}
	go func() { _ = s.udp.ActivateAndServe() }()
	go func() { _ = s.tcp.ActivateAndServe() }()
	return s, nil
}
func (s *splitDNS) Close() {
	s.cancel()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan struct{}, 2)
	go func() { _ = s.udp.ShutdownContext(ctx); done <- struct{}{} }()
	go func() { _ = s.tcp.ShutdownContext(ctx); done <- struct{}{} }()
	<-done
	<-done
}

var errPacketWorkerPanic = errors.New("packet worker panic")

// Never include panic values: packet contents and session data can be sensitive.
func reportPacketWorkerPanic(failures chan<- error) {
	if recover() != nil {
		failures <- errPacketWorkerPanic
	}
}
