package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	clientpkg "github.com/mythologyli/zju-connect/client"
	easyconnect "github.com/mythologyli/zju-connect/client/easyconnect"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

type outboundResourcePolicy struct {
	mu              sync.Mutex
	index           *easyconnect.ResourceACL
	domains         clientpkg.DomainResources
	bound           map[[4]byte]map[string][]clientpkg.DomainResource
	dns             map[[4]byte]bool
	fragments       map[[11]byte]time.Time
	dropped, resets uint64
	rules           int
}

func validResourceProtocol(s string) bool {
	return s == "tcp" || s == "udp" || s == "icmp" || s == "all"
}
func newOutboundResourcePolicy(resources []clientpkg.IPResource, domains clientpkg.DomainResources, static map[string][]net.IP, servers []string) (*outboundResourcePolicy, error) {
	p := &outboundResourcePolicy{domains: make(clientpkg.DomainResources), bound: make(map[[4]byte]map[string][]clientpkg.DomainResource), dns: make(map[[4]byte]bool), fragments: make(map[[11]byte]time.Time)}
	var clean []clientpkg.IPResource
	for _, r := range resources {
		a, b := r.IPMin.To4(), r.IPMax.To4()
		if a == nil || b == nil || binary.BigEndian.Uint32(a) > binary.BigEndian.Uint32(b) || !validResourceProtocol(r.Protocol) || r.PortMin < 0 || r.PortMax > 65535 || r.PortMin > r.PortMax {
			continue
		}
		clean = append(clean, r)
	}
	for name, rules := range domains {
		n, e := domainName(name)
		if e != nil {
			continue
		}
		if strings.HasPrefix(name, "*.") || strings.HasPrefix(name, ".") {
			n = "." + n
		}
		for _, r := range rules {
			if validResourceProtocol(r.Protocol) && r.PortMin >= 0 && r.PortMax <= 65535 && r.PortMin <= r.PortMax {
				p.domains[n] = append(p.domains[n], r)
				p.rules++
			}
		}
	}
	p.rules += len(clean)
	if p.rules == 0 {
		return nil, errors.New("no usable server resource policy")
	}
	p.index = easyconnect.NewResourceACL(clean)
	for _, s := range servers {
		if ip := net.ParseIP(s).To4(); ip != nil {
			var key [4]byte
			copy(key[:], ip)
			p.dns[key] = true
		}
	}
	for name, ips := range static {
		if e := p.bindDNS(name, ips); e != nil {
			return nil, e
		}
	}
	return p, nil
}

// Bind only the queried authorized name's declared protocols and ports. A DNS
// answer never grants all ports; aliases do not grant additional domain rules.
func (p *outboundResourcePolicy) bindDNS(name string, ips []net.IP) error {
	n, e := domainName(name)
	if e != nil {
		return e
	}
	var rules []clientpkg.DomainResource
	for suffix := n; ; {
		rules = append(rules, p.domains[suffix]...)
		if suffix != n {
			rules = append(rules, p.domains["."+suffix]...)
		}
		i := strings.IndexByte(suffix, '.')
		if i < 0 {
			break
		}
		suffix = suffix[i+1:]
	}
	if len(rules) == 0 {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(ips) > 256 {
		return errors.New("DNS answer policy limit")
	}
	added := map[[4]byte]bool{}
	for _, ip := range ips {
		if v := ip.To4(); v != nil && ip.IsGlobalUnicast() {
			var key [4]byte
			copy(key[:], v)
			if p.bound[key] == nil {
				added[key] = true
			}
			if _, ok := p.bound[key][n]; !ok && len(p.bound[key]) >= 64 {
				return errors.New("shared IP policy limit")
			}
		}
	}
	if len(p.bound)+len(added) > 4096 {
		return errors.New("DNS binding policy limit")
	}
	for _, ip := range ips {
		if v := ip.To4(); v != nil && ip.IsGlobalUnicast() {
			var key [4]byte
			copy(key[:], v)
			if p.bound[key] == nil {
				p.bound[key] = map[string][]clientpkg.DomainResource{}
			}
			if _, ok := p.bound[key][n]; !ok && len(p.bound[key]) >= 64 {
				return errors.New("shared IP policy limit")
			}
			p.bound[key][n] = append([]clientpkg.DomainResource(nil), rules...)
		}
	}
	return nil
}
func (p *outboundResourcePolicy) filter(packet []byte) (bool, []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	reject := func() (bool, []byte) {
		p.dropped++
		var reset []byte
		if validIPv4(packet) && packet[9] == 6 && binary.BigEndian.Uint16(packet[6:8])&0x3fff == 0 {
			h := int(packet[0]&15) * 4
			if len(packet) >= h+20 {
				th := int(packet[h+12]>>4) * 4
				if th >= 20 && h+th <= len(packet) && packet[h+13]&4 == 0 {
					reset = localTCPReset(packet, h, th, len(packet))
					p.resets++
				}
			}
		}
		return false, reset
	}
	if !validIPv4(packet) {
		return reject()
	}
	h := int(packet[0]&15) * 4
	frag := binary.BigEndian.Uint16(packet[6:8])
	var fk [11]byte
	copy(fk[:8], packet[12:20])
	copy(fk[8:10], packet[4:6])
	fk[10] = packet[9]
	now := time.Now()
	if frag&0x1fff != 0 {
		until, ok := p.fragments[fk]
		if !ok || now.After(until) {
			delete(p.fragments, fk)
			return reject()
		}
		if frag&0x2000 == 0 {
			delete(p.fragments, fk)
		}
		return true, nil
	}
	protocol := fmt.Sprintf("ip_%d", packet[9])
	port := 0
	switch packet[9] {
	case 6:
		protocol = "tcp"
	case 17:
		protocol = "udp"
	case 1:
		protocol = "icmp"
	}
	if protocol == "tcp" || protocol == "udp" {
		if len(packet) < h+4 {
			return reject()
		}
		port = int(binary.BigEndian.Uint16(packet[h+2 : h+4]))
	}
	ip := net.IP(packet[16:20])
	var key [4]byte
	copy(key[:], ip)
	allowed := p.index.Matches(ip, protocol, port)
	if !allowed && port == 53 && (protocol == "tcp" || protocol == "udp") && p.dns[key] {
		allowed = true
	}
	if !allowed {
		for _, r := range p.bound[key] {
			if _, ok := clientpkg.MatchDomainResource(r, protocol, port); ok {
				allowed = true
				break
			}
		}
	}
	if !allowed {
		return reject()
	}
	if frag&0x2000 != 0 {
		if len(p.fragments) >= 4096 {
			for k, v := range p.fragments {
				if now.After(v) {
					delete(p.fragments, k)
				}
			}
		}
		if len(p.fragments) >= 4096 {
			return reject()
		}
		p.fragments[fk] = now.Add(30 * time.Second)
	}
	return true, nil
}

// Best-effort warm-up for declared exact resource names also covers a browser's
// existing DNS cache. Only the configured internal DNS servers are queried.
func (p *outboundResourcePolicy) prime(ctx context.Context, servers []string, addRoute func(netip.Addr) error) {
	if len(servers) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var names []string
	for name := range p.domains {
		if !strings.HasPrefix(name, ".") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	if len(names) > 256 {
		names = names[:256]
	}
	jobs := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for name := range jobs {
				if ctx.Err() != nil {
					return
				}
				q := new(dns.Msg)
				q.SetQuestion(dns.Fqdn(name), dns.TypeA)
				for _, server := range servers {
					c := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
					answer, _, err := c.ExchangeContext(ctx, q, net.JoinHostPort(server, "53"))
					if err == nil && answer != nil && answer.Truncated {
						c.Net = "tcp"
						answer, _, err = c.ExchangeContext(ctx, q, net.JoinHostPort(server, "53"))
					}
					if err != nil || answer == nil || answer.Rcode != dns.RcodeSuccess {
						continue
					}
					ips := authorizedDNSAnswers(name, answer.Answer)
					if ctx.Err() != nil {
						return
					}
					if p.bindDNS(name, ips) == nil {
						for _, ip := range ips {
							if a, ok := netip.AddrFromSlice(ip); ok {
								_ = addRoute(a.Unmap())
							}
						}
					}
					break
				}
			}
		}()
	}
feed:
	for _, name := range names {
		select {
		case jobs <- name:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
}
