package main

import (
	"bytes"
	"encoding/binary"
	"github.com/miekg/dns"
	"inet.af/netaddr"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func packet(body []byte) []byte {
	p := make([]byte, 20+len(body))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	copy(p[20:], body)
	return p
}

type fragmented struct{ r *bytes.Reader }

func (f fragmented) Read(p []byte) (int, error) {
	if len(p) > 3 {
		p = p[:3]
	}
	return f.r.Read(p)
}
func TestIPv4StreamFraming(t *testing.T) {
	a, b := packet([]byte("first")), packet([]byte("second"))
	r := fragmented{bytes.NewReader(append(a, b...))}
	buf := make([]byte, 65535)
	for _, want := range [][]byte{a, b} {
		got, e := readIPv4(r, buf)
		if e != nil || !bytes.Equal(got, want) {
			t.Fatalf("frame mismatch %v", e)
		}
	}
	if _, e := readIPv4(r, buf); e != io.EOF {
		t.Fatal(e)
	}
	a[0] = 0x4f
	if _, e := readIPv4(bytes.NewReader(a), buf); e == nil {
		t.Fatal("bad header accepted")
	}
	if validIPv4(a) {
		t.Fatal("bad length accepted")
	}
}
func TestTunResourceRoutesExcludeGatewayAndUnsafeRanges(t *testing.T) {
	var b netaddr.IPSetBuilder
	b.AddPrefix(netaddr.MustParseIPPrefix("10.0.0.0/24"))
	set, _ := b.IPSet()
	plan, e := routePlan(set, []string{"10.2.0.53"}, map[string][]net.IP{"app.internal": {net.ParseIP("10.3.0.2")}}, []net.IP{net.ParseIP("10.0.0.20")})
	if e != nil {
		t.Fatal(e)
	}
	contains := func(s string) bool {
		ip := netip.MustParseAddr(s)
		for _, p := range plan {
			if p.Contains(ip) {
				return true
			}
		}
		return false
	}
	if contains("10.0.0.20") || !contains("10.0.0.21") || !contains("10.2.0.53") || !contains("10.3.0.2") {
		t.Fatal("bad route plan")
	}
	b.AddPrefix(netaddr.MustParseIPPrefix("0.0.0.0/0"))
	all, _ := b.IPSet()
	if _, e = routePlan(all, nil, nil, nil); e == nil {
		t.Fatal("default accepted")
	}
}
func TestDNSNamesPreventSystemPathInjection(t *testing.T) {
	for _, s := range []string{"../hosts", "a/b", "*", "bad..domain", "-bad.local", "a;reboot", "a\n.local"} {
		if _, e := domainName(s); e == nil {
			t.Fatal(s)
		}
	}
	if got, e := domainName("*.Example.LOCAL."); e != nil || got != "example.local" {
		t.Fatal(got, e)
	}
}
func TestResolverJournalCleanupOnlyOwnedFiles(t *testing.T) {
	dir := t.TempDir()
	journal := filepath.Join(dir, "lease.json")
	if e := installResolvers(dir, journal, []string{"a.internal", "b.internal"}, 2053, "test-tag"); e != nil {
		t.Fatal(e)
	}
	if e := cleanupLease(dir, journal); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(filepath.Join(dir, "a.internal")); !os.IsNotExist(e) {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(dir, "a.internal"), []byte("nameserver 10.0.0.1\n"), 0600)
	if e := installResolvers(dir, journal, []string{"a.internal"}, 2053, "test-tag"); e == nil {
		t.Fatal("overwrote existing DNS")
	}
	os.Remove(filepath.Join(dir, "a.internal"))
	if e := installResolvers(dir, journal, []string{"a.internal"}, 2053, "test-tag"); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(dir, "a.internal"), []byte("modified by user"), 0600)
	if e := cleanupLease(dir, journal); e == nil {
		t.Fatal("deleted externally changed DNS")
	}
	if _, e := os.Stat(journal); e != nil {
		t.Fatal("recovery journal lost")
	}
}
func TestSplitDNSUsesAuthorizedStaticRecordsOnly(t *testing.T) {
	s, e := newSplitDNS([]string{"internal.example"}, map[string][]net.IP{"app.internal.example": {net.ParseIP("10.10.0.1")}}, nil, func(netip.Addr) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	client := &dns.Client{}
	for _, x := range []struct {
		name        string
		typ         uint16
		code, count int
	}{{"app.internal.example.", dns.TypeA, dns.RcodeSuccess, 1}, {"app.internal.example.", dns.TypeAAAA, dns.RcodeSuccess, 0}, {"public.example.", dns.TypeA, dns.RcodeRefused, 0}, {"unknown.internal.example.", dns.TypeA, dns.RcodeServerFailure, 0}} {
		q := new(dns.Msg)
		q.SetQuestion(x.name, x.typ)
		r, _, e := client.Exchange(q, net.JoinHostPort("127.0.0.1", strconv.Itoa(s.port)))
		if e != nil || r.Rcode != x.code || len(r.Answer) != x.count {
			t.Fatalf("DNS %s: %v %v", x.name, r, e)
		}
	}
}
