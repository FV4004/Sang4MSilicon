package main

import (
	"encoding/binary"
	"github.com/miekg/dns"
	clientpkg "github.com/mythologyli/zju-connect/client"
	"net"
	"testing"
)

func aclRule(ip string, protocol string, lo, hi int) clientpkg.IPResource {
	return clientpkg.IPResource{IPMin: net.ParseIP(ip), IPMax: net.ParseIP(ip), Protocol: protocol, PortMin: lo, PortMax: hi}
}
func TestResourceACLRejectsUnlistedPortOnAllowedIP(t *testing.T) {
	p, e := newOutboundResourcePolicy([]clientpkg.IPResource{aclRule("198.51.100.2", "tcp", 80, 80)}, nil, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	a, b := [4]byte{192, 0, 2, 1}, [4]byte{198, 51, 100, 2}
	for _, port := range []uint16{80, 443} {
		packet := diagTCP(a, b, 54321, port, 2, 0)
		before := string(packet)
		ok, reset := p.filter(packet)
		if ok != (port == 80) {
			t.Fatal("port authorization mismatch", port)
		}
		if string(packet) != before {
			t.Fatal("policy changed a packet")
		}
		if port == 443 && (len(reset) != 40 || reset[33] != 0x14 || packetChecksum(reset[:20]) != 0) {
			t.Fatal("denial did not return local reset")
		}
	}
	if p.dropped != 1 || p.resets != 1 {
		t.Fatal("ACL diagnostics incorrect")
	}
}
func TestResourceACLDomainDNSGrantsOnlyDeclaredPortsAndWildcardScope(t *testing.T) {
	domains := clientpkg.DomainResources{"*.internal.example": {{Protocol: "tcp", PortMin: 80, PortMax: 80}}}
	p, e := newOutboundResourcePolicy(nil, domains, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	ip := net.ParseIP("198.51.100.2")
	a, b := [4]byte{192, 0, 2, 1}, [4]byte{198, 51, 100, 2}
	p.bindDNS("unrelated.example", []net.IP{ip})
	if ok, _ := p.filter(diagTCP(a, b, 12345, 80, 2, 0)); ok {
		t.Fatal("unrelated domain granted access")
	}
	p.bindDNS("internal.example", []net.IP{ip})
	if ok, _ := p.filter(diagTCP(a, b, 12345, 80, 2, 0)); ok {
		t.Fatal("wildcard granted apex access")
	}
	p.bindDNS("ehr.internal.example", []net.IP{ip})
	if ok, _ := p.filter(diagTCP(a, b, 12345, 80, 2, 0)); !ok {
		t.Fatal("authorized DNS binding rejected")
	}
	if ok, _ := p.filter(diagTCP(a, b, 12345, 443, 2, 0)); ok {
		t.Fatal("DNS binding granted all ports")
	}
}
func TestResourceACLDNSAndProtocolRules(t *testing.T) {
	p, e := newOutboundResourcePolicy([]clientpkg.IPResource{aclRule("198.51.100.2", "tcp", 80, 80)}, nil, nil, []string{"192.0.2.53"})
	if e != nil {
		t.Fatal(e)
	}
	udp := make([]byte, 28)
	udp[0] = 0x45
	udp[9] = 17
	binary.BigEndian.PutUint16(udp[2:4], 28)
	copy(udp[12:16], net.ParseIP("192.0.2.1").To4())
	copy(udp[16:20], net.ParseIP("192.0.2.53").To4())
	binary.BigEndian.PutUint16(udp[22:24], 53)
	if ok, _ := p.filter(udp); !ok {
		t.Fatal("configured DNS blocked")
	}
	binary.BigEndian.PutUint16(udp[22:24], 443)
	if ok, _ := p.filter(udp); ok {
		t.Fatal("DNS exception granted other service")
	}
	copy(udp[16:20], net.ParseIP("198.51.100.2").To4())
	binary.BigEndian.PutUint16(udp[22:24], 80)
	if ok, _ := p.filter(udp); ok {
		t.Fatal("TCP permission granted UDP")
	}
	if _, e := newOutboundResourcePolicy(nil, nil, nil, nil); e == nil {
		t.Fatal("missing policy allowed")
	}
}
func TestAuthorizedDNSAnswersFollowsAliasesNotUnrelatedRecords(t *testing.T) {
	a, _ := dns.NewRR("ehr.internal.example. 60 IN CNAME app.host.example.")
	b, _ := dns.NewRR("app.host.example. 60 IN A 198.51.100.2")
	other, _ := dns.NewRR("unrelated.example. 60 IN A 203.0.113.9")
	ips := authorizedDNSAnswers("ehr.internal.example", []dns.RR{a, b, other})
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("198.51.100.2")) {
		t.Fatal("unrelated DNS answers authorized", ips)
	}
}

func TestResourceACLFragmentsRequireAuthorizedFirstFragment(t *testing.T) {
	p, err := newOutboundResourcePolicy([]clientpkg.IPResource{aclRule("198.51.100.2", "tcp", 80, 80)}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	a, b := [4]byte{192, 0, 2, 1}, [4]byte{198, 51, 100, 2}
	first := diagTCP(a, b, 12345, 80, 2, 0)
	binary.BigEndian.PutUint16(first[4:6], 123)
	binary.BigEndian.PutUint16(first[6:8], 0x2000)
	tail := append([]byte(nil), first[:28]...)
	binary.BigEndian.PutUint16(tail[2:4], 28)
	binary.BigEndian.PutUint16(tail[6:8], 3)
	if ok, _ := p.filter(tail); ok {
		t.Fatal("orphan fragment allowed")
	}
	if ok, _ := p.filter(first); !ok {
		t.Fatal("authorized first fragment denied")
	}
	if ok, _ := p.filter(tail); !ok {
		t.Fatal("authorized continuation denied")
	}
	if ok, _ := p.filter(tail); ok {
		t.Fatal("fragment association survived final fragment")
	}
	binary.BigEndian.PutUint16(first[22:24], 443)
	if ok, _ := p.filter(first); ok {
		t.Fatal("unlisted first fragment allowed")
	}
	if ok, _ := p.filter(tail); ok {
		t.Fatal("denied first fragment authorized continuation")
	}
}
