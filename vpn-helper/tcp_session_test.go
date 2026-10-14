package main

import (
	"encoding/binary"
	"testing"
)

func TestTCPEpochAcceptsNewHandshakeAndUnchangedPayload(t *testing.T) {
	a, b := [4]byte{192, 0, 2, 1}, [4]byte{198, 51, 100, 2}
	g := newTCPSessionGuard()
	packets := [][]byte{diagTCP(a, b, 54321, 80, 0xc2, 0), diagTCP(b, a, 80, 54321, 0x52, 0), diagTCP(a, b, 54321, 80, 0x10, 0), diagTCP(a, b, 54321, 80, 0x18, 0)}
	for i, p := range packets {
		saved := string(p)
		ok, r := g.filter(p, i != 1)
		if !ok || r != nil || string(p) != saved {
			t.Fatal("fresh TCP rejected or modified", i)
		}
	}
}
func TestTCPEpochRejectsOldACKDataAndUnsolicitedFIN(t *testing.T) {
	a, b := [4]byte{192, 0, 2, 1}, [4]byte{198, 51, 100, 2}
	g := newTCPSessionGuard()
	old := diagTCP(a, b, 54321, 80, 0x18, 0)
	binary.BigEndian.PutUint32(old[28:32], 123456)
	ok, r := g.filter(old, true)
	if ok || len(r) != 40 || r[33] != 4 || binary.BigEndian.Uint32(r[24:28]) != 123456 {
		t.Fatal("old connection reset invalid")
	}
	if string(r[12:16]) != string(b[:]) || string(r[16:20]) != string(a[:]) || binary.BigEndian.Uint16(r[20:22]) != 80 || binary.BigEndian.Uint16(r[22:24]) != 54321 {
		t.Fatal("reset did not target local socket")
	}
	if packetChecksum(r[:20]) != 0 {
		t.Fatal("IP reset checksum invalid")
	}
	pseudo := make([]byte, 32)
	copy(pseudo[:8], r[12:20])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], 20)
	copy(pseudo[12:], r[20:])
	if packetChecksum(pseudo) != 0 {
		t.Fatal("TCP reset checksum invalid")
	}
	if ok, r = g.filter(diagTCP(b, a, 80, 54321, 0x11, 0), false); ok || r != nil {
		t.Fatal("old inbound FIN admitted")
	}
	if ok, r = g.filter(diagTCP(a, b, 54321, 80, 4, 0), true); ok || r != nil {
		t.Fatal("reset loop possible")
	}
	if g.droppedTX != 2 || g.droppedRX != 1 || g.resets != 1 {
		t.Fatal("drop counts incorrect")
	}
	// The browser can retry the same tuple with a genuinely new SYN.
	if ok, _ = g.filter(diagTCP(a, b, 54321, 80, 2, 0), true); !ok {
		t.Fatal("fresh retry blocked")
	}
	if ok, _ = g.filter(old, true); !ok {
		t.Fatal("new epoch flow blocked")
	}
}
func TestTCPEpochDoesNotCarryStateBetweenVPNWorkers(t *testing.T) {
	a, b := [4]byte{192, 0, 2, 1}, [4]byte{198, 51, 100, 2}
	g := newTCPSessionGuard()
	g.filter(diagTCP(a, b, 12345, 80, 2, 0), true)
	if ok, _ := newTCPSessionGuard().filter(diagTCP(a, b, 12345, 80, 0x10, 0), true); ok {
		t.Fatal("previous VPN flow survived new guard")
	}
	udp := make([]byte, 28)
	udp[0] = 0x45
	udp[9] = 17
	binary.BigEndian.PutUint16(udp[2:4], 28)
	if ok, r := g.filter(udp, true); !ok || r != nil {
		t.Fatal("UDP altered")
	}
}
func TestTCPEpochFragmentRequiresCurrentFirstFragment(t *testing.T) {
	a, b := [4]byte{192, 0, 2, 1}, [4]byte{198, 51, 100, 2}
	g := newTCPSessionGuard()
	first := diagTCP(a, b, 12345, 80, 2, 0)
	binary.BigEndian.PutUint16(first[6:8], 0x2000)
	rest := append([]byte(nil), first...)
	binary.BigEndian.PutUint16(rest[6:8], 1)
	if ok, _ := g.filter(rest, true); ok {
		t.Fatal("orphan fragment admitted")
	}
	if ok, _ := g.filter(first, true); !ok {
		t.Fatal("new fragmented SYN rejected")
	}
	if ok, _ := g.filter(rest, true); !ok {
		t.Fatal("current fragment rejected")
	}
	if ok, _ := g.filter(rest, true); ok {
		t.Fatal("completed fragment association retained")
	}
}
