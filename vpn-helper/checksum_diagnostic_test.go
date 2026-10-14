package main

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

func signDiagnosticTCP(p []byte) {
	h := int(p[0]&15) * 4
	p[10] = 0
	p[11] = 0
	binary.BigEndian.PutUint16(p[10:12], packetChecksum(p[:h]))
	p[h+16] = 0
	p[h+17] = 0
	pseudo := make([]byte, 12+len(p)-h)
	copy(pseudo[:8], p[12:20])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(p)-h))
	copy(pseudo[12:], p[h:])
	binary.BigEndian.PutUint16(p[h+16:h+18], packetChecksum(pseudo))
}
func TestChecksumDiagnosticValidHandshakeAndCorruptionWithoutMutation(t *testing.T) {
	a, b := [4]byte{192, 0, 2, 1}, [4]byte{198, 51, 100, 2}
	d := &diagnosticState{start: time.Now()}
	syn := diagTCP(a, b, 54321, 80, 0xc2, 0)
	binary.BigEndian.PutUint32(syn[24:28], 100)
	signDiagnosticTCP(syn)
	synAck := diagTCP(b, a, 80, 54321, 0x52, 0)
	binary.BigEndian.PutUint32(synAck[24:28], 400)
	binary.BigEndian.PutUint32(synAck[28:32], 101)
	signDiagnosticTCP(synAck)
	ack := diagTCP(a, b, 54321, 80, 0x10, 0)
	binary.BigEndian.PutUint32(ack[24:28], 101)
	binary.BigEndian.PutUint32(ack[28:32], 401)
	signDiagnosticTCP(ack)
	d.sendBegin(syn)
	d.received(synAck)
	before := string(ack)
	d.sendBegin(ack)
	if string(ack) != before {
		t.Fatal("checksum diagnostic rewrote a packet")
	}
	report := d.summary()
	if !strings.Contains(report, "IPCK_GOOD_TCPCK_GOOD_SEQREL_1_ACKREL_1") || d.badIPTX != 0 || d.badTCPTX != 0 {
		t.Fatal(report)
	}
	ack[8]++
	d.sendBegin(ack)
	if d.badIPTX != 1 || d.badTCPTX != 0 {
		t.Fatal("IP-only corruption classification incorrect")
	}
	ack[39]++
	d.sendBegin(ack)
	if d.badTCPTX != 1 {
		t.Fatal("transport corruption not detected")
	}
}
func TestChecksumDiagnosticRetainsHeadAndRollingTailWithBoundedFlowKeys(t *testing.T) {
	a, b := [4]byte{192, 0, 2, 1}, [4]byte{198, 51, 100, 2}
	d := &diagnosticState{start: time.Now()}
	for i := 0; i < 30; i++ {
		flags := byte(0x10)
		if i == 0 {
			flags = 2
		}
		p := diagTCP(a, b, 12345, 80, flags, 0)
		binary.BigEndian.PutUint32(p[24:28], uint32(100+i))
		signDiagnosticTCP(p)
		d.sendBegin(p)
	}
	if len(d.packets) != 12 || !strings.Contains(d.packets[0], "SEQREL_0") || !strings.Contains(d.packets[5], "SEQREL_5") || !strings.Contains(d.packets[6], "SEQREL_24") || !strings.Contains(d.packets[11], "SEQREL_29") {
		t.Fatal(d.packets)
	}
	for i := 0; i < 1000; i++ {
		d.sendBegin(diagTCP(a, b, uint16(20000+i), 80, 2, 0))
	}
	if len(d.flows) > 32 || len(d.anchors) > 32 || len(d.summary()) > 4096 {
		t.Fatal("unbounded diagnostics")
	}
}
