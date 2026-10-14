package main

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

func diagTCP(src, dst [4]byte, sourcePort, destPort uint16, flags byte, options int) []byte {
	p := make([]byte, 40+options)
	p[0] = 0x45
	p[9] = 6
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	copy(p[12:16], src[:])
	copy(p[16:20], dst[:])
	binary.BigEndian.PutUint16(p[20:22], sourcePort)
	binary.BigEndian.PutUint16(p[22:24], destPort)
	p[32] = byte((20+options)/4) << 4
	p[33] = flags
	return p
}
func TestPacketDiagnosticSymmetricFlowAndSourceClassification(t *testing.T) {
	a, b := [4]byte{192, 0, 2, 7}, [4]byte{198, 51, 100, 8}
	d := &diagnosticState{start: time.Now()}
	d.setVIP(a[:])
	tx := diagTCP(a, b, 54321, 80, 2, 4)
	saved := string(tx)
	d.sendBegin(tx)
	d.sent()
	d.received(diagTCP(b, a, 80, 54321, 0x12, 0))
	report := d.summary()
	for _, want := range []string{"TX_F1_TCP_FLAGS_02_SRC_VIP_DST_OTHER_LEN_44_PAY_0", "RX_F1_TCP_FLAGS_12_SRC_OTHER_DST_VIP_LEN_40_PAY_0"} {
		if !strings.Contains(report, want) {
			t.Fatal(report)
		}
	}
	if string(tx) != saved || strings.Contains(report, "192.0.2.7") || strings.Contains(report, "198.51.100.8") || strings.Contains(report, "54321") {
		t.Fatal("packet modified or endpoint exposed", report)
	}
}
func TestPacketDiagnosticFragmentAndMalformedBoundaries(t *testing.T) {
	a, b := [4]byte{192, 0, 2, 7}, [4]byte{198, 51, 100, 8}
	d := &diagnosticState{start: time.Now()}
	p := diagTCP(a, b, 12345, 80, 2, 0)
	binary.BigEndian.PutUint16(p[6:8], 0x2000)
	d.sendBegin(p)
	if !strings.Contains(d.summary(), "TCP_FRAG_FLAGS_NA") {
		t.Fatal(d.summary())
	}
	for _, bad := range [][]byte{nil, {0x45}, make([]byte, 20)} {
		d.sendBegin(bad)
	}
	if len(d.packets) != 1 {
		t.Fatal("malformed headers interpreted")
	}
}
func TestPacketDiagnosticStorageBoundedDuringSuccessfulTraffic(t *testing.T) {
	d := &diagnosticState{start: time.Now()}
	for i := 0; i < 1000; i++ {
		d.sendBegin(diagTCP([4]byte{192, 0, 2, 1}, [4]byte{198, 51, 100, 2}, uint16(10000+i), 80, 0x10, 0))
		d.sent()
	}
	if len(d.packets) != 12 || len(d.flows) > 12 || len(d.summary()) > 4096 {
		t.Fatal("unbounded diagnostic storage")
	}
}
