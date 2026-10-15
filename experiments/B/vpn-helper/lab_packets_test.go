package main

import (
	"encoding/binary"
	"testing"
)

func TestLabRFC1071Checksum(t *testing.T) {
	if labChecksum([]byte{0, 1, 0xf2, 3, 0xf4, 0xf5, 0xf6, 0xf7}) != 0x220d {
		t.Fatal("RFC checksum mismatch")
	}
}
func TestLabSYNMSSAndChecksums(t *testing.T) {
	p := packet(make([]byte, 24))
	p[9] = 6
	copy(p[12:20], []byte{10, 0, 0, 2, 10, 0, 0, 3})
	p[32] = 0x60
	p[33] = 2
	copy(p[40:44], []byte{2, 4, 5, 0xb4})
	normalizeLabIPv4(p)
	if binary.BigEndian.Uint16(p[42:44]) != 1200 || labChecksum(p[:20]) != 0 || labTransportChecksum(p, p[20:]) != 0 {
		t.Fatal("MSS/checksum repair failed")
	}
}
func TestLabFragmentsAreNotTransportRewritten(t *testing.T) {
	p := packet(make([]byte, 24))
	p[9] = 6
	p[6] = 0x20
	p[36] = 0xab
	p[37] = 0xcd
	normalizeLabIPv4(p)
	if p[36] != 0xab || p[37] != 0xcd {
		t.Fatal("fragment checksum changed")
	}
}

func TestLabUDPChecksumAndZeroChecksumPreservation(t *testing.T) {
	p := packet(make([]byte, 12))
	p[9] = 17
	copy(p[12:20], []byte{10, 0, 0, 2, 10, 0, 0, 3})
	binary.BigEndian.PutUint16(p[24:26], 12)
	binary.BigEndian.PutUint16(p[26:28], 0x1234)
	copy(p[28:], []byte{1, 2, 3, 4})
	normalizeLabIPv4(p)
	if labTransportChecksum(p, p[20:]) != 0 || p[28] != 1 || p[31] != 4 {
		t.Fatal("UDP normalization corrupted payload/checksum")
	}
	p[26] = 0
	p[27] = 0
	normalizeLabIPv4(p)
	if p[26] != 0 || p[27] != 0 {
		t.Fatal("disabled UDP checksum was enabled")
	}
}
