package main

import (
	"encoding/binary"
	"sync"
	"time"
)

type tcpSessionGuard struct {
	mu                           sync.Mutex
	flows                        map[[12]byte]bool
	fragments                    map[[10]byte]time.Time
	droppedTX, droppedRX, resets uint64
}

func newTCPSessionGuard() *tcpSessionGuard {
	return &tcpSessionGuard{flows: make(map[[12]byte]bool), fragments: make(map[[10]byte]time.Time)}
}

// An epoch belongs to one VPN worker. Only a SYN starting in this epoch admits
// a TCP tuple; no payload is inspected and non-TCP traffic is unchanged.
func (g *tcpSessionGuard) filter(p []byte, out bool) (bool, []byte) {
	if len(p) < 20 || p[0]>>4 != 4 || p[9] != 6 {
		return true, nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	reject := func(reset []byte) (bool, []byte) {
		if out {
			g.droppedTX++
		} else {
			g.droppedRX++
		}
		if reset != nil {
			g.resets++
		}
		return false, reset
	}
	h := int(p[0]&15) * 4
	total := int(binary.BigEndian.Uint16(p[2:4]))
	if h < 20 || total < h || total > len(p) {
		return reject(nil)
	}
	frag := binary.BigEndian.Uint16(p[6:8])
	offset := frag & 0x1fff
	var fk [10]byte
	copy(fk[:8], p[12:20])
	copy(fk[8:], p[4:6])
	now := time.Now()
	if offset != 0 {
		until, ok := g.fragments[fk]
		if !ok || now.After(until) {
			delete(g.fragments, fk)
			return reject(nil)
		}
		if frag&0x2000 == 0 {
			delete(g.fragments, fk)
		}
		return true, nil
	}
	if total < h+20 {
		return reject(nil)
	}
	th := int(p[h+12]>>4) * 4
	if th < 20 || total < h+th {
		return reject(nil)
	}
	var key [12]byte
	if out {
		copy(key[:4], p[12:16])
		copy(key[4:8], p[16:20])
		copy(key[8:], p[h:h+4])
	} else {
		copy(key[:4], p[16:20])
		copy(key[4:8], p[12:16])
		copy(key[8:10], p[h+2:h+4])
		copy(key[10:], p[h:h+2])
	}
	flags := p[h+13]
	if flags&2 != 0 && flags&0x15 == 0 { // SYN without ACK/RST, including ECN SYN.
		if !g.flows[key] && len(g.flows) >= 65536 {
			return reject(nil)
		}
		g.flows[key] = true
	}
	if !g.flows[key] {
		if out && frag&0x2000 == 0 && flags&4 == 0 {
			return reject(localTCPReset(p, h, th, total))
		}
		return reject(nil)
	}
	if frag&0x2000 != 0 {
		if len(g.fragments) >= 4096 {
			for k, t := range g.fragments {
				if now.After(t) {
					delete(g.fragments, k)
				}
			}
		}
		if len(g.fragments) >= 4096 {
			return reject(nil)
		}
		g.fragments[fk] = now.Add(30 * time.Second)
	}
	return true, nil
}
func packetChecksum(b []byte) uint16 {
	var sum uint32
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b[:2]))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return ^uint16(sum)
}

// Reply only into the local UTUN to clear a socket predating this VPN epoch.
// RFC TCP reset sequencing: for an ACK, RST.SEQ=SEG.ACK; otherwise acknowledge
// segment sequence-space length. Never transmit this reset to the gateway.
func localTCPReset(p []byte, h, th, total int) []byte {
	r := make([]byte, 40)
	r[0] = 0x45
	r[8] = 64
	r[9] = 6
	binary.BigEndian.PutUint16(r[2:4], 40)
	copy(r[12:16], p[16:20])
	copy(r[16:20], p[12:16])
	copy(r[20:22], p[h+2:h+4])
	copy(r[22:24], p[h:h+2])
	r[32] = 0x50
	if p[h+13]&0x10 != 0 {
		copy(r[24:28], p[h+8:h+12])
		r[33] = 4
	} else {
		seq := binary.BigEndian.Uint32(p[h+4:h+8]) + uint32(total-h-th)
		if p[h+13]&2 != 0 {
			seq++
		}
		if p[h+13]&1 != 0 {
			seq++
		}
		binary.BigEndian.PutUint32(r[28:32], seq)
		r[33] = 0x14
	}
	binary.BigEndian.PutUint16(r[10:12], packetChecksum(r[:20]))
	pseudo := make([]byte, 32)
	copy(pseudo[:8], r[12:20])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], 20)
	copy(pseudo[12:], r[20:])
	binary.BigEndian.PutUint16(r[36:38], packetChecksum(pseudo))
	return r
}
