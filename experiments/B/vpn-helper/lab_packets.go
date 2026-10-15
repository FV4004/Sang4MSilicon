package main

import "encoding/binary"

func labChecksum(p []byte) uint16 {
	var sum uint32
	for len(p) > 1 {
		sum += uint32(binary.BigEndian.Uint16(p))
		p = p[2:]
	}
	if len(p) == 1 {
		sum += uint32(p[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return ^uint16(sum)
}
func labTransportChecksum(ip, segment []byte) uint16 {
	pseudo := make([]byte, 12+len(segment))
	copy(pseudo, ip[12:20])
	pseudo[9] = ip[9]
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(segment)))
	copy(pseudo[12:], segment)
	return labChecksum(pseudo)
}
func normalizeLabIPv4(p []byte) {
	if !validIPv4(p) {
		return
	}
	h := int(p[0]&15) * 4
	p[10] = 0
	p[11] = 0
	binary.BigEndian.PutUint16(p[10:12], labChecksum(p[:h]))
	if binary.BigEndian.Uint16(p[6:8])&0x3fff != 0 {
		return
	}
	seg := p[h:]
	if p[9] == 6 && len(seg) >= 20 {
		th := int(seg[12]>>4) * 4
		if th < 20 || th > len(seg) {
			return
		}
		if seg[13]&2 != 0 {
			for i := 20; i < th; {
				kind := seg[i]
				if kind == 0 {
					break
				}
				if kind == 1 {
					i++
					continue
				}
				if i+1 >= th {
					break
				}
				n := int(seg[i+1])
				if n < 2 || i+n > th {
					break
				}
				if kind == 2 && n == 4 && binary.BigEndian.Uint16(seg[i+2:i+4]) > 1200 {
					binary.BigEndian.PutUint16(seg[i+2:i+4], 1200)
				}
				i += n
			}
		}
		seg[16] = 0
		seg[17] = 0
		binary.BigEndian.PutUint16(seg[16:18], labTransportChecksum(p, seg))
	} else if p[9] == 17 && len(seg) >= 8 {
		n := int(binary.BigEndian.Uint16(seg[4:6]))
		if n < 8 || n > len(seg) || binary.BigEndian.Uint16(seg[6:8]) == 0 {
			return
		}
		seg = seg[:n]
		seg[6] = 0
		seg[7] = 0
		v := labTransportChecksum(p, seg)
		if v == 0 {
			v = 65535
		}
		binary.BigEndian.PutUint16(seg[6:8], v)
	}
}
