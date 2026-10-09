package main

import (
	"encoding/binary"
	"fmt"
	"strings"
)

func decodeName(msg []byte, off int) (string, int, error) {
	if off < 0 || off >= len(msg) {
		return "", 0, fmt.Errorf("name out of range")
	}
	var labels []string
	jumped := false
	end := off
	seen := 0
	for {
		if seen > 128 || off >= len(msg) {
			return "", 0, fmt.Errorf("bad name")
		}
		seen++
		n := int(msg[off])
		if n == 0 {
			off++
			if !jumped {
				end = off
			}
			break
		}
		if n&0xC0 == 0xC0 {
			if off+1 >= len(msg) {
				return "", 0, fmt.Errorf("bad pointer")
			}
			ptr := int(n&0x3F)<<8 | int(msg[off+1])
			if ptr >= len(msg) {
				return "", 0, fmt.Errorf("pointer out of range")
			}
			if !jumped {
				end = off + 2
			}
			off = ptr
			jumped = true
			continue
		}
		if n&0xC0 != 0 {
			return "", 0, fmt.Errorf("bad label")
		}
		off++
		if off+n > len(msg) {
			return "", 0, fmt.Errorf("label overflow")
		}
		labels = append(labels, string(msg[off:off+n]))
		off += n
		if !jumped {
			end = off
		}
	}
	return strings.ToLower(strings.Join(labels, ".")), end, nil
}

// fakeResponse answers an A query with ip, or an empty NOERROR for anything else.
func fakeResponse(query []byte, ip [4]byte, ttl uint32) ([]byte, string, error) {
	if len(query) < 12 {
		return nil, "", fmt.Errorf("short query")
	}
	name, off, err := decodeName(query, 12)
	if err != nil {
		return nil, "", err
	}
	if off+4 > len(query) {
		return nil, "", fmt.Errorf("short question")
	}
	qtype := binary.BigEndian.Uint16(query[off : off+2])
	qEnd := off + 4

	resp := make([]byte, 0, qEnd+16)
	resp = append(resp, query[:2]...)
	resp = append(resp, 0x81, 0x80)
	resp = append(resp, 0, 1) // QDCOUNT
	if qtype == 1 && name != "" {
		resp = append(resp, 0, 1) // ANCOUNT
	} else {
		resp = append(resp, 0, 0)
	}
	resp = append(resp, 0, 0, 0, 0) // NSCOUNT, ARCOUNT
	resp = append(resp, query[12:qEnd]...)
	if qtype == 1 && name != "" {
		resp = append(resp, 0xC0, 0x0C)
		resp = append(resp, 0, 1, 0, 1)
		var ttlb [4]byte
		binary.BigEndian.PutUint32(ttlb[:], ttl)
		resp = append(resp, ttlb[:]...)
		resp = append(resp, 0, 4)
		resp = append(resp, ip[:]...)
	}
	return resp, name, nil
}
