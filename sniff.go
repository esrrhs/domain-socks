package main

import "bytes"

func sniffHost(b []byte) string {
	if len(b) < 5 {
		return ""
	}
	if b[0] == 0x16 && b[1] == 0x03 {
		if host := sniffSNI(b); host != "" {
			return host
		}
	}
	if isHTTP(b) {
		return sniffHTTPHost(b)
	}
	return ""
}

func isHTTP(b []byte) bool {
	methods := []string{"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT "}
	for _, m := range methods {
		if bytes.HasPrefix(b, []byte(m)) {
			return true
		}
	}
	return false
}

func sniffHTTPHost(b []byte) string {
	lower := bytes.ToLower(b)
	key := []byte("\nhost:")
	i := bytes.Index(lower, key)
	if i < 0 {
		return ""
	}
	rest := b[i+len(key):]
	rest = bytes.TrimLeft(rest, " \t")
	end := bytes.IndexByte(rest, '\n')
	if end < 0 {
		return ""
	}
	host := string(bytes.TrimSpace(rest[:end]))
	if c := bytes.IndexByte([]byte(host), ':'); c >= 0 {
		host = host[:c]
	}
	return host
}

func sniffSNI(b []byte) string {
	// TLS record + handshake, enough to walk to the server_name extension.
	if len(b) < 5 || b[0] != 0x16 {
		return ""
	}
	recLen := int(b[3])<<8 | int(b[4])
	if 5+recLen > len(b) {
		b = b[:len(b)]
	} else {
		b = b[:5+recLen]
	}
	if len(b) < 5+4+2+32+1 {
		return ""
	}
	hs := b[5:]
	if hs[0] != 0x01 {
		return ""
	}
	off := 4 + 2 + 32
	if off >= len(hs) {
		return ""
	}
	sidLen := int(hs[off])
	off++
	off += sidLen
	if off+2 > len(hs) {
		return ""
	}
	csLen := int(hs[off])<<8 | int(hs[off+1])
	off += 2 + csLen
	if off+1 > len(hs) {
		return ""
	}
	compLen := int(hs[off])
	off++
	off += compLen
	if off+2 > len(hs) {
		return ""
	}
	extLen := int(hs[off])<<8 | int(hs[off+1])
	off += 2
	extEnd := off + extLen
	if extEnd > len(hs) {
		extEnd = len(hs)
	}
	for off+4 <= extEnd {
		typ := int(hs[off])<<8 | int(hs[off+1])
		l := int(hs[off+2])<<8 | int(hs[off+3])
		off += 4
		if off+l > extEnd {
			return ""
		}
		if typ == 0 && l >= 5 {
			data := hs[off : off+l]
			// list length(2) + name type(1) + name length(2) + name
			if len(data) >= 5 && data[2] == 0 {
				nlen := int(data[3])<<8 | int(data[4])
				if 5+nlen <= len(data) {
					return string(data[5 : 5+nlen])
				}
			}
		}
		off += l
	}
	return ""
}
