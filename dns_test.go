package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestFakeResponseStableName(t *testing.T) {
	q := buildQuery("www.google.com")
	ip := [4]byte{198, 18, 0, 1}
	resp, name, err := fakeResponse(q, ip, 120)
	if err != nil {
		t.Fatal(err)
	}
	if name != "www.google.com" {
		t.Fatalf("name %s", name)
	}
	got, err := answerA(resp)
	if err != nil {
		t.Fatal(err)
	}
	if got != ip {
		t.Fatalf("ip %v", got)
	}
}

func TestAAAAEmpty(t *testing.T) {
	q := buildQuery("www.google.com")
	binary.BigEndian.PutUint16(q[len(q)-4:], 28)
	resp, _, err := fakeResponse(q, [4]byte{}, 120)
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(resp[6:8]) != 0 {
		t.Fatalf("ancount %d", binary.BigEndian.Uint16(resp[6:8]))
	}
}

func TestSNI(t *testing.T) {
	host := "www.youtube.com"
	pkt := craftClientHello(host)
	if got := sniffSNI(pkt); got != host {
		t.Fatalf("sni %q", got)
	}
}

func TestHTTPHost(t *testing.T) {
	b := []byte("GET / HTTP/1.1\r\nHost: www.baidu.com\r\n\r\n")
	if got := sniffHost(b); got != "www.baidu.com" {
		t.Fatalf("host %q", got)
	}
}

func buildQuery(name string) []byte {
	var b []byte
	b = append(b, 0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0)
	for _, lab := range bytes.Split([]byte(name), []byte(".")) {
		b = append(b, byte(len(lab)))
		b = append(b, lab...)
	}
	b = append(b, 0, 0, 1, 0, 1)
	return b
}

func answerA(msg []byte) ([4]byte, error) {
	_, off, err := decodeName(msg, 12)
	if err != nil {
		return [4]byte{}, err
	}
	off += 4
	_, off, err = decodeName(msg, off)
	if err != nil {
		return [4]byte{}, err
	}
	off += 8 // type class ttl
	off += 2 // rdlen
	var ip [4]byte
	copy(ip[:], msg[off:off+4])
	return ip, nil
}

func craftClientHello(host string) []byte {
	var sni []byte
	sni = append(sni, 0, byte(len(host)+3))
	sni = append(sni, 0)
	sni = append(sni, byte(len(host)>>8), byte(len(host)))
	sni = append(sni, host...)
	var ext []byte
	ext = append(ext, 0, 0, byte(len(sni)>>8), byte(len(sni)))
	ext = append(ext, sni...)
	var hs []byte
	hs = append(hs, 0x03, 0x03)
	hs = append(hs, make([]byte, 32)...)
	hs = append(hs, 0)    // session
	hs = append(hs, 0, 2, 0x00, 0x2f) // one cipher
	hs = append(hs, 1, 0) // compression
	hs = append(hs, byte(len(ext)>>8), byte(len(ext)))
	hs = append(hs, ext...)
	var rec []byte
	rec = append(rec, 0x01)
	rec = append(rec, byte(len(hs)>>16), byte(len(hs)>>8), byte(len(hs)))
	rec = append(rec, hs...)
	var pkt []byte
	pkt = append(pkt, 0x16, 0x03, 0x01, byte(len(rec)>>8), byte(len(rec)))
	pkt = append(pkt, rec...)
	return pkt
}

func TestCaptiveProbe(t *testing.T) {
	yes := []string{
		"GET /generate_204 HTTP/1.1\r\nHost: connectivitycheck.gstatic.com\r\n\r\n",
		"GET /gen_204?foo=1 HTTP/1.1\r\nHost: www.google.com\r\n\r\n",
		"HEAD /generate_204 HTTP/1.0\r\n\r\n",
	}
	for _, s := range yes {
		if !captiveProbe([]byte(s)) {
			t.Fatalf("want probe: %q", s)
		}
	}
	no := []string{
		"GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n",
		"GET /generate_2040 HTTP/1.1\r\n\r\n",
		"",
	}
	for _, s := range no {
		if captiveProbe([]byte(s)) {
			t.Fatalf("not a probe: %q", s)
		}
	}
}
