package main

import (
	"bytes"
	"flag"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

type fakeMap struct {
	mu    sync.Mutex
	next  uint32
	toIP  map[string][4]byte
	toDom map[[4]byte]string
}

func newFakeMap() *fakeMap {
	return &fakeMap{
		next:  ip4tou32(net.IPv4(198, 18, 0, 1)),
		toIP:  map[string][4]byte{},
		toDom: map[[4]byte]string{},
	}
}

func ip4tou32(ip net.IP) uint32 {
	b := ip.To4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func u32toip(v uint32) [4]byte {
	return [4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

func (m *fakeMap) assign(domain string) [4]byte {
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	m.mu.Lock()
	defer m.mu.Unlock()
	if ip, ok := m.toIP[domain]; ok {
		return ip
	}
	// 198.18.0.0/15 ends at 198.19.255.254
	if m.next >= ip4tou32(net.IPv4(198, 20, 0, 0)) {
		m.next = ip4tou32(net.IPv4(198, 18, 0, 1))
	}
	ip := u32toip(m.next)
	m.next++
	m.toIP[domain] = ip
	m.toDom[ip] = domain
	log.Printf("fakeip %s -> %d.%d.%d.%d", domain, ip[0], ip[1], ip[2], ip[3])
	return ip
}

func (m *fakeMap) domain(ip net.IP) string {
	b := ip.To4()
	if b == nil {
		return ""
	}
	var key [4]byte
	copy(key[:], b)
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.toDom[key]
}

func main() {
	socks := flag.String("socks", "192.168.1.101:1081", "upstream socks5")
	dnsAddr := flag.String("dns", "127.0.0.1:1053", "fake-ip dns listen")
	listen := flag.String("listen", "0.0.0.0:12345", "transparent redirect listen")
	flag.Parse()

	fm := newFakeMap()
	go serveDNS(*dnsAddr, fm)
	log.Printf("domain-socks socks=%s dns=%s listen=%s", *socks, *dnsAddr, *listen)
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleConn(c, fm, *socks)
	}
}

func serveDNS(addr string, fm *fakeMap) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Fatalf("dns: %v", err)
	}
	defer pc.Close()
	buf := make([]byte, 1500)
	for {
		n, peer, err := pc.ReadFrom(buf)
		if err != nil {
			log.Printf("dns read: %v", err)
			continue
		}
		q := append([]byte(nil), buf[:n]...)
		name, off, err := decodeName(q, 12)
		if err != nil || off+2 > len(q) {
			continue
		}
		qtype := uint16(q[off])<<8 | uint16(q[off+1])
		var ip [4]byte
		if qtype == 1 && name != "" {
			ip = fm.assign(name)
		}
		resp, _, err := fakeResponse(q, ip, 120)
		if err != nil {
			continue
		}
		_, _ = pc.WriteTo(resp, peer)
	}
}

func handleConn(c net.Conn, fm *fakeMap, proxy string) {
	defer c.Close()
	dstIP, dstPort, err := originalDst(c)
	if err != nil {
		log.Printf("original dst: %v", err)
		return
	}
	domain := fm.domain(dstIP)
	var prefix []byte
	if domain == "" || dstPort == 80 {
		var sniffed string
		prefix, sniffed = peekHost(c)
		if domain == "" {
			domain = sniffed
		}
	}
	if dstPort == 80 && captiveProbe(prefix) {
		_, _ = c.Write([]byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		return
	}
	up, err := socksConnect(proxy, domain, dstIP, dstPort)
	if err != nil {
		target := domain
		if target == "" {
			target = dstIP.String()
		}
		log.Printf("socks fail %s -> %s:%d: %v", c.RemoteAddr(), target, dstPort, err)
		return
	}
	defer up.Close()
	target := domain
	how := "domain"
	if target == "" {
		target = dstIP.String()
		how = "ip"
	}
	log.Printf("socks ok %s %s -> %s:%d", how, c.RemoteAddr(), target, dstPort)
	if len(prefix) > 0 {
		if _, err = up.Write(prefix); err != nil {
			return
		}
	}
	setKeepAlive(c)
	setKeepAlive(up)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(up, c)
		closeWrite(up)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(c, up)
		closeWrite(c)
	}()
	wg.Wait()
}

func captiveProbe(prefix []byte) bool {
	line := prefix
	if i := bytes.Index(prefix, []byte("\r\n")); i >= 0 {
		line = prefix[:i]
	}
	fields := bytes.Fields(line)
	if len(fields) < 2 {
		return false
	}
	path := string(fields[1])
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	return path == "/generate_204" || path == "/gen_204"
}

func setKeepAlive(c net.Conn) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tc.SetKeepAlive(true)
	_ = tc.SetKeepAlivePeriod(30 * time.Second)
	_ = tc.SetNoDelay(true)
}

func closeWrite(c net.Conn) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tc.CloseWrite()
}

func peekHost(c net.Conn) ([]byte, string) {
	_ = c.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	buf := make([]byte, 2048)
	n, _ := c.Read(buf)
	_ = c.SetReadDeadline(time.Time{})
	if n <= 0 {
		return nil, ""
	}
	prefix := append([]byte(nil), buf[:n]...)
	host := strings.TrimSuffix(strings.ToLower(sniffHost(prefix)), ".")
	return prefix, host
}
