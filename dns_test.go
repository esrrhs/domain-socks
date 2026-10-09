package main

import (
	"context"
	"net"
	"testing"
	"time"

	ghdns "github.com/esrrhs/gohome/dns"
)

func TestSplitRoutingWithGohome(t *testing.T) {
	cfg := ghdns.DefaultConfig()
	cfg.EnableFakeIP = true

	r, err := ghdns.NewResolver(cfg)
	if err != nil {
		t.Fatalf("failed to create resolver: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// 1. 测试国内常见主干域名 -> ShouldProxy 应为 false
	cnDomains := []string{
		"baidu.com",
		"www.baidu.com",
		"qq.com",
		"weixin.qq.com",
		"taobao.com",
		"aliyun.com",
		"bilibili.com",
		"gov.cn",
		"pku.edu.cn",
	}

	for _, d := range cnDomains {
		sp, err := r.ShouldProxy(d)
		if err != nil {
			t.Fatalf("ShouldProxy(%s) returned error: %v", d, err)
		}
		if sp {
			t.Errorf("expected %s NOT to proxy (direct), but ShouldProxy returned true", d)
		}
	}

	// 2. 测试海外/代理域名 -> 应该分配 Fake-IP，且 ShouldProxy 判定为 true
	proxyDomain := "google.com"
	ips, err := r.Resolve(ctx, proxyDomain)
	if err != nil {
		t.Fatalf("resolve %s failed: %v", proxyDomain, err)
	}
	if len(ips) == 0 {
		t.Fatalf("no ips for %s", proxyDomain)
	}

	fakeIP := ips[0]
	if !r.IsFakeIP(fakeIP) {
		t.Fatalf("expected fake IP for %s, got %v", proxyDomain, fakeIP)
	}

	// 反查
	origDomain, ok := r.LookupDomainByFakeIP(fakeIP)
	if !ok || origDomain != proxyDomain {
		t.Fatalf("expected reverse lookup %s, got %s (ok=%v)", proxyDomain, origDomain, ok)
	}

	// 对 Fake-IP 做代理判定
	sp, err := r.ShouldProxy(fakeIP.String())
	if err != nil {
		t.Fatalf("ShouldProxy(%s) err: %v", fakeIP, err)
	}
	if !sp {
		t.Errorf("expected fake IP %s to proxy", fakeIP)
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
	hs = append(hs, 0)                // session
	hs = append(hs, 0, 2, 0x00, 0x2f) // one cipher
	hs = append(hs, 1, 0)             // compression
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
	yes := []struct {
		req    string
		domain string
	}{
		{"GET /generate_204 HTTP/1.1\r\nHost: connectivitycheck.gstatic.com\r\n\r\n", "connectivitycheck.gstatic.com"},
		{"GET /gen_204?foo=1 HTTP/1.1\r\nHost: www.google.com\r\n\r\n", "www.google.com"},
		{"HEAD /generate_204 HTTP/1.0\r\n\r\n", ""},
		{"GET /check_network_status.txt HTTP/1.1\r\n\r\n", ""},
		{"GET /ncsi.txt HTTP/1.1\r\n\r\n", ""},
		{"GET /anything HTTP/1.1\r\n\r\n", "connect.rom.miui.com"},
		{"GET /anything HTTP/1.1\r\n\r\n", "connectivitycheck.android.com"},
	}
	for _, tc := range yes {
		if !captiveProbe([]byte(tc.req), tc.domain) {
			t.Fatalf("want probe: req=%q domain=%q", tc.req, tc.domain)
		}
	}
	no := []struct {
		req    string
		domain string
	}{
		{"GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n", "www.google.com"},
		{"GET /generate_2040 HTTP/1.1\r\n\r\n", "example.com"},
		{"", ""},
	}
	for _, tc := range no {
		if captiveProbe([]byte(tc.req), tc.domain) {
			t.Fatalf("not a probe: req=%q domain=%q", tc.req, tc.domain)
		}
	}
}

func TestSocks5AuthServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	expectedUser := "testuser"
	expectedPass := "testpass"

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()

		// Read greeting
		buf := make([]byte, 256)
		n, err := c.Read(buf)
		if err != nil || n < 3 || buf[0] != 0x05 {
			return
		}
		// Expect user/pass method
		c.Write([]byte{0x05, 0x02})

		// Read auth
		n, err = c.Read(buf)
		if err != nil || n < 5 || buf[0] != 0x01 {
			return
		}
		ulen := int(buf[1])
		u := string(buf[2 : 2+ulen])
		plen := int(buf[2+ulen])
		p := string(buf[3+ulen : 3+ulen+plen])

		if u == expectedUser && p == expectedPass {
			c.Write([]byte{0x01, 0x00}) // auth success
		} else {
			c.Write([]byte{0x01, 0x01}) // auth failure
			return
		}

		// Read connect request
		n, err = c.Read(buf)
		if err != nil || n < 4 || buf[1] != 0x01 {
			return
		}
		// Reply success: BND.ADDR 0.0.0.0:0
		c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}()

	conn, err := socksConnect(ln.Addr().String(), "example.com", nil, 80, expectedUser, expectedPass)
	if err != nil {
		t.Fatalf("socksConnect with user/pass failed: %v", err)
	}
	conn.Close()
}
