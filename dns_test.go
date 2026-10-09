package main

import (
	"context"
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
