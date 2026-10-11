package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"testing"
	"time"

	ghdns "github.com/esrrhs/gohome/dns"
	"github.com/miekg/dns"
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

// stubExchangeResolver 只实现 DNS 中间件测试关心的方法，
// 其余方法通过内嵌 nil 接口在被误调用时直接 panic，暴露测试问题。
type stubExchangeResolver struct {
	ghdns.Resolver
	proxyDomains map[string]bool
	upstreamHits int
	// isFake 非 nil 时为 A 查询返回 Fake-IP 段应答
	isFake func(net.IP) bool
	// fail 非 nil 时 Exchange 直接返回该错误
	fail error
	// delay 非零时 Exchange 先 sleep，用于模拟上游延迟
	delay time.Duration
}

func (s *stubExchangeResolver) ShouldProxy(target string) (bool, error) {
	return s.proxyDomains[target], nil
}

func (s *stubExchangeResolver) IsFakeIP(ip net.IP) bool {
	return s.isFake != nil && s.isFake(ip)
}

func (s *stubExchangeResolver) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	s.upstreamHits++
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if s.fail != nil {
		return nil, s.fail
	}
	resp := new(dns.Msg)
	resp.SetReply(req)
	if len(req.Question) == 0 {
		return resp, nil
	}
	q := req.Question[0]
	switch q.Qtype {
	case dns.TypeAAAA:
		resp.Answer = append(resp.Answer, &dns.AAAA{
			Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
			AAAA: net.ParseIP("2001:db8::1"),
		})
	case dns.TypeA:
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.IPv4(198, 18, 0, 5),
		})
	}
	return resp, nil
}

func TestAAAAFilter(t *testing.T) {
	stub := &stubExchangeResolver{proxyDomains: map[string]bool{"www.google.com": true}}
	f := &aaaaFilter{Resolver: stub, enabled: true}

	// 代理域名 AAAA：返回空 NOERROR，且不得透传到上游（防 IPv6 泄漏）
	req := new(dns.Msg)
	req.SetQuestion("www.google.com.", dns.TypeAAAA)
	resp, err := f.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 {
		t.Fatalf("expected empty NOERROR for proxy AAAA, rcode=%d answers=%d", resp.Rcode, len(resp.Answer))
	}
	if stub.upstreamHits != 0 {
		t.Fatalf("proxy AAAA must not reach upstream, hits=%d", stub.upstreamHits)
	}

	// 直连域名 AAAA：正常透传，保留双栈
	req2 := new(dns.Msg)
	req2.SetQuestion("www.baidu.com.", dns.TypeAAAA)
	resp2, err := f.Exchange(context.Background(), req2)
	if err != nil {
		t.Fatalf("direct AAAA exchange: %v", err)
	}
	if len(resp2.Answer) != 1 {
		t.Fatalf("direct AAAA should pass through, answers=%d", len(resp2.Answer))
	}

	// A 查询始终透传
	reqA := new(dns.Msg)
	reqA.SetQuestion("www.google.com.", dns.TypeA)
	if _, err := f.Exchange(context.Background(), reqA); err != nil {
		t.Fatalf("A exchange: %v", err)
	}
	if stub.upstreamHits != 2 {
		t.Fatalf("A query must pass through, upstream hits=%d", stub.upstreamHits)
	}
}

// TestDNSMetrics 验证 DNS 中间件在各路径上的计数：
// 代理 AAAA 拦截、AAAA 透传、Fake-IP A 应答、上游错误，以及 disabled 开关。
func TestDNSMetrics(t *testing.T) {
	stub := &stubExchangeResolver{
		proxyDomains: map[string]bool{"www.google.com": true},
		isFake: func(ip net.IP) bool {
			v4 := ip.To4()
			return v4 != nil && v4[0] == 198 && (v4[1] == 18 || v4[1] == 19)
		},
	}
	st := newStats()
	f := &aaaaFilter{Resolver: stub, st: st, enabled: true}

	aaaaProxy := new(dns.Msg)
	aaaaProxy.SetQuestion("www.google.com.", dns.TypeAAAA)
	if _, err := f.Exchange(context.Background(), aaaaProxy); err != nil {
		t.Fatal(err)
	}
	aaaaDirect := new(dns.Msg)
	aaaaDirect.SetQuestion("www.baidu.com.", dns.TypeAAAA)
	if _, err := f.Exchange(context.Background(), aaaaDirect); err != nil {
		t.Fatal(err)
	}
	aReq := new(dns.Msg)
	aReq.SetQuestion("www.google.com.", dns.TypeA)
	if _, err := f.Exchange(context.Background(), aReq); err != nil {
		t.Fatal(err)
	}

	snap := st.snapshot().Counters
	if snap[statDNSQueries] != 3 {
		t.Fatalf("dns_queries=%d want 3", snap[statDNSQueries])
	}
	if snap[statDNSAAAA] != 2 {
		t.Fatalf("dns_queries_aaaa=%d want 2", snap[statDNSAAAA])
	}
	if snap[statDNSAAAAFiltered] != 1 {
		t.Fatalf("dns_aaaa_filtered=%d want 1", snap[statDNSAAAAFiltered])
	}
	if snap[statDNSFakeIP] != 1 {
		t.Fatalf("dns_fakeip_answers=%d want 1", snap[statDNSFakeIP])
	}
	if snap[statDNSErrors] != 0 {
		t.Fatalf("dns_errors=%d want 0", snap[statDNSErrors])
	}

	// 上游错误必须计数且错误透传
	stub.fail = fmt.Errorf("upstream boom")
	if _, err := f.Exchange(context.Background(), aReq); err == nil {
		t.Fatal("expected upstream error to propagate")
	}
	if got := st.snapshot().Counters[statDNSErrors]; got != 1 {
		t.Fatalf("dns_errors=%d want 1", got)
	}
	stub.fail = nil

	// enabled=false：代理域名 AAAA 也透传，filtered 不再增长
	f.enabled = false
	if _, err := f.Exchange(context.Background(), aaaaProxy); err != nil {
		t.Fatal(err)
	}
	if got := st.snapshot().Counters[statDNSAAAAFiltered]; got != 1 {
		t.Fatalf("filtered must stay 1 when disabled, got %d", got)
	}
	if stub.upstreamHits != 4 { // aaaaDirect + aReq + failed aReq + disabled aaaaProxy
		t.Fatalf("upstreamHits=%d want 4", stub.upstreamHits)
	}
	// 恰好 4 次真实上游往返进延迟直方图（含 1 次失败），
	// 被本地短路的代理 AAAA 不计入。
	if h := st.snapshot().Histograms[histDNSUpstreamSeconds]; h.Count != 4 || h.SumSeconds <= 0 {
		t.Fatalf("dns upstream histogram=%+v want count=4 sum>0", h)
	}
}

// TestDNSUpstreamLatencyHistogram 验证延迟直方图的短路排除、
// 延迟桶归属与失败观测。
func TestDNSUpstreamLatencyHistogram(t *testing.T) {
	stub := &stubExchangeResolver{
		proxyDomains: map[string]bool{"www.google.com": true},
		delay:        5 * time.Millisecond,
	}
	st := newStats()
	f := &aaaaFilter{Resolver: stub, st: st, enabled: true}

	// 代理 AAAA：本地短路，零上游观测
	aaaaProxy := new(dns.Msg)
	aaaaProxy.SetQuestion("www.google.com.", dns.TypeAAAA)
	if _, err := f.Exchange(context.Background(), aaaaProxy); err != nil {
		t.Fatal(err)
	}
	if h := st.snapshot().Histograms[histDNSUpstreamSeconds]; h.Count != 0 {
		t.Fatalf("short-circuit AAAA must not hit histogram, count=%d", h.Count)
	}

	// A 查询：5ms 延迟必须落在 >=5ms 的累计桶且 sum>=5ms
	aReq := new(dns.Msg)
	aReq.SetQuestion("www.google.com.", dns.TypeA)
	if _, err := f.Exchange(context.Background(), aReq); err != nil {
		t.Fatal(err)
	}
	h := st.snapshot().Histograms[histDNSUpstreamSeconds]
	if h.Count != 1 || h.SumSeconds < 0.005 {
		t.Fatalf("after delayed A query histogram=%+v want count=1 sum>=0.005", h)
	}
	// 不假设调度器把 5ms sleep 唤醒到哪个具体桶（常为 5~10ms），
	// 只校验：2ms 桶必不含（sleep 不会提前）、尾桶必含，且某个桶
	// 从 0 跳变到 1（单调累计）。
	idx002 := sort.SearchFloat64s(dnsBuckets, 0.002)
	if h.CumulativeCounts[idx002] != 0 {
		t.Fatalf("5ms sleep must not land in le=0.002, cum=%v", h.CumulativeCounts)
	}
	if h.CumulativeCounts[len(h.CumulativeCounts)-1] != 1 {
		t.Fatalf("+Inf cumulative=%d want 1", h.CumulativeCounts[len(h.CumulativeCounts)-1])
	}
	var sawOne bool
	for _, v := range h.CumulativeCounts {
		if v == 1 {
			sawOne = true
		}
		if v < 0 || v > 1 {
			t.Fatalf("cumulative counts must be 0/1 monotonic: %v", h.CumulativeCounts)
		}
	}
	if !sawOne {
		t.Fatalf("sample missing from all buckets: %v", h.CumulativeCounts)
	}

	// 失败的上游调用同样观测（慢失败也是信号）
	stub.delay = 0
	stub.fail = fmt.Errorf("dns timeout")
	if _, err := f.Exchange(context.Background(), aReq); err == nil {
		t.Fatal("expected error propagation")
	}
	if h := st.snapshot().Histograms[histDNSUpstreamSeconds]; h.Count != 2 {
		t.Fatalf("failed upstream call must be observed, count=%d want 2", h.Count)
	}
}

// TestTCPActiveGauge 验证活跃连接 gauge 的开/闭配对
func TestTCPActiveGauge(t *testing.T) {
	st := newStats()
	if got := st.snapshot().Gauges["tcp_active"]; got != 0 {
		t.Fatalf("initial tcp_active=%d want 0", got)
	}
	st.tcpConnOpened()
	st.tcpConnOpened()
	if got := st.snapshot().Gauges["tcp_active"]; got != 2 {
		t.Fatalf("tcp_active=%d want 2", got)
	}
	st.tcpConnClosed()
	if got := st.snapshot().Gauges["tcp_active"]; got != 1 {
		t.Fatalf("tcp_active=%d want 1", got)
	}
}

// TestPeekHostFragmentedTLS 验证 ClientHello 被 TCP 拆成多个段到达时，
// peekHost 仍能还原完整 SNI，且返回的 prefix 不丢字节（后续要原样转发）。
func TestPeekHostFragmentedTLS(t *testing.T) {
	pkt := craftClientHello("www.youtube.com")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		s, err := ln.Accept()
		if err != nil {
			return
		}
		defer s.Close()
		// 先只发 TLS record 头的前 3 字节，再发剩余部分
		_, _ = s.Write(pkt[:3])
		time.Sleep(30 * time.Millisecond)
		_, _ = s.Write(pkt[3:])
		time.Sleep(200 * time.Millisecond)
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	prefix, host := peekHost(c)
	if host != "www.youtube.com" {
		t.Fatalf("expected sni www.youtube.com, got %q", host)
	}
	if !bytes.Equal(prefix, pkt) {
		t.Fatalf("prefix mismatch: got %d bytes, want %d bytes", len(prefix), len(pkt))
	}
}

// TestPeekHostNonHTTPFastReturn 验证非 HTTP(S) 协议（如 SSH 服务器 banner）
// 不会被 250ms 嗅探超时拖慢：首包到达即判定并返回。
func TestPeekHostNonHTTPFastReturn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		s, err := ln.Accept()
		if err != nil {
			return
		}
		defer s.Close()
		_, _ = s.Write([]byte("SSH-2.0-OpenSSH_9.7\r\n"))
		time.Sleep(300 * time.Millisecond)
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	start := time.Now()
	prefix, host := peekHost(c)
	elapsed := time.Since(start)
	if host != "" {
		t.Fatalf("ssh banner must not yield a host, got %q", host)
	}
	if len(prefix) == 0 {
		t.Fatal("prefix should carry the already-read banner bytes")
	}
	if elapsed > 100*time.Millisecond {
		t.Fatalf("non-HTTP protocol should bail out immediately, took %v", elapsed)
	}
}

// TestPeekHostFragmentedHTTP 验证 HTTP 请求头跨段时仍能嗅探 Host。
func TestPeekHostFragmentedHTTP(t *testing.T) {
	full := []byte("GET /index.html HTTP/1.1\r\nHost: www.example.cn\r\nAccept: */*\r\n\r\n")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		s, err := ln.Accept()
		if err != nil {
			return
		}
		defer s.Close()
		_, _ = s.Write(full[:7])
		time.Sleep(30 * time.Millisecond)
		_, _ = s.Write(full[7:])
		time.Sleep(200 * time.Millisecond)
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	prefix, host := peekHost(c)
	if host != "www.example.cn" {
		t.Fatalf("expected www.example.cn, got %q", host)
	}
	if !bytes.Equal(prefix, full) {
		t.Fatalf("prefix lost bytes: got %d want %d", len(prefix), len(full))
	}
}

func TestSniffConclusive(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
		want bool
	}{
		{"empty", nil, false},
		{"tls first byte only", []byte{0x16}, false},
		{"tls second byte not ssl3", []byte{0x16, 0x01, 0x00}, true},
		{"tls header partial", []byte{0x16, 0x03, 0x01, 0x00}, false},
		{"http method prefix", []byte("GE"), false},
		{"http garbage prefix", []byte("XYZ"), true},
		{"http headers complete", []byte("GET / HTTP/1.1\r\nHost: a.com\r\n\r\n"), true},
		{"http headers partial", []byte("GET / HTTP/1.1\r\nHost: a.com\r\n"), false},
	}
	for _, tc := range cases {
		if got := sniffConclusive(tc.b); got != tc.want {
			t.Errorf("%s: sniffConclusive=%v want %v", tc.name, got, tc.want)
		}
	}

	// 完整 TLS record（无 SNI 也应下结论），截断的 record 必须继续等待
	pkt := craftClientHello("x.test")
	if !sniffConclusive(pkt) {
		t.Error("complete client hello should be conclusive")
	}
	recLen := int(pkt[3])<<8 | int(pkt[4])
	if sniffConclusive(pkt[:4+recLen]) {
		t.Error("truncated client hello should wait for more bytes")
	}
}

func TestDNSListenCandidates(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"[::]:1053", []string{"[::]:1053", "0.0.0.0:1053"}},
		{":1053", []string{"[::]:1053", "0.0.0.0:1053"}},
		{"0.0.0.0:1053", []string{"[::]:1053", "0.0.0.0:1053"}},
		{"127.0.0.1:1053", []string{"127.0.0.1:1053"}},
		{"192.168.1.1:53", []string{"192.168.1.1:53"}},
		{"[::1]:1053", []string{"[::1]:1053"}},
		{"garbage", []string{"garbage"}},
	}
	for _, tc := range cases {
		got := dnsListenCandidates(tc.in)
		if len(got) != len(tc.want) {
			t.Errorf("dnsListenCandidates(%q) = %v, want %v", tc.in, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("dnsListenCandidates(%q) = %v, want %v", tc.in, got, tc.want)
				break
			}
		}
	}
}

// ipv6LoopbackAvailable 判断本机是否真的能在 ::1 上收包
// （部分精简容器只有 v4 loopback）。
func ipv6LoopbackAvailable() bool {
	c, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func dnsQueryLoopback(t *testing.T, addr string) {
	t.Helper()
	c := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion("example.org.", dns.TypeA)
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("dns query via %s: %v", addr, err)
	}
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("dns query via %s: bad response %v", addr, resp)
	}
}

// freeDualStackPort 预占一个 [::] 空闲端口并立即释放：
// ghdns.Server 不暴露实际绑定地址，无法从 :0 反查分配到的端口。
func freeDualStackPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp", "[::]:0")
	if err != nil {
		t.Fatalf("probe free dual-stack port: %v", err)
	}
	port := c.LocalAddr().(*net.UDPAddr).Port
	_ = c.Close()
	return port
}

// TestStartDNSDualStack 验证默认的 [::]:port 单 socket 在双栈内核上同时
// 接收 v4(127.0.0.1) 与 v6(::1) 查询——这是两族 nat REDIRECT 能
// 共用一个 DNS 端口的前提。无 v6 loopback 的环境只断言 v4。
func TestStartDNSDualStack(t *testing.T) {
	port := freeDualStackPort(t)
	stub := &stubExchangeResolver{}
	srv, _, err := startDNS(stub, fmt.Sprintf("[::]:%d", port))
	if err != nil {
		t.Fatalf("startDNS dual-stack: %v", err)
	}
	defer srv.Stop()

	dnsQueryLoopback(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if ipv6LoopbackAvailable() {
		dnsQueryLoopback(t, net.JoinHostPort("::1", strconv.Itoa(port)))
	} else {
		t.Log("IPv6 loopback unavailable, skip ::1 query")
	}
}
