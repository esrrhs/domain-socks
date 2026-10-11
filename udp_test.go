package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	ghdns "github.com/esrrhs/gohome/dns"
)

func TestPackUnpackSocks5UDP(t *testing.T) {
	cases := []struct {
		name       string
		host       string
		port       int
		wantAtyp   byte
		wantHost   string
		packErr    bool
		unpackErr  bool
		fragHeader []byte // 手工构造非法/特殊头
	}{
		{"ipv4", "1.2.3.4", 443, socks5AtypIPv4, "1.2.3.4", false, false, nil},
		{"ipv4 mapped ipv6", "::ffff:5.6.7.8", 5353, socks5AtypIPv4, "5.6.7.8", false, false, nil},
		{"ipv6", "2001:db8::1", 12345, socks5AtypIPv6, "2001:db8::1", false, false, nil},
		{"domain", "www.example.com", 9999, socks5AtypDomain, "www.example.com", false, false, nil},
		{"bad port zero", "1.1.1.1", 0, 0, "", true, false, nil},
		{"bad port too big", "1.1.1.1", 70000, 0, "", true, false, nil},
		{"frag rejected", "", 0, 0, "", false, true, []byte{0, 0, 1, 1, 8, 8, 8, 8, 0x1f, 0x90}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.fragHeader != nil {
				if _, _, _, err := unpackSocks5UDP(tc.fragHeader); err == nil {
					t.Fatal("want unpack error for fragmented packet")
				}
				return
			}
			pkt, err := packSocks5UDP(tc.host, tc.port, []byte("DATA"))
			if tc.packErr {
				if err == nil {
					t.Fatal("want pack error")
				}
				return
			}
			if err != nil {
				t.Fatalf("pack: %v", err)
			}
			if pkt[3] != tc.wantAtyp {
				t.Fatalf("atyp=%d want %d", pkt[3], tc.wantAtyp)
			}
			host, port, data, err := unpackSocks5UDP(pkt)
			if tc.unpackErr {
				if err == nil {
					t.Fatal("want unpack error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unpack: %v", err)
			}
			if host != tc.wantHost || port != tc.port || string(data) != "DATA" {
				t.Fatalf("got %s:%d data=%q", host, port, data)
			}
		})
	}

	// 截断报文必须报错而非越界
	for _, n := range []int{0, 1, 3, 4, 9} {
		if _, _, _, err := unpackSocks5UDP(make([]byte, n)); err == nil {
			t.Fatalf("truncated packet len=%d must error", n)
		}
	}
}

// mockSocks5UDP 启动一个最小可用的支持 UDP ASSOCIATE 的 SOCKS5 服务端：
// TCP 控制连接完成握手后回 relay 端点；UDP relay 收到报文解封装后原样回显。
type mockSocks5UDP struct {
	t testing.TB

	tcpLn net.Listener
	relay *net.UDPConn

	// handshakeDelay 在应答前 sleep，用于放大并发首包的竞争窗口
	handshakeDelay time.Duration

	mu           sync.Mutex
	controls     []net.Conn
	controlCount int
	lastHost     string
	lastAtyp     byte
}

func startMockSocks5UDP(t testing.TB) *mockSocks5UDP {
	t.Helper()
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	m := &mockSocks5UDP{t: t, tcpLn: tcpLn, relay: relay}

	go func() {
		for {
			c, err := tcpLn.Accept()
			if err != nil {
				return
			}
			go m.serveControl(c)
		}
	}()
	go m.serveRelay()
	return m
}

func (m *mockSocks5UDP) addr() string { return m.tcpLn.Addr().String() }

func (m *mockSocks5UDP) serveControl(c net.Conn) {
	buf := make([]byte, 256)
	n, err := c.Read(buf) // greeting
	if err != nil || n < 3 || buf[0] != 0x05 {
		c.Close()
		return
	}
	if m.handshakeDelay > 0 {
		time.Sleep(m.handshakeDelay)
	}
	if _, err = c.Write([]byte{0x05, 0x00}); err != nil {
		c.Close()
		return
	}
	// UDP ASSOCIATE 请求固定 10 字节（ATYP=1, 0.0.0.0:0）
	req := make([]byte, 10)
	if _, err = io.ReadFull(c, req); err != nil {
		c.Close()
		return
	}
	if req[1] != socksCmdUDPAssociate {
		c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		c.Close()
		return
	}
	raddr := m.relay.LocalAddr().(*net.UDPAddr)
	reply := []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1,
		byte(raddr.Port >> 8), byte(raddr.Port)}
	if _, err = c.Write(reply); err != nil {
		c.Close()
		return
	}
	m.mu.Lock()
	m.controls = append(m.controls, c)
	m.controlCount++
	m.mu.Unlock()
	// 阻塞直到客户端关闭控制连接
	io.Copy(io.Discard, c)
}

func (m *mockSocks5UDP) serveRelay() {
	buf := make([]byte, udpMaxPacket)
	for {
		n, src, err := m.relay.ReadFromUDP(buf)
		if err != nil {
			return
		}
		host, port, data, err := unpackSocks5UDP(buf[:n])
		if err != nil {
			continue
		}
		m.mu.Lock()
		m.lastHost = host
		m.lastAtyp = buf[3]
		m.mu.Unlock()
		echo, err := packSocks5UDP(host, port, data)
		if err != nil {
			continue
		}
		_, _ = m.relay.WriteToUDP(echo, src)
	}
}

func (m *mockSocks5UDP) closeControlsFrom(idx int) {
	m.mu.Lock()
	conns := append([]net.Conn(nil), m.controls[idx:]...)
	m.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

func (m *mockSocks5UDP) stop() {
	_ = m.tcpLn.Close()
	_ = m.relay.Close()
	m.closeControlsFrom(0)
}

func waitUDPReply(t *testing.T, ch <-chan []byte, want string) {
	t.Helper()
	select {
	case got := <-ch:
		if string(got) != want {
			t.Fatalf("reply=%q want %q", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting reply %q", want)
	}
}

// TestUDPGatewayProxy 走通 Fake-IP 域名 -> UDP ASSOCIATE -> relay 回显
// 全链路，并验证：ATYP=0x03 域名请求、多条流向复用一条 association。
func TestUDPGatewayProxy(t *testing.T) {
	mock := startMockSocks5UDP(t)
	defer mock.stop()

	cfg := ghdns.DefaultConfig()
	cfg.EnableFakeIP = true
	resolver, err := ghdns.NewResolver(cfg)
	if err != nil {
		t.Fatal(err)
	}

	gw := newUDPGateway(resolver, mock.addr(), "", "")
	defer gw.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ip1, err := resolver.ResolveOne(ctx, "www.google.com")
	if err != nil {
		t.Fatal(err)
	}
	ip2, err := resolver.ResolveOne(ctx, "www.youtube.com")
	if err != nil {
		t.Fatal(err)
	}

	replies := make(chan []byte, 8)
	reply := func(b []byte) error { replies <- b; return nil }
	release := func() {}

	gw.handle([]byte("PING1"), "lan-client-1", ip1, 9999, reply, release)
	waitUDPReply(t, replies, "PING1")

	gw.handle([]byte("PING2"), "lan-client-2", ip2, 12345, reply, release)
	waitUDPReply(t, replies, "PING2")

	mock.mu.Lock()
	count := mock.controlCount
	atyp := mock.lastAtyp
	host := mock.lastHost
	mock.mu.Unlock()
	if count != 1 {
		t.Fatalf("expected one shared UDP association, got %d", count)
	}
	if atyp != socks5AtypDomain {
		t.Fatalf("expected ATYP domain, got %d", atyp)
	}
	if host != "www.youtube.com" {
		t.Fatalf("relay saw host %q", host)
	}
}

// TestUDPGatewayDirect 验证非代理目标走本地直连 socket，回包经 NAT 映射
// 送回对应客户端。
func TestUDPGatewayDirect(t *testing.T) {
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, src, err := echo.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = echo.WriteToUDP(bytes.Clone(buf[:n]), src)
		}
	}()

	cfg := ghdns.DefaultConfig()
	cfg.EnableFakeIP = true
	resolver, _ := ghdns.NewResolver(cfg)
	gw := newUDPGateway(resolver, "127.0.0.1:1", "", "")
	defer gw.Close()

	replies := make(chan []byte, 4)
	echoAddr := echo.LocalAddr().(*net.UDPAddr)
	gw.handle([]byte("HELLO"), "lan-direct",
		net.IPv4(127, 0, 0, 1), echoAddr.Port,
		func(b []byte) error { replies <- b; return nil }, func() {})
	waitUDPReply(t, replies, "HELLO")
}

// TestUDPGatewayDirectIPv6 验证真实 IPv6 目标走 udp6 直连 socket（TPROXY v6 数据面）。
// 无 IPv6 loopback 的环境（CI 容器）跳过而非失败。
func TestUDPGatewayDirectIPv6(t *testing.T) {
	echo, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, src, err := echo.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = echo.WriteToUDP(bytes.Clone(buf[:n]), src)
		}
	}()

	cfg := ghdns.DefaultConfig()
	cfg.EnableFakeIP = true
	resolver, _ := ghdns.NewResolver(cfg)
	gw := newUDPGateway(resolver, "127.0.0.1:1", "", "")
	defer gw.Close()

	replies := make(chan []byte, 4)
	echoAddr := echo.LocalAddr().(*net.UDPAddr)
	gw.handle([]byte("V6HELLO"), "lan-v6",
		net.IPv6loopback, echoAddr.Port,
		func(b []byte) error { replies <- b; return nil }, func() {})
	waitUDPReply(t, replies, "V6HELLO")
}

// TestUDPGatewayMultiTargetReply 回归测试：同一客户端（同 clientKey）并发
// 访问两个不同目标时，回包必须各走各 flow 的 reply 闭包——TPROXY 模式下
// 闭包绑定具体目标的透明发送 socket，存成 per-client 会导致第二目标的
// 回包从第一目标的源地址发出（客户端丢弃）。
func TestUDPGatewayMultiTargetReply(t *testing.T) {
	mock := startMockSocks5UDP(t)
	defer mock.stop()

	cfg := ghdns.DefaultConfig()
	cfg.EnableFakeIP = true
	resolver, _ := ghdns.NewResolver(cfg)
	gw := newUDPGateway(resolver, mock.addr(), "", "")
	defer gw.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ip1, err := resolver.ResolveOne(ctx, "www.google.com")
	if err != nil {
		t.Fatal(err)
	}
	ip2, err := resolver.ResolveOne(ctx, "www.youtube.com")
	if err != nil {
		t.Fatal(err)
	}

	sink1 := make(chan []byte, 4)
	sink2 := make(chan []byte, 4)
	const sameClient = "same-lan-client"

	gw.handle([]byte("TO1"), sameClient, ip1, 1111,
		func(b []byte) error { sink1 <- b; return nil }, func() {})
	waitUDPReply(t, sink1, "TO1")

	gw.handle([]byte("TO2"), sameClient, ip2, 2222,
		func(b []byte) error { sink2 <- b; return nil }, func() {})
	// 旧实现下 reply 是 per-client 首次闭包：TO2 的回包会进 sink1，
	// 这里永远等不到 -> 超时失败
	waitUDPReply(t, sink2, "TO2")

	select {
	case b := <-sink1:
		t.Fatalf("reply cross-talk: sink1 received %q (must only carry TO1)", b)
	default:
	}

	mock.mu.Lock()
	count := mock.controlCount
	mock.mu.Unlock()
	if count != 1 {
		t.Fatalf("expected shared single association, got %d", count)
	}
}

// TestAssocConcurrentFirstSend 验证并发首包只触发一次 ASSOCIATE 握手，
// 其余 goroutine 等待并复用结果（singleflight）。
func TestAssocConcurrentFirstSend(t *testing.T) {
	mock := startMockSocks5UDP(t)
	defer mock.stop()
	mock.handshakeDelay = 50 * time.Millisecond

	cfg := ghdns.DefaultConfig()
	cfg.EnableFakeIP = true
	resolver, _ := ghdns.NewResolver(cfg)
	gw := newUDPGateway(resolver, mock.addr(), "", "")
	defer gw.Close()

	const n = 20
	var wg sync.WaitGroup
	errs := make([]error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = gw.proxy.ensureAssoc()
		}(i)
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}

	mock.mu.Lock()
	count := mock.controlCount
	mock.mu.Unlock()
	if count != 1 {
		t.Fatalf("expected exactly one association handshake, got %d", count)
	}
}

// TestAssocCooldown 验证建连失败后的冷却语义：
// 首次失败后，冷却期内并发请求全部快速返回缓存错误、不触发新拨号；
// 冷却清除后立即重试并成功。
func TestAssocCooldown(t *testing.T) {
	mock := startMockSocks5UDP(t)
	dead := mock.addr()
	mock.stop() // 端口关闭 -> dial 立即 refused

	cfg := ghdns.DefaultConfig()
	cfg.EnableFakeIP = true
	resolver, _ := ghdns.NewResolver(cfg)
	gw := newUDPGateway(resolver, dead, "", "")
	defer gw.Close()
	r := gw.proxy

	if err := r.ensureAssoc(); err == nil {
		t.Fatal("first attempt must fail against a dead proxy")
	}

	// 冷却期内 10 个并发请求：全部快速失败，且不得产生新的 TCP 尝试
	const n = 10
	var wg sync.WaitGroup
	errs := make([]error, n)
	start := make(chan struct{})
	begin := time.Now()
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = r.ensureAssoc()
		}(i)
	}
	close(start)
	wg.Wait()
	if elapsed := time.Since(begin); elapsed > 200*time.Millisecond {
		t.Fatalf("cooldown failures must be immediate, took %v", elapsed)
	}
	for i, err := range errs {
		if err == nil {
			t.Fatalf("goroutine %d unexpectedly succeeded in cooldown", i)
		}
	}

	// 代理恢复 + 冷却结束：下一次请求正常建连
	alive := startMockSocks5UDP(t)
	defer alive.stop()
	r.proxyAddr = alive.addr()
	r.mu.Lock()
	r.cooldownUntil = time.Time{}
	r.mu.Unlock()
	if err := r.ensureAssoc(); err != nil {
		t.Fatalf("retry after cooldown: %v", err)
	}
	alive.mu.Lock()
	count := alive.controlCount
	alive.mu.Unlock()
	if count != 1 {
		t.Fatalf("expected one control connection after recovery, got %d", count)
	}
}

// TestUDPAssocReconnect 验证控制连接断开后，下一次发送自动重建 association，
// 而不是静默丢包（读循环拆除 -> ensureAssoc 重建）。
func TestUDPAssocReconnect(t *testing.T) {
	mock := startMockSocks5UDP(t)
	defer mock.stop()

	cfg := ghdns.DefaultConfig()
	cfg.EnableFakeIP = true
	resolver, _ := ghdns.NewResolver(cfg)
	gw := newUDPGateway(resolver, mock.addr(), "", "")
	defer gw.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ip, _ := resolver.ResolveOne(ctx, "www.google.com")

	replies := make(chan []byte, 4)
	reply := func(b []byte) error { replies <- b; return nil }

	gw.handle([]byte("FIRST"), "c", ip, 1000, reply, func() {})
	waitUDPReply(t, replies, "FIRST")

	// 服务端强拆控制连接，等待客户端感知并拆除 association
	mock.closeControlsFrom(0)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		gw.proxy.mu.Lock()
		dead := gw.proxy.control == nil
		gw.proxy.mu.Unlock()
		if dead {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	gw.proxy.mu.Lock()
	dead := gw.proxy.control == nil
	gw.proxy.mu.Unlock()
	if !dead {
		t.Fatal("association should be torn down after control close")
	}

	gw.handle([]byte("SECOND"), "c", ip, 1000, reply, func() {})
	waitUDPReply(t, replies, "SECOND")

	mock.mu.Lock()
	count := mock.controlCount
	mock.mu.Unlock()
	if count != 2 {
		t.Fatalf("expected association re-established, count=%d", count)
	}
}

func TestResolveRelayAddr(t *testing.T) {
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpLn.Close()
	go func() {
		c, _ := tcpLn.Accept()
		if c != nil {
			io.Copy(io.Discard, c)
		}
	}()
	c, err := net.Dial("tcp", tcpLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// 服务器回 0.0.0.0:0 时，补全为控制连接对端 IP:Port
	a, err := resolveRelayAddr(c, "", net.IPv4zero, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := tcpLn.Addr().(*net.TCPAddr)
	if !a.IP.Equal(want.IP) || a.Port != want.Port {
		t.Fatalf("fallback relay=%s want %s", a, want)
	}

	// 显式地址优先
	a2, err := resolveRelayAddr(c, "", net.IPv4(8, 8, 8, 8), 5555)
	if err != nil || a2.String() != "8.8.8.8:5555" {
		t.Fatalf("explicit relay=%s err=%v", a2, err)
	}
}
