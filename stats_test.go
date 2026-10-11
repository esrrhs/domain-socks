package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	ghdns "github.com/esrrhs/gohome/dns"
)

func TestStatsNilSafe(t *testing.T) {
	var s *stats
	// 未绑定 stats 的数据面路径（历史构造、个别测试）不得 panic
	s.inc(statTCPAccepted)
	s.add(statTCPProxyBytesUp, 9999)
	s.registerGauges(map[string]func() int64{"x": func() int64 { return 1 }})
}

func TestStatsAddBatch(t *testing.T) {
	s := newStats()
	s.add(statUDPBytesIn, 0) // 零增量不影响
	s.add(statUDPBytesIn, 100)
	s.add(statUDPBytesIn, 23)
	if got := s.snapshot().Counters[statUDPBytesIn]; got != 123 {
		t.Fatalf("udp bytes in=%d want 123", got)
	}
}

func TestHumanBytes(t *testing.T) {
	cases := []struct {
		n    int64
		want string
	}{
		{0, "0B"}, {1023, "1023B"}, {1024, "1.0KiB"},
		{1536, "1.5KiB"}, {1 << 20, "1.00MiB"}, {1 << 30, "1.00GiB"},
	}
	for _, tc := range cases {
		if got := humanBytes(tc.n); got != tc.want {
			t.Errorf("humanBytes(%d)=%q want %q", tc.n, got, tc.want)
		}
	}
}

func TestFormatConnLine(t *testing.T) {
	line := formatConnLine("192.168.1.5:54321", "www.google.com:443", "socks",
		2048, 5*1024*1024, 2350*time.Millisecond, nil)
	for _, want := range []string{"192.168.1.5:54321", "www.google.com:443", "via socks",
		"up 2.0KiB", "down 5.00MiB", "in 2.35s"} {
		if !strings.Contains(line, want) {
			t.Fatalf("line %q missing %q", line, want)
		}
	}
	failLine := formatConnLine("1.2.3.4:1", "dead.host:443", "socks", 0, 0, time.Millisecond,
		errors.New("dial tcp: i/o timeout"))
	if !strings.Contains(failLine, "fail: dial tcp: i/o timeout") {
		t.Fatalf("fail line missing error: %q", failLine)
	}
}

// bufConn 是只实现 Write 的最小 net.Conn（其余方法经内嵌 nil 接口，
// 本测试不会调用）
type bufConn struct {
	net.Conn
	buf bytes.Buffer
}

func (b *bufConn) Write(p []byte) (int, error) { return b.buf.Write(p) }

func TestCountingConn(t *testing.T) {
	var n int64
	raw := &bufConn{}
	c := countingConn{Conn: raw, n: &n}

	if k, err := c.Write([]byte("ping")); err != nil || k != 4 {
		t.Fatalf("first write: k=%d err=%v", k, err)
	}
	if k, err := c.Write([]byte("pong")); err != nil || k != 4 {
		t.Fatalf("second write: k=%d err=%v", k, err)
	}
	if n != 8 || raw.buf.String() != "pingpong" {
		t.Fatalf("counted=%d underlying=%q", n, raw.buf.String())
	}
}

func TestStatsCountersAndGauges(t *testing.T) {
	s := newStats()
	s.inc(statTCPAccepted)
	s.inc(statTCPAccepted)
	s.inc(statAssocCool)

	var gaugeVal int64 = 7
	s.registerGauges(map[string]func() int64{
		"gauge_x": func() int64 { return gaugeVal },
	})

	snap := s.snapshot()
	if snap.Counters[statTCPAccepted] != 2 {
		t.Fatalf("tcp_accepted=%d want 2", snap.Counters[statTCPAccepted])
	}
	if snap.Counters[statAssocCool] != 1 {
		t.Fatalf("cooldown=%d want 1", snap.Counters[statAssocCool])
	}
	if snap.Counters[statUDPIn] != 0 {
		t.Fatalf("unseen counter should start at 0, got %d", snap.Counters[statUDPIn])
	}
	if snap.Gauges["gauge_x"] != 7 {
		t.Fatalf("gauge_x=%d want 7", snap.Gauges["gauge_x"])
	}
	if snap.Goroutines < 1 || snap.UptimeSeconds < 0 {
		t.Fatalf("runtime fields bogus: %+v", snap)
	}

	text := s.renderText()
	if !strings.Contains(text, "domain-socks stats") ||
		!strings.Contains(text, "tcp_accepted") ||
		!strings.Contains(text, "gauges:") {
		t.Fatalf("text snapshot missing sections:\n%s", text)
	}
}

func TestStatsHTTPEndpoints(t *testing.T) {
	s := newStats()
	s.inc(statUDPIn)
	srv := startStatsServer("127.0.0.1:0", s, func() error { return nil })
	if srv == nil {
		t.Fatal("stats server failed to start on ephemeral port")
	}
	defer srv.Close()
	base := "http://" + srv.Addr

	// /healthz：永远 200（liveness 不依赖外部组件）
	respHZ, err := http.Get(base + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	hb, _ := io.ReadAll(respHZ.Body)
	_ = respHZ.Body.Close()
	if respHZ.StatusCode != 200 || strings.TrimSpace(string(hb)) != "ok" {
		t.Fatalf("healthz: status=%d body=%q", respHZ.StatusCode, hb)
	}

	// /readyz：探针返回 nil 时 200 ready
	respRZ, err := http.Get(base + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	rb, _ := io.ReadAll(respRZ.Body)
	_ = respRZ.Body.Close()
	if respRZ.StatusCode != 200 || strings.TrimSpace(string(rb)) != "ready" {
		t.Fatalf("readyz: status=%d body=%q", respRZ.StatusCode, rb)
	}

	// 无探针的实例不注册 /readyz（命中 / → 文本快照，404 由独立实例验证）
	noProbe := startStatsServer("127.0.0.1:0", newStats(), nil)
	if noProbe == nil {
		t.Fatal("setup: noProbe server failed")
	}
	defer noProbe.Close()
	respNP, err := http.Get("http://" + noProbe.Addr + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	_ = respNP.Body.Close()
	if respNP.StatusCode != 503 {
		t.Fatalf("readyz without probe: status=%d want 503", respNP.StatusCode)
	}

	// /json：结构化输出
	resp, err := http.Get(base + "/json")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("json response: status=%d cache=%s", resp.StatusCode, resp.Header.Get("Cache-Control"))
	}
	var snap statsJSON
	if err := json.Unmarshal(body, &snap); err != nil {
		t.Fatalf("decode json: %v\nbody=%s", err, body)
	}
	if snap.Counters[statUDPIn] != 1 {
		t.Fatalf("udp_in over http=%d want 1", snap.Counters[statUDPIn])
	}

	// /：文本快照
	resp2, err := http.Get(base + "/")
	if err != nil {
		t.Fatal(err)
	}
	text, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	if !strings.Contains(string(text), "udp_in") {
		t.Fatalf("text endpoint missing counters:\n%s", text)
	}

	// 禁用与绑定失败都必须返回 nil（不能拖垮数据面）
	if got := startStatsServer("", s, nil); got != nil {
		t.Fatal("empty addr must disable the stats server")
	}
	occupied := startStatsServer("127.0.0.1:0", newStats(), nil)
	if occupied == nil {
		t.Fatal("setup: second ephemeral listener unexpectedly failed")
	}
	defer occupied.Close()
	if got := startStatsServer(occupied.Addr, newStats(), nil); got != nil {
		got.Close()
		t.Fatal("bind conflict must return nil, not a half-started server")
	}
}

// TestStatsGatewayWiring 走通真实 gateway -> mock SOCKS5 UDP ASSOCIATE 链路，
// 验证计数器与 gauge 在数据面各埋点的接线正确。
func TestStatsGatewayWiring(t *testing.T) {
	mock := startMockSocks5UDP(t)
	defer mock.stop()

	cfg := ghdns.DefaultConfig()
	cfg.EnableFakeIP = true
	resolver, err := ghdns.NewResolver(cfg)
	if err != nil {
		t.Fatal(err)
	}

	st := newStats()
	gw := newUDPGateway(resolver, mock.addr(), "", "")
	gw.setStats(st)
	defer gw.Close()
	st.registerGauges(map[string]func() int64{
		"udp_active_clients": func() int64 { n, _ := gw.activeCounts(); return n },
		"udp_active_flows":   func() int64 { _, n := gw.activeCounts(); return n },
		"udp_assoc_up":       gw.proxy.assocIsUp,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ip, err := resolver.ResolveOne(ctx, "www.google.com")
	if err != nil {
		t.Fatal(err)
	}

	replies := make(chan []byte, 4)
	reply := func(b []byte) error { replies <- b; return nil }
	gw.handle([]byte("PING"), "lan-stats-1", ip, 9999, reply, func() {})
	select {
	case got := <-replies:
		if string(got) != "PING" {
			t.Fatalf("reply=%q want PING", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting echo reply")
	}

	snap := st.snapshot()
	if snap.Counters[statUDPIn] < 1 {
		t.Fatalf("udp_in=%d want >=1", snap.Counters[statUDPIn])
	}
	if snap.Counters[statUDPProxyIn] < 1 {
		t.Fatalf("udp_proxy_in=%d want >=1", snap.Counters[statUDPProxyIn])
	}
	if snap.Counters[statAssocUp] != 1 {
		t.Fatalf("assoc_established=%d want 1", snap.Counters[statAssocUp])
	}
	if snap.Counters[statUDPReplies] < 1 {
		t.Fatalf("udp_replies=%d want >=1", snap.Counters[statUDPReplies])
	}
	// "PING" 4 字节入站、4 字节回包
	if snap.Counters[statUDPBytesIn] < 4 {
		t.Fatalf("udp_bytes_in=%d want >=4", snap.Counters[statUDPBytesIn])
	}
	if snap.Counters[statUDPBytesOut] < 4 {
		t.Fatalf("udp_bytes_out=%d want >=4", snap.Counters[statUDPBytesOut])
	}
	if snap.Counters[statUDPFwdFail] != 0 {
		t.Fatalf("unexpected forward failures: %d", snap.Counters[statUDPFwdFail])
	}
	if snap.Gauges["udp_assoc_up"] != 1 {
		t.Fatalf("udp_assoc_up gauge=%d want 1", snap.Gauges["udp_assoc_up"])
	}
	if snap.Gauges["udp_active_clients"] != 1 || snap.Gauges["udp_active_flows"] != 1 {
		t.Fatalf("active gauges: clients=%d flows=%d, want 1/1",
			snap.Gauges["udp_active_clients"], snap.Gauges["udp_active_flows"])
	}

	// 关闭后 association gauge 应归零（close 路径不计 teardown）
	gw.Close()
	if st.snapshot().Gauges["udp_assoc_up"] != 0 {
		t.Fatal("udp_assoc_up gauge must drop to 0 after Close")
	}
	if got := st.snapshot().Counters[statAssocDown]; got != 0 {
		t.Fatalf("shutdown must not count as teardown, got %d", got)
	}
}

// mockSocks5TCP 是最小 SOCKS5 方法协商服务器，只握手不处理 CONNECT，
// 专门用于 /readyz 上游探测测试。
type mockSocks5TCP struct {
	ln       net.Listener
	mu       sync.Mutex
	hits     int
	user     string
	pass     string
	needAuth bool // true：只接受 0x02；false：只接受 0x00
	// hangClose>0 表示接受后立刻关闭连接（模拟协议异常上游），用计数器
	// 而非布尔：只对前 N 个连接生效，避免与 server goroutine 间数据竞争。
	hangClose int32
}

func newMockSocks5TCP(t *testing.T, needAuth bool, user, pass string) *mockSocks5TCP {
	t.Helper()
	return newMockSocks5TCPWithHang(t, needAuth, user, pass, 0)
}

func newMockSocks5TCPWithHang(t *testing.T, needAuth bool, user, pass string, hang int32) *mockSocks5TCP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	m := &mockSocks5TCP{ln: ln, needAuth: needAuth, user: user, pass: pass, hangClose: hang}
	go m.serve()
	return m
}

func (m *mockSocks5TCP) addr() string { return m.ln.Addr().String() }

func (m *mockSocks5TCP) close() { _ = m.ln.Close() }

func (m *mockSocks5TCP) hitCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.hits
}

func (m *mockSocks5TCP) serve() {
	for {
		c, err := m.ln.Accept()
		if err != nil {
			return
		}
		m.mu.Lock()
		m.hits++
		m.mu.Unlock()
		go m.handle(c)
	}
}

func (m *mockSocks5TCP) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	m.mu.Lock()
	hang := m.hangClose > 0
	if hang {
		m.hangClose--
	}
	m.mu.Unlock()
	if hang {
		return
	}
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return
	}
	if hdr[0] != 0x05 {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	if m.needAuth {
		var supports bool
		for _, mm := range methods {
			if mm == 0x02 {
				supports = true
			}
		}
		if !supports {
			_, _ = c.Write([]byte{0x05, 0xFF})
			return
		}
		if _, err := c.Write([]byte{0x05, 0x02}); err != nil {
			return
		}
		// RFC 1929：01 ulen user plen pass
		head := make([]byte, 2)
		if _, err := io.ReadFull(c, head); err != nil || head[0] != 0x01 {
			return
		}
		creds := make([]byte, int(head[1]))
		if _, err := io.ReadFull(c, creds); err != nil {
			return
		}
		pLen := make([]byte, 1)
		if _, err := io.ReadFull(c, pLen); err != nil {
			return
		}
		passwd := make([]byte, int(pLen[0]))
		if _, err := io.ReadFull(c, passwd); err != nil {
			return
		}
		if string(creds) == m.user && string(passwd) == m.pass {
			_, _ = c.Write([]byte{0x01, 0x00})
		} else {
			_, _ = c.Write([]byte{0x01, 0x01})
		}
	} else {
		_, _ = c.Write([]byte{0x05, 0x00})
	}
}

func TestProbeSocksUpstream(t *testing.T) {
	// 免密上游
	anon := newMockSocks5TCP(t, false, "", "")
	defer anon.close()
	if err := probeSocksUpstream(anon.addr(), "", ""); err != nil {
		t.Fatalf("anon probe: %v", err)
	}

	// 认证上游：正确/错误凭据
	auth := newMockSocks5TCP(t, true, "u", "p")
	defer auth.close()
	if err := probeSocksUpstream(auth.addr(), "u", "p"); err != nil {
		t.Fatalf("auth probe with valid creds: %v", err)
	}
	if err := probeSocksUpstream(auth.addr(), "u", "wrong"); err == nil {
		t.Fatal("wrong password must fail negotiation")
	}
	if err := probeSocksUpstream(auth.addr(), "", ""); err == nil {
		t.Fatal("no-auth greeting against auth-required upstream must fail")
	}

	// 协议异常（连接被立刻关闭）必须报错
	broken := newMockSocks5TCPWithHang(t, false, "", "", 1)
	defer broken.close()
	if err := probeSocksUpstream(broken.addr(), "", ""); err == nil {
		t.Fatal("immediate-close upstream must fail probe")
	}

	// 不可达地址必须快速失败（不挂起 /readyz）
	if err := probeSocksUpstream("127.0.0.1:1", "", ""); err == nil {
		t.Fatal("connection refused must fail probe")
	}
}

func TestReadyzThroughHTTP(t *testing.T) {
	auth := newMockSocks5TCP(t, true, "router", "secret")
	defer auth.close()

	calls := 0
	srv := startStatsServer("127.0.0.1:0", newStats(), func() error {
		calls++
		return probeSocksUpstream(auth.addr(), "router", "secret")
	})
	if srv == nil {
		t.Fatal("stats server failed")
	}
	defer srv.Close()
	base := "http://" + srv.Addr

	// 正确凭据：200 ready
	resp, err := http.Get(base + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || strings.TrimSpace(string(body)) != "ready" {
		t.Fatalf("readyz ok case: status=%d body=%q", resp.StatusCode, body)
	}

	// TTL 内第二次抓取必须命中缓存：探针只执行一次，mock 只收到一条连接
	resp2, err := http.Get(base + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp2.Body.Close()
	if calls != 1 {
		t.Fatalf("readyz cache: probe calls=%d want 1", calls)
	}
	if got := auth.hitCount(); got != 1 {
		t.Fatalf("readyz cache: upstream connections=%d want 1", got)
	}

	// 故障探针 → 503
	bad := startStatsServer("127.0.0.1:0", newStats(), func() error {
		return probeSocksUpstream("127.0.0.1:1", "", "")
	})
	if bad == nil {
		t.Fatal("bad-probe server failed")
	}
	defer bad.Close()
	resp3, err := http.Get("http://" + bad.Addr + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	b3, _ := io.ReadAll(resp3.Body)
	_ = resp3.Body.Close()
	if resp3.StatusCode != 503 || !strings.Contains(string(b3), "not ready") {
		t.Fatalf("readyz fail case: status=%d body=%q", resp3.StatusCode, b3)
	}
}

func TestReadinessCache(t *testing.T) {
	// TTL 内缓存成功与失败结果；过期后重新探测
	calls := 0
	failing := false
	rc := &readinessCache{
		ttl: 50 * time.Millisecond,
		probe: func() error {
			calls++
			if failing {
				return errors.New("upstream down")
			}
			return nil
		},
	}
	if err := rc.check(); err != nil || calls != 1 {
		t.Fatalf("first check: err=%v calls=%d", err, calls)
	}
	if err := rc.check(); err != nil || calls != 1 {
		t.Fatalf("cached check: err=%v calls=%d", err, calls)
	}
	time.Sleep(70 * time.Millisecond)
	failing = true
	if err := rc.check(); err == nil || calls != 2 {
		t.Fatalf("refreshed check should see failure: calls=%d", calls)
	}
	// 失败结果同样被缓存，避免上游持续故障时每次抓取都拨号
	if err := rc.check(); err == nil || calls != 2 {
		t.Fatalf("cached failure: calls=%d", calls)
	}
}
