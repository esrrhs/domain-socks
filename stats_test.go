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
	"sync/atomic"
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
	var n atomic.Int64
	raw := &bufConn{}
	c := countingConn{Conn: raw, n: &n}

	if k, err := c.Write([]byte("ping")); err != nil || k != 4 {
		t.Fatalf("first write: k=%d err=%v", k, err)
	}
	if k, err := c.Write([]byte("pong")); err != nil || k != 4 {
		t.Fatalf("second write: k=%d err=%v", k, err)
	}
	if n.Load() != 8 || raw.buf.String() != "pingpong" {
		t.Fatalf("counted=%d underlying=%q", n.Load(), raw.buf.String())
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
	// 一次真实 ASSOCIATE 握手必须被延迟直方图记录
	if h := snap.Histograms[histUDPAssocDialSeconds]; h.Count != 1 || h.SumSeconds <= 0 {
		t.Fatalf("udp assoc dial histogram=%+v want count=1 sum>0", h)
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
	// Close flush 的 flow 必须记录一次存活时长（代理路径，sum>0）
	if h := st.snapshot().Histograms[histUDPFlowSeconds]; h.Count != 1 || h.SumSeconds <= 0 {
		t.Fatalf("udp flow lifetime histogram=%+v want count=1 sum>0", h)
	}

	// Close flush 了 UDP flow：/top 两张表都应含本次代理流量
	drows := st.domains.top(10)
	crows := st.clients.top(10)
	var drow, crow *aggRow
	for i := range drows {
		if drows[i].key == "www.google.com" {
			drow = &drows[i]
		}
	}
	for i := range crows {
		if crows[i].key == "lan-stats-1" {
			crow = &crows[i]
		}
	}
	if drow == nil {
		t.Fatalf("udp flow domain missing from /top: %+v", drows)
	}
	if drow.conns != 1 || drow.proxy != 1 || drow.direct != 0 || drow.up != 4 || drow.down != 4 {
		t.Fatalf("udp domain aggregate=%+v want conns/proxy=1 up/down=4", drow)
	}
	if crow == nil || crow.up != 4 || crow.down != 4 {
		t.Fatalf("udp client aggregate=%+v want up/down=4", crow)
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

func TestHistogramBuckets(t *testing.T) {
	bounds := []float64{0.001, 0.01, 1}
	h := newHistogram(bounds)

	// 等上界归属（le 语义）：0 与恰为 1ms 都进首桶
	h.observe(0)
	h.observe(1 * time.Millisecond)
	h.observe(2 * time.Millisecond) // 第二桶 (1ms,10ms]
	h.observe(10 * time.Millisecond)
	h.observe(500 * time.Millisecond) // 第三桶 (10ms,1s]
	h.observe(1 * time.Second)        // 恰好等于上界仍进第三桶
	h.observe(2 * time.Second)        // +Inf

	snap := h.snapshot()
	if snap.Count != 7 {
		t.Fatalf("count=%d want 7", snap.Count)
	}
	wantRaw := []int64{2, 2, 2, 1} // 原始每桶计数
	var gotRaw []int64
	cum := snap.CumulativeCounts
	for i := range cum {
		var prev int64
		if i > 0 {
			prev = cum[i-1]
		}
		gotRaw = append(gotRaw, cum[i]-prev)
	}
	if len(gotRaw) != len(wantRaw) {
		t.Fatalf("bucket count=%d want %d (finite bounds + +Inf)", len(gotRaw), len(wantRaw))
	}
	for i := range wantRaw {
		if gotRaw[i] != wantRaw[i] {
			t.Fatalf("raw bucket[%d]=%d want %d (cum=%v)", i, gotRaw[i], wantRaw[i], cum)
		}
	}
	// 累计末值必须等于总样本数
	if cum[len(cum)-1] != 7 {
		t.Fatalf("+Inf cumulative=%d want 7", cum[len(cum)-1])
	}
	// 边界切片不暴露内部可变数组（快照应可独立持有）
	snap.BucketsLE[0] = 999
	if h.buckets[0] != 0.001 {
		t.Fatal("snapshot must not alias the internal bucket slice")
	}
	// sum：0+1ms+2ms+10ms+500ms+1s+2s = 3.513s
	if got := snap.SumSeconds; got < 3.512 || got > 3.514 {
		t.Fatalf("sum=%.6f want ~3.513", got)
	}
}

func TestHistogramSafety(t *testing.T) {
	var nilH *histogram
	nilH.observe(time.Second) // 必须不 panic
	nilH.observe(-1)          // 负值忽略

	h := newHistogram([]float64{1})
	h.observe(-5 * time.Second)
	if h.snapshot().Count != 0 {
		t.Fatal("negative observation must be dropped")
	}
	var nilStats *stats
	nilStats.observe(histTCPProxyDialSeconds, time.Second) // nil stats 安全
}

func TestHistogramExposedInSnapshots(t *testing.T) {
	s := newStats()
	s.observe(histTCPProxyDialSeconds, 5*time.Millisecond)
	s.observe(histTCPDirectDialSeconds, 50*time.Millisecond)
	s.observe(histTCPProxyConnSeconds, 3*time.Second)
	s.observe(histTCPDirectConnSeconds, 200*time.Millisecond)

	// JSON 快照含两张直方图且数值合法（+Inf 不得进入 JSON）
	jb, err := json.Marshal(s.snapshot())
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	var decoded statsJSON
	if err := json.Unmarshal(jb, &decoded); err != nil {
		t.Fatalf("histogram snapshot must be valid JSON: %v", err)
	}
	if decoded.Histograms[histTCPProxyDialSeconds].Count != 1 {
		t.Fatalf("proxy dial count in json snapshot=%v", decoded.Histograms)
	}
	if decoded.Histograms[histTCPDirectDialSeconds].Count != 1 {
		t.Fatalf("direct dial count in json snapshot=%v", decoded.Histograms)
	}
	if decoded.Histograms[histTCPProxyConnSeconds].Count != 1 ||
		decoded.Histograms[histTCPDirectConnSeconds].Count != 1 {
		t.Fatalf("conn hist counts in json snapshot=%v want 1/1", decoded.Histograms)
	}
	if strings.Contains(string(jb), "Inf") {
		t.Fatalf("JSON must not contain Inf:\n%s", jb)
	}

	// 文本快照含直方图段与桶行
	text := s.renderText()
	if !strings.Contains(text, "histograms:") ||
		!strings.Contains(text, histTCPProxyDialSeconds) ||
		!strings.Contains(text, histTCPProxyConnSeconds) ||
		!strings.Contains(text, "le=") ||
		!strings.Contains(text, "+Inf") {
		t.Fatalf("text snapshot missing histogram section:\n%s", text)
	}
}

func TestConnTrackerLifecycle(t *testing.T) {
	s := newStats()
	var up1, down1, up2, down2 atomic.Int64
	up1.Store(100)
	down1.Store(200)

	i1, unreg1 := s.trackConn("192.168.1.5:5000", "www.example.com:443", "socks", &up1, &down1)
	i2, unreg2 := s.trackConn("192.168.1.6:5001", "10.1.2.3:80", "direct", &up2, &down2)
	if i1 == nil || i2 == nil {
		t.Fatal("trackConn must return info + unregister")
	}

	rows := s.conns.rows(time.Now())
	if len(rows) != 2 {
		t.Fatalf("rows=%d want 2", len(rows))
	}
	// 注册即 dial 状态
	var r1 connRow
	for _, r := range rows {
		if r.target == "www.example.com:443" {
			r1 = r
		}
	}
	if r1.client != "192.168.1.5:5000" || r1.via != "socks" || r1.state != "dial" ||
		r1.up != 100 || r1.down != 200 || r1.age <= 0 {
		t.Fatalf("tracked row mismatch: %+v", r1)
	}

	// 拨号完成切 forward；字节热更新无需重新注册
	i1.setState("forward")
	up1.Add(50)
	rows = s.conns.rows(time.Now())
	for _, r := range rows {
		if r.target == "www.example.com:443" {
			if r.state != "forward" || r.up != 150 {
				t.Fatalf("forward row mismatch: %+v", r)
			}
		}
	}

	// 注销幂等
	unreg1()
	unreg1()
	if len(s.conns.rows(time.Now())) != 1 {
		t.Fatal("idempotent unregister must leave exactly one conn")
	}
	unreg2()
	if rows := s.conns.rows(time.Now()); len(rows) != 0 {
		t.Fatalf("all unregistered: rows=%d want 0", len(rows))
	}

	// nil stats / nil info 全部安全
	var nilS *stats
	if ni, fn := nilS.trackConn("c", "t", "socks", &up1, &down1); ni != nil {
		t.Fatal("nil stats trackConn must return nil info")
	} else {
		fn() // 不得 panic
	}
	var nilInfo *connInfo
	nilInfo.setState("forward") // 不得 panic
}

func TestConnsHTTPEndpoint(t *testing.T) {
	s := newStats()
	srv := startStatsServer("127.0.0.1:0", s, func() error { return nil })
	if srv == nil {
		t.Fatal("stats server failed")
	}
	defer srv.Close()
	base := "http://" + srv.Addr

	// 空集合
	resp, err := http.Get(base + "/conns")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "no active connections") {
		t.Fatalf("empty /conns: status=%d body=%q", resp.StatusCode, body)
	}

	// 存活连接出现在表格中
	var up, down atomic.Int64
	up.Store(2048)
	down.Store(1 << 20)
	info, unreg := s.trackConn("192.168.1.5:54321", "www.google.com:443", "socks", &up, &down)
	info.setState("forward")
	defer unreg()

	resp2, err := http.Get(base + "/conns")
	if err != nil {
		t.Fatal(err)
	}
	tbl, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	for _, want := range []string{"www.google.com:443", "192.168.1.5:54321", "socks", "forward", "2.0KiB", "1.00MiB", "AGE"} {
		if !strings.Contains(string(tbl), want) {
			t.Fatalf("/conns table missing %q:\n%s", want, tbl)
		}
	}
}

func TestAggTable(t *testing.T) {
	tb := newAggTable(3)

	tb.record("a.com", "socks", 100, 200)
	tb.record("a.com", "direct", 10, 20)
	tb.record("b.com", "socks", 500, 500)
	tb.record("c.com", "direct", 1, 1)
	// 第 4 个新键超容量，折叠进 __other__
	tb.record("d.com", "socks", 7, 7)
	tb.record("e.com", "direct", 3, 3)

	rows := tb.top(10)
	if len(rows) != 4 { // a/b/c/__other__
		t.Fatalf("rows=%d want 4 (3 keys + overflow)", len(rows))
	}
	if rows[0].key != "b.com" || rows[0].up+rows[0].down != 1000 {
		t.Fatalf("top row=%+v want b.com/1000", rows[0])
	}
	var a, other aggRow
	for _, r := range rows {
		switch r.key {
		case "a.com":
			a = r
		case aggOverflow:
			other = r
		}
	}
	if a.conns != 2 || a.proxy != 1 || a.direct != 1 || a.up != 110 || a.down != 220 {
		t.Fatalf("a.com aggregate=%+v", a)
	}
	// d.com+e.com 都折叠进 __other__：2 条、proxy/direct 各 1
	if other.conns != 2 || other.proxy != 1 || other.direct != 1 || other.up != 10 || other.down != 10 {
		t.Fatalf("overflow aggregate=%+v", other)
	}

	// topN 截断
	if got := tb.top(2); len(got) != 2 || got[0].key != "b.com" {
		t.Fatalf("top(2)=%+v", got)
	}

	// 空键与 nil 表跳过；recordFlow 只收 socks/direct
	tb.record("", "socks", 999, 999)
	if len(tb.top(100)) != 4 {
		t.Fatal("empty key must be dropped")
	}
	var nilTB *aggTable
	nilTB.record("x", "socks", 1, 1) // 不 panic

	s := newStats()
	s.recordFlow("h.example", "192.168.1.5", "socks", 10, 20)
	s.recordFlow("h.example", "192.168.1.5", "dst-fail", 9, 9) // 过滤
	s.recordFlow("h.example", "192.168.1.5", "captive204", 9, 9)
	var nilS *stats
	nilS.recordFlow("h", "c", "socks", 1, 1) // 不 panic
	dr := s.domains.top(10)
	cr := s.clients.top(10)
	if len(dr) != 1 || dr[0].conns != 1 || dr[0].proxy != 1 || dr[0].up != 10 {
		t.Fatalf("domain rows=%+v", dr)
	}
	if len(cr) != 1 || cr[0].key != "192.168.1.5" || cr[0].conns != 1 {
		t.Fatalf("client rows=%+v", cr)
	}
}

func TestTopHTTPEndpoint(t *testing.T) {
	s := newStats()
	srv := startStatsServer("127.0.0.1:0", s, nil)
	if srv == nil {
		t.Fatal("stats server failed")
	}
	defer srv.Close()
	base := "http://" + srv.Addr

	resp, err := http.Get(base + "/top")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "top domains") ||
		!strings.Contains(string(body), "top clients") ||
		!strings.Contains(string(body), "(empty)") {
		t.Fatalf("empty /top mismatch:\n%s", body)
	}

	s.recordFlow("heavy.example", "192.168.1.9", "socks", 3000, 7000)
	resp2, err := http.Get(base + "/top")
	if err != nil {
		t.Fatal(err)
	}
	tbl, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	for _, want := range []string{"heavy.example", "192.168.1.9", "CONNS", "PROXY", "2.9KiB", "6.8KiB"} {
		if !strings.Contains(string(tbl), want) {
			t.Fatalf("/top missing %q:\n%s", want, tbl)
		}
	}
}

// stripLiveMetrics 剔除两个实时 runtime gauge 的样本行：uptime 可能跨秒、
// 并发测试会改变 goroutine 数，都是合法活值，不能参与渲染确定性比较。
func stripLiveMetrics(in string) string {
	var out []string
	for _, ln := range strings.Split(in, "\n") {
		if strings.HasPrefix(ln, promPrefix+"uptime_seconds ") ||
			strings.HasPrefix(ln, promPrefix+"goroutines ") {
			continue
		}
		out = append(out, ln)
	}
	return strings.Join(out, "\n")
}

// parsePromLines 极简解析 /metrics：返回 sample[name+labels]=value，
// typ[name]=类型，help 存在性单独检查。
func parsePromLines(t *testing.T, body string) (map[string]string, map[string]string, int) {
	t.Helper()
	samples := map[string]string{}
	types := map[string]string{}
	helpCount := 0
	for _, line := range strings.Split(body, "\n") {
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "# TYPE "):
			fields := strings.Fields(line)
			if len(fields) != 4 {
				t.Fatalf("bad TYPE line: %q", line)
			}
			types[fields[2]] = fields[3]
		case strings.HasPrefix(line, "# HELP "):
			helpCount++
		case strings.HasPrefix(line, "#"):
			t.Fatalf("unexpected comment: %q", line)
		default:
			fields := strings.Fields(line)
			if len(fields) != 2 {
				t.Fatalf("bad sample line: %q", line)
			}
			samples[fields[0]] = fields[1]
		}
	}
	return samples, types, helpCount
}

func TestPrometheusExposition(t *testing.T) {
	s := newStats()
	s.inc(statTCPAccepted)
	s.inc(statTCPAccepted)
	s.inc(statTCPProxyBytesDown) // 值为 1 的字节计数器
	s.observe(histTCPProxyDialSeconds, 5*time.Millisecond)
	s.observe(histTCPProxyDialSeconds, 3*time.Second)

	body := s.renderPrometheus()
	samples, types, helpCount := parsePromLines(t, body)

	// 每个 TYPE 都有配套 HELP
	if helpCount != len(types) {
		t.Fatalf("HELP lines=%d != TYPE families=%d", helpCount, len(types))
	}
	if v := samples["domain_socks_up"]; v != "1" || types["domain_socks_up"] != "gauge" {
		t.Fatalf("up gauge: val=%q type=%q", v, types["domain_socks_up"])
	}
	if v := samples["domain_socks_tcp_accepted_total"]; v != "2" ||
		types["domain_socks_tcp_accepted_total"] != "counter" {
		t.Fatalf("accepted counter: val=%q type=%q", v, types["domain_socks_tcp_accepted_total"])
	}
	if v := samples["domain_socks_tcp_proxy_bytes_down_total"]; v != "1" {
		t.Fatalf("bytes counter=%q", v)
	}
	// 计数器不得出现不带 _total 的裸名
	if _, ok := samples["domain_socks_tcp_accepted"]; ok {
		t.Fatal("counters must use _total suffix")
	}
	for _, g := range []string{"domain_socks_uptime_seconds", "domain_socks_goroutines", "domain_socks_tcp_active"} {
		if types[g] != "gauge" {
			t.Fatalf("%s type=%q want gauge", g, types[g])
		}
		if _, ok := samples[g]; !ok {
			t.Fatalf("missing gauge sample %s", g)
		}
	}

	// 直方图族：13 个有限 le 桶 + +Inf + sum + count
	fam := "domain_socks_tcp_proxy_dial_seconds"
	if types[fam] != "histogram" {
		t.Fatalf("histogram family type=%q", types[fam])
	}
	var bucketLines int
	var infCount string
	for name, v := range samples {
		if strings.HasPrefix(name, fam+"_bucket{le=") {
			bucketLines++
			if strings.Contains(name, `le="+Inf"`) {
				infCount = v
			}
		}
	}
	if bucketLines != len(dialBuckets)+1 {
		t.Fatalf("bucket lines=%d want %d", bucketLines, len(dialBuckets)+1)
	}
	if infCount != "2" {
		t.Fatalf("+Inf bucket=%q want 2", infCount)
	}
	if samples[fam+"_count"] != "2" {
		t.Fatalf("hist count=%q want 2", samples[fam+"_count"])
	}
	// 5ms 与 3s 的桶累计：le=0.005 应为 1，le=5（含两样本）应为 2
	wantLe := map[string]string{
		fam + `_bucket{le="0.005"}`: "1",
		fam + `_bucket{le="5"}`:     "2",
	}
	for k, want := range wantLe {
		if samples[k] != want {
			t.Fatalf("%s=%q want %s", k, samples[k], want)
		}
	}
	if sum := samples[fam+"_sum"]; sum != "3.005" {
		t.Fatalf("hist sum=%q want 3.005", sum)
	}

	// 除 le 标签外不得出现 Inf/NaN 值
	for name, v := range samples {
		if strings.Contains(name, "_bucket{") {
			continue
		}
		if v == "+Inf" || v == "-Inf" || v == "NaN" {
			t.Fatalf("illegal float value for %s: %s", name, v)
		}
	}

	// 输出确定性：族顺序/格式必须稳定。剔除两个实时 runtime gauge
	// 的样本行（uptime 跨秒、并发测试改变 goroutine 数都是合法活值）。
	if stripLiveMetrics(body) != stripLiveMetrics(s.renderPrometheus()) {
		t.Fatal("prometheus render is not deterministic")
	}

	// nil stats 安全：只报 up=0
	var nilS *stats
	nilBody := nilS.renderPrometheus()
	nSamples, _, _ := parsePromLines(t, nilBody)
	if nSamples["domain_socks_up"] != "0" || len(nSamples) != 1 {
		t.Fatalf("nil render=%q", nilBody)
	}
}

func TestMetricsHTTPEndpoint(t *testing.T) {
	s := newStats()
	srv := startStatsServer("127.0.0.1:0", s, nil)
	if srv == nil {
		t.Fatal("stats server failed")
	}
	defer srv.Close()

	resp, err := http.Get("http://" + srv.Addr + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	ct := resp.Header.Get("Content-Type")
	if resp.StatusCode != 200 || !strings.HasPrefix(ct, "text/plain; version=0.0.4") {
		t.Fatalf("/metrics: status=%d content-type=%q", resp.StatusCode, ct)
	}
	if !strings.Contains(string(body), "# TYPE domain_socks_tcp_accepted_total counter") {
		t.Fatalf("/metrics missing TYPE header:\n%s", body)
	}
}

// TestPrometheusTopExport 验证 /top 排行榜以带 label 的 counter 导出：
// 空表也有族头、字节/路由拆分值正确、label 转义、渲染确定、基数有界。
func TestPrometheusTopExport(t *testing.T) {
	s := newStats()
	empty := s.renderPrometheus()
	for _, hdr := range []string{
		"# TYPE domain_socks_top_domain_bytes_total counter",
		"# TYPE domain_socks_top_domain_connections_total counter",
		"# TYPE domain_socks_top_client_bytes_total counter",
		"# TYPE domain_socks_top_client_connections_total counter",
	} {
		if !strings.Contains(empty, hdr) {
			t.Fatalf("empty exposition missing %q", hdr)
		}
	}
	if strings.Contains(empty, "top_domain_bytes_total{") {
		t.Fatalf("no labeled samples expected on empty table")
	}

	s.recordFlow("heavy.example", "192.168.1.9", "socks", 3000, 7000)
	s.recordFlow("heavy.example", "192.168.1.9", "direct", 100, 200)
	s.recordFlow("light.example", "192.168.1.10", "direct", 10, 20)
	// 直接向表写入含特殊字符的键，验证 label 值按 \ \" \n 转义
	s.domains.record(`bad"na\me`+"\nx", "socks", 1, 1)

	body := s.renderPrometheus()
	wantLines := []string{
		`domain_socks_top_domain_bytes_total{name="heavy.example",direction="up"} 3100`,
		`domain_socks_top_domain_bytes_total{name="heavy.example",direction="down"} 7200`,
		`domain_socks_top_domain_connections_total{name="heavy.example",via="proxy"} 1`,
		`domain_socks_top_domain_connections_total{name="heavy.example",via="direct"} 1`,
		`domain_socks_top_client_bytes_total{name="192.168.1.9",direction="up"} 3100`,
		`domain_socks_top_client_connections_total{name="192.168.1.10",via="direct"} 1`,
		// 零值的 via 拆分也必须稳定输出
		`domain_socks_top_domain_connections_total{name="light.example",via="proxy"} 0`,
		// " \ \n -> \" \\ \n
		`name="bad\"na\\me\nx"`,
	}
	for _, w := range wantLines {
		if !strings.Contains(body, w) {
			t.Fatalf("/metrics top export missing %q:\n%s", w, body)
		}
	}

	// 基数硬界：域名维带 label 样本最多 4*aggTopN
	var labeled int
	for _, ln := range strings.Split(body, "\n") {
		if strings.HasPrefix(ln, "domain_socks_top_domain_") && strings.Contains(ln, "{name=") {
			labeled++
		}
	}
	if labeled > 4*aggTopN {
		t.Fatalf("domain labeled samples=%d exceeds bound %d", labeled, 4*aggTopN)
	}

	if stripLiveMetrics(body) != stripLiveMetrics(s.renderPrometheus()) {
		t.Fatal("top export rendering is not deterministic")
	}
}
