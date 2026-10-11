package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	ghdns "github.com/esrrhs/gohome/dns"
)

func TestStatsNilSafe(t *testing.T) {
	var s *stats
	// 未绑定 stats 的数据面路径（历史构造、个别测试）不得 panic
	s.inc(statTCPAccepted)
	s.registerGauges(map[string]func() int64{"x": func() int64 { return 1 }})
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
	srv := startStatsServer("127.0.0.1:0", s)
	if srv == nil {
		t.Fatal("stats server failed to start on ephemeral port")
	}
	defer srv.Close()
	base := "http://" + srv.Addr

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
	if got := startStatsServer("", s); got != nil {
		t.Fatal("empty addr must disable the stats server")
	}
	occupied := startStatsServer("127.0.0.1:0", newStats())
	if occupied == nil {
		t.Fatal("setup: second ephemeral listener unexpectedly failed")
	}
	defer occupied.Close()
	if got := startStatsServer(occupied.Addr, newStats()); got != nil {
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
