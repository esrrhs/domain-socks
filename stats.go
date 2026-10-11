package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// 计数器键名（同时是 JSON / 文本快照中的稳定字段名）
const (
	statTCPAccepted   = "tcp_accepted"    // 进入透明监听的 TCP 连接总数
	statTCPProxy      = "tcp_proxy"       // 经 SOCKS5 转发成功的连接
	statTCPDirect     = "tcp_direct"      // 直连成功的连接
	statTCPCaptive    = "tcp_captive204"  // 连通性探测直接回 204
	statTCPDstFail    = "tcp_dst_fail"    // 原始目标反查失败（REDIRECT 异常）
	statTCPSocksFail  = "tcp_socks_fail"  // 上游 SOCKS5 拨号/握手失败
	statTCPDirectFail = "tcp_direct_fail" // 直连拨号失败

	statUDPIn        = "udp_in"                // 入站 UDP 报文总数
	statUDPProxyIn   = "udp_proxy_in"          // 判定走代理的报文
	statUDPDirectIn  = "udp_direct_in"         // 直连报文
	statUDPReplies   = "udp_replies"           // 成功回送 LAN 客户端的回包
	statUDPReplyMiss = "udp_reply_miss"        // 回包找不到对应 flow（已过期/串台）
	statUDPFwdFail   = "udp_forward_fail"      // 转发失败（含冷却快速失败）
	statAssocUp      = "udp_assoc_established" // ASSOCIATE 成功建立次数
	statAssocDown    = "udp_assoc_teardown"    // ASSOCIATE 被拆除次数（断连/关闭）
	statAssocCool    = "udp_assoc_cooldown"    // 命中建连冷却快速失败次数
	statAssocBadPkt  = "udp_assoc_bad_packet"  // relay 回包解析失败次数

	statDNSQueries      = "dns_queries"        // 到达本地解析器的查询总数
	statDNSAAAA         = "dns_queries_aaaa"   // 其中 AAAA 查询数
	statDNSAAAAFiltered = "dns_aaaa_filtered"  // 代理域名 AAAA 被空 NOERROR 拦截数
	statDNSFakeIP       = "dns_fakeip_answers" // 应答含 Fake-IP A 记录的响应数
	statDNSErrors       = "dns_errors"         // 上游解析失败的查询数

	// 字节量（按连接/报文汇总，非每包原子操作）
	statTCPProxyBytesUp    = "tcp_proxy_bytes_up"   // 经 SOCKS5 上行（LAN->远端）
	statTCPProxyBytesDown  = "tcp_proxy_bytes_down" // 经 SOCKS5 下行（远端->LAN）
	statTCPDirectBytesUp   = "tcp_direct_bytes_up"
	statTCPDirectBytesDown = "tcp_direct_bytes_down"
	statUDPBytesIn         = "udp_bytes_in"  // LAN 入站报文载荷字节
	statUDPBytesOut        = "udp_bytes_out" // 回送 LAN 的报文载荷字节
)

// stats 持有进程级数据面计数器。所有 inc 方法对 nil 接收者安全，
// 使未启用统计的构造路径（旧测试）无需改动。
type stats struct {
	start time.Time

	counters map[string]*atomic.Int64
	// tcpActive 是当前处于转发/嗅探阶段的透明 TCP 连接数
	tcpActive atomic.Int64

	mu     sync.Mutex
	gauges map[string]func() int64
}

func newStats() *stats {
	keys := []string{
		statTCPAccepted, statTCPProxy, statTCPDirect, statTCPCaptive,
		statTCPDstFail, statTCPSocksFail, statTCPDirectFail,
		statUDPIn, statUDPProxyIn, statUDPDirectIn,
		statUDPReplies, statUDPReplyMiss, statUDPFwdFail,
		statAssocUp, statAssocDown, statAssocCool, statAssocBadPkt,
		statDNSQueries, statDNSAAAA, statDNSAAAAFiltered,
		statDNSFakeIP, statDNSErrors,
		statTCPProxyBytesUp, statTCPProxyBytesDown,
		statTCPDirectBytesUp, statTCPDirectBytesDown,
		statUDPBytesIn, statUDPBytesOut,
	}
	s := &stats{
		start:    time.Now(),
		counters: make(map[string]*atomic.Int64, len(keys)),
		gauges:   make(map[string]func() int64),
	}
	for _, k := range keys {
		s.counters[k] = new(atomic.Int64)
	}
	// 内部 gauge 直接注册
	s.gauges["tcp_active"] = s.tcpActive.Load
	return s
}

func (s *stats) tcpConnOpened() {
	if s != nil {
		s.tcpActive.Add(1)
	}
}

func (s *stats) tcpConnClosed() {
	if s != nil {
		s.tcpActive.Add(-1)
	}
}

func (s *stats) inc(key string) {
	if s == nil {
		return
	}
	if c := s.counters[key]; c != nil {
		c.Add(1)
	}
}

// add 批量累加（连接结束时汇总字节数用，避免每包一次原子操作）
func (s *stats) add(key string, n int64) {
	if s == nil || n == 0 {
		return
	}
	if c := s.counters[key]; c != nil {
		c.Add(n)
	}
}

// registerGauges 注册瞬时值采集函数（如活跃 flow 数、association 在线状态）
func (s *stats) registerGauges(m map[string]func() int64) {
	if s == nil {
		return
	}
	s.mu.Lock()
	for k, fn := range m {
		s.gauges[k] = fn
	}
	s.mu.Unlock()
}

// statsJSON 是 /json 的稳定输出结构
type statsJSON struct {
	UptimeSeconds int64            `json:"uptime_seconds"`
	Goroutines    int              `json:"goroutines"`
	Counters      map[string]int64 `json:"counters"`
	Gauges        map[string]int64 `json:"gauges"`
}

func (s *stats) snapshot() statsJSON {
	counters := make(map[string]int64, len(s.counters))
	for k, c := range s.counters {
		counters[k] = c.Load()
	}
	gauges := make(map[string]int64)
	if s != nil {
		s.mu.Lock()
		for k, fn := range s.gauges {
			gauges[k] = fn()
		}
		s.mu.Unlock()
	}
	return statsJSON{
		UptimeSeconds: int64(time.Since(s.start).Seconds()),
		Goroutines:    runtime.NumGoroutine(),
		Counters:      counters,
		Gauges:        gauges,
	}
}

// renderText 输出适合 curl/人眼阅读的对齐文本
func (s *stats) renderText() string {
	snap := s.snapshot()
	out := fmt.Sprintf("domain-socks stats (uptime %ds, goroutines %d)\ncounters:\n",
		snap.UptimeSeconds, snap.Goroutines)
	for _, k := range sortedKeys(snap.Counters) {
		out += fmt.Sprintf("  %-22s %d\n", k, snap.Counters[k])
	}
	if len(snap.Gauges) > 0 {
		out += "gauges:\n"
		for _, k := range sortedKeys(snap.Gauges) {
			out += fmt.Sprintf("  %-22s %d\n", k, snap.Gauges[k])
		}
	}
	return out
}

func sortedKeys(m map[string]int64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// startStatsServer 启动只读指标 HTTP 服务。addr 为空表示禁用；
// 绑定失败不致命（端口冲突不应拖垮代理数据面），仅告警并返回 nil。
// 默认 127.0.0.1:18080 只对本机可达；显式绑定 0.0.0.0/:: 会向 LAN 暴露。
func startStatsServer(addr string, s *stats) *http.Server {
	if addr == "" || s == nil {
		return nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("stats server disabled, listen %s failed: %v", addr, err)
		return nil
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(s.snapshot())
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = fmt.Fprint(w, s.renderText())
	})
	srv := &http.Server{Addr: ln.Addr().String(), Handler: mux}
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("stats server: %v", err)
		}
	}()
	log.Printf("stats server listening on %s (GET / or /json)", ln.Addr())
	return srv
}
