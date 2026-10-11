package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"runtime"
	"sort"
	"strconv"
	"strings"
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

	// 延迟直方图（固定桶，单位秒；observe 传拨号耗时，成功/失败都记）
	histTCPProxyDialSeconds  = "tcp_proxy_dial_seconds"  // SOCKS5 拨号+协商+CONNECT 总耗时
	histTCPDirectDialSeconds = "tcp_direct_dial_seconds" // 直连 net.Dial 耗时
	histUDPAssocDialSeconds  = "udp_assoc_dial_seconds"  // UDP ASSOCIATE 拨号+握手耗时
	histDNSUpstreamSeconds   = "dns_upstream_seconds"    // 上游 DNS 解析往返耗时

	// 连接时长直方图（固定桶，单位秒；连接关闭时 observe 一次）
	histTCPProxyConnSeconds  = "tcp_proxy_conn_seconds"  // 经 SOCKS5 转发连接的总存活时长
	histTCPDirectConnSeconds = "tcp_direct_conn_seconds" // 直连转发连接的总存活时长
)

// dnsBuckets 比拨号桶更细：本地/快速上游常在 1~5ms，劣化时滑向
// 50ms~1s，超过 2s 通常已逼近解析超时；AAAA 本地短路不进此图。
var dnsBuckets = []float64{
	0.0005, 0.001, 0.002, 0.005, 0.01, 0.02, 0.05,
	0.1, 0.2, 0.5, 1, 2, 5, 10,
}

// dialBuckets 覆盖拨号延迟的关心区间：局域网 SOCKS5 通常 <10ms，
// 经公网上游劣化时落在 100ms~2s，8s/12s 超时的失败落入 +Inf 前的末档。
var dialBuckets = []float64{
	0.001, 0.0025, 0.005, 0.01, 0.025, 0.05,
	0.1, 0.25, 0.5, 1, 2, 5, 10,
}

// connBuckets 覆盖连接会话长度（接受连接到关闭，含拨号）：短请求常在
// 亚秒~数秒，长连（keep-alive/流式/推送）数十秒到数分钟，超过 1h 折叠进 +Inf。
var connBuckets = []float64{
	0.1, 0.25, 0.5, 1, 2, 5, 10,
	30, 60, 180, 600, 1800, 3600,
}

// histogram 是固定上界延迟分布（零依赖；观测热路径只有一次原子 Add）。
// counts 长度为 len(buckets)+1，最后一个是 +Inf 桶；sumMicros 用整数
// 微秒累加，避免 float 原子操作。buckets 构造后不可变，可跨实例共享。
type histogram struct {
	buckets   []float64
	counts    []atomic.Int64
	sumMicros atomic.Int64
}

func newHistogram(buckets []float64) *histogram {
	return &histogram{buckets: buckets, counts: make([]atomic.Int64, len(buckets)+1)}
}

// observe 记录一次耗时。nil 接收者与负值均安全忽略。
// 等上界归属：v 恰好等于桶边界时计入该桶（Prometheus le 语义）。
func (h *histogram) observe(d time.Duration) {
	if h == nil || d < 0 {
		return
	}
	h.sumMicros.Add(d.Microseconds())
	i := sort.SearchFloat64s(h.buckets, d.Seconds())
	h.counts[i].Add(1)
}

type histogramJSON struct {
	// BucketsLE 是有限桶上界（秒）；CumulativeCounts 比它多一个尾元素，
	// 对应 le=+Inf（即 count）。刻意不在 JSON 中输出 +Inf（非法 JSON 数值）。
	BucketsLE        []float64 `json:"buckets_le_seconds"`
	CumulativeCounts []int64   `json:"cumulative_counts"`
	Count            int64     `json:"count"`
	SumSeconds       float64   `json:"sum_seconds"`
}

func (h *histogram) snapshot() histogramJSON {
	cum := make([]int64, len(h.counts))
	var total int64
	for i := range h.counts {
		total += h.counts[i].Load()
		cum[i] = total
	}
	bounds := make([]float64, len(h.buckets))
	copy(bounds, h.buckets)
	return histogramJSON{
		BucketsLE:        bounds,
		CumulativeCounts: cum,
		Count:            total,
		SumSeconds:       float64(h.sumMicros.Load()) / 1e6,
	}
}

// stats 持有进程级数据面计数器。所有 inc 方法对 nil 接收者安全，
// 使未启用统计的构造路径（旧测试）无需改动。
type stats struct {
	start time.Time

	counters map[string]*atomic.Int64
	// tcpActive 是当前处于转发/嗅探阶段的透明 TCP 连接数
	tcpActive atomic.Int64

	mu     sync.Mutex
	gauges map[string]func() int64

	histograms map[string]*histogram
	conns      *connTracker

	domains *aggTable // 按目标域名/IP 聚合（连接关闭时记一次）
	clients *aggTable // 按 LAN 客户端 IP 聚合
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
		start:      time.Now(),
		counters:   make(map[string]*atomic.Int64, len(keys)),
		gauges:     make(map[string]func() int64),
		histograms: make(map[string]*histogram, 6),
		conns:      newConnTracker(),
		domains:    newAggTable(aggCapDomains),
		clients:    newAggTable(aggCapClients),
	}
	for _, k := range keys {
		s.counters[k] = new(atomic.Int64)
	}
	s.histograms[histTCPProxyDialSeconds] = newHistogram(dialBuckets)
	s.histograms[histTCPDirectDialSeconds] = newHistogram(dialBuckets)
	s.histograms[histUDPAssocDialSeconds] = newHistogram(dialBuckets)
	s.histograms[histDNSUpstreamSeconds] = newHistogram(dnsBuckets)
	s.histograms[histTCPProxyConnSeconds] = newHistogram(connBuckets)
	s.histograms[histTCPDirectConnSeconds] = newHistogram(connBuckets)
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

// observe 向命名直方图记录一次耗时（nil stats 安全）。
func (s *stats) observe(key string, d time.Duration) {
	if s == nil {
		return
	}
	if h := s.histograms[key]; h != nil {
		h.observe(d)
	}
}

// connInfo 是一条存活中的透明 TCP 连接的实时视图（GET /conns）。
// 注册时路由（via）已决定，state 在拨号成功后由 dial 切到 forward。
type connInfo struct {
	start  time.Time
	client string
	target string
	via    string // socks / direct
	up     *atomic.Int64
	down   *atomic.Int64

	mu    sync.Mutex
	state string // "dial" | "forward"
}

func (i *connInfo) setState(state string) {
	if i == nil {
		return
	}
	i.mu.Lock()
	i.state = state
	i.mu.Unlock()
}

type connRow struct {
	age            time.Duration
	client, target string
	via, state     string
	up, down       int64
}

// connTracker 是存活连接集合。每连接仅 add/remove 两次短临界区，
// 快照按 age 降序拷贝输出，遍历期间不阻塞数据面写字节。
type connTracker struct {
	mu    sync.Mutex
	conns map[*connInfo]struct{}
}

func newConnTracker() *connTracker {
	return &connTracker{conns: make(map[*connInfo]struct{})}
}

func (t *connTracker) add(i *connInfo) func() {
	t.mu.Lock()
	t.conns[i] = struct{}{}
	t.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			t.mu.Lock()
			delete(t.conns, i)
			t.mu.Unlock()
		})
	}
}

// trackConn 登记一条连接（dial 状态），返回信息体与幂等注销函数。
// nil 接收者安全，使未启用统计的构造路径无需判空。
func (s *stats) trackConn(client, target, via string, up, down *atomic.Int64) (*connInfo, func()) {
	if s == nil || s.conns == nil {
		return nil, func() {}
	}
	info := &connInfo{
		start: time.Now(), client: client, target: target, via: via,
		up: up, down: down, state: "dial",
	}
	return info, s.conns.add(info)
}

func (t *connTracker) rows(now time.Time) []connRow {
	t.mu.Lock()
	rows := make([]connRow, 0, len(t.conns))
	for i := range t.conns {
		i.mu.Lock()
		state := i.state
		i.mu.Unlock()
		rows = append(rows, connRow{
			age: now.Sub(i.start), client: i.client, target: i.target,
			via: i.via, state: state, up: i.up.Load(), down: i.down.Load(),
		})
	}
	t.mu.Unlock()
	sort.Slice(rows, func(a, b int) bool { return rows[a].age > rows[b].age })
	return rows
}

// renderConns 输出 curl 友好的等宽表格；无连接时给明确提示。
func (s *stats) renderConns(now time.Time) string {
	if s == nil || s.conns == nil {
		return "no active connections\n"
	}
	rows := s.conns.rows(now)
	if len(rows) == 0 {
		return "no active connections\n"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%-9s %-7s %-8s %-22s %-30s %9s %9s\n",
		"AGE", "VIA", "STATE", "CLIENT", "TARGET", "UP", "DOWN")
	for _, r := range rows {
		fmt.Fprintf(&b, "%-9s %-7s %-8s %-22s %-30s %9s %9s\n",
			r.age.Round(time.Millisecond).String(), r.via, r.state,
			r.client, r.target, humanBytes(r.up), humanBytes(r.down))
	}
	return b.String()
}

// 流量 Top 聚合：回答"哪个域名/哪台设备最耗流量"。仅在连接关闭时
// 写一次（非每包热路径），map 有界，超限的新键折叠进 __other__，
// 适合路由器长期运行不重置。
const (
	aggCapDomains = 8192
	aggCapClients = 1024
	aggTopN       = 20
	aggOverflow   = "__other__"
)

type aggEntry struct {
	conns  int64
	proxy  int64 // 其中经 SOCKS5 转发的连接数
	direct int64 // 其中直连的连接数
	up     int64
	down   int64
}

type aggRow struct {
	key string
	aggEntry
}

type aggTable struct {
	cap int
	mu  sync.Mutex
	m   map[string]*aggEntry
}

func newAggTable(cap int) *aggTable {
	return &aggTable{cap: cap, m: make(map[string]*aggEntry)}
}

// record 累加一条已关闭连接。key 为空（域名反查失败的兜底 unknown
// 不聚合域名）时跳过；超限新键折叠进 aggOverflow。
func (t *aggTable) record(key, via string, up, down int64) {
	if t == nil || key == "" {
		return
	}
	t.mu.Lock()
	e, ok := t.m[key]
	if !ok {
		k := key
		if len(t.m) >= t.cap {
			k = aggOverflow
			e, ok = t.m[k]
		}
		if !ok {
			e = &aggEntry{}
			t.m[k] = e
		}
	}
	e.conns++
	e.up += up
	e.down += down
	switch via {
	case "socks":
		e.proxy++
	case "direct":
		e.direct++
	}
	t.mu.Unlock()
}

// top 返回按总字节降序（并列按键名升序保证确定性）的前 n 行拷贝。
func (t *aggTable) top(n int) []aggRow {
	t.mu.Lock()
	rows := make([]aggRow, 0, len(t.m))
	for k, e := range t.m {
		rows = append(rows, aggRow{key: k, aggEntry: *e})
	}
	t.mu.Unlock()
	sort.Slice(rows, func(a, b int) bool {
		ta, tb := rows[a].up+rows[a].down, rows[b].up+rows[b].down
		if ta != tb {
			return ta > tb
		}
		return rows[a].key < rows[b].key
	})
	if n < len(rows) {
		rows = rows[:n]
	}
	return rows
}

// recordFlow 在连接关闭时按目标 host 与客户端 IP 各聚合一次。
// nil stats 安全；仅 socks/direct 路由计入（dst-fail 无目标流量）。
func (s *stats) recordFlow(targetHost, clientHost, via string, up, down int64) {
	if s == nil || (via != "socks" && via != "direct") {
		return
	}
	s.domains.record(targetHost, via, up, down)
	s.clients.record(clientHost, via, up, down)
}

func renderAggSection(title string, rows []aggRow) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s (top %d by total bytes, since start)\n", title, aggTopN)
	if len(rows) == 0 {
		b.WriteString("  (empty)\n")
		return b.String()
	}
	fmt.Fprintf(&b, "  %-32s %7s %7s %7s %10s %10s\n",
		"NAME", "CONNS", "PROXY", "DIRECT", "UP", "DOWN")
	for _, r := range rows {
		fmt.Fprintf(&b, "  %-32s %7d %7d %7d %10s %10s\n",
			truncateForTable(r.key, 32), r.conns, r.proxy, r.direct,
			humanBytes(r.up), humanBytes(r.down))
	}
	return b.String()
}

// truncateForTable 截断过长键名（域名），保留尾部通常更有区分度的部分。
// 按 rune 截断，避免切断多字节字符产生非法 UTF-8。
func truncateForTable(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return "…" + string(r[len(r)-n+1:])
}

func (s *stats) renderTop() string {
	if s == nil {
		return "top domains:\n  (empty)\ntop clients:\n  (empty)\n"
	}
	var b strings.Builder
	b.WriteString(renderAggSection("top domains", s.domains.top(aggTopN)))
	b.WriteString(renderAggSection("top clients", s.clients.top(aggTopN)))
	return b.String()
}

// Prometheus 文本 exposition（0.0.4，零依赖纯文本）。计数器统一加
// _total 后缀，gauge 不加，直方图输出 _bucket(累计)/_sum/_count。
// 族按名排序，多次抓取字节级确定，方便 Prometheus/Alertmanager 抓取。
const promPrefix = "domain_socks_"

// metricHelp 为 /metrics 提供人类可读说明；新增计数器时在此补一行，
// 缺失的键回退到通用说明，不影响输出合法性。
var metricHelp = map[string]string{
	statTCPAccepted:          "Total intercepted inbound TCP connections.",
	statTCPProxy:             "TCP connections successfully relayed via upstream SOCKS5.",
	statTCPDirect:            "TCP connections successfully dialed directly.",
	statTCPCaptive:           "Captive-portal probes answered with synthetic HTTP 204.",
	statTCPDstFail:           "TCP connections whose original destination could not be recovered.",
	statTCPSocksFail:         "TCP SOCKS5 dial/negotiate/CONNECT failures.",
	statTCPDirectFail:        "TCP direct dial failures.",
	statUDPIn:                "Total inbound UDP datagrams received from LAN clients.",
	statUDPProxyIn:           "Inbound UDP datagrams classified to relay.",
	statUDPDirectIn:          "Inbound UDP datagrams classified direct.",
	statUDPReplies:           "UDP replies successfully delivered back to LAN clients.",
	statUDPReplyMiss:         "UDP replies with no matching client flow (expired/stale).",
	statUDPFwdFail:           "UDP forward failures, including cooldown fast-fails.",
	statAssocUp:              "Successful UDP ASSOCIATE establishments.",
	statAssocDown:            "UDP ASSOCIATE teardowns (upstream close/errors).",
	statAssocCool:            "UDP sends fast-failed by the dial cooldown.",
	statAssocBadPkt:          "Malformed UDP relay packets from the upstream.",
	statDNSQueries:           "Total DNS queries received by the local resolver.",
	statDNSAAAA:              "DNS AAAA queries received.",
	statDNSAAAAFiltered:      "Proxy-domain AAAA queries answered with empty NOERROR.",
	statDNSFakeIP:            "DNS responses containing Fake-IP A records.",
	statDNSErrors:            "DNS queries that failed at the upstream resolver.",
	statTCPProxyBytesUp:      "Bytes sent LAN->remote over SOCKS5-relayed TCP.",
	statTCPProxyBytesDown:    "Bytes sent remote->LAN over SOCKS5-relayed TCP.",
	statTCPDirectBytesUp:     "Bytes sent LAN->remote over direct TCP.",
	statTCPDirectBytesDown:   "Bytes sent remote->LAN over direct TCP.",
	statUDPBytesIn:           "UDP payload bytes received from LAN clients.",
	statUDPBytesOut:          "UDP payload bytes delivered back to LAN clients.",
	histTCPProxyDialSeconds:  "Time spent in SOCKS5 dial+negotiate+CONNECT (incl. failures).",
	histTCPDirectDialSeconds: "Time spent in direct TCP dial (incl. failures).",
	histUDPAssocDialSeconds:  "Time spent in UDP ASSOCIATE dial+handshake (incl. failures; cooldown fast-fails excluded).",
	histDNSUpstreamSeconds:   "Upstream DNS resolver round-trip time (incl. failures; local AAAA short-circuits excluded).",
	histTCPProxyConnSeconds:  "Lifetime of proxied (SOCKS5) TCP connections from accept to close (incl. dial).",
	histTCPDirectConnSeconds: "Lifetime of directly forwarded TCP connections from accept to close (incl. dial).",
}

func promHelp(key string) string {
	if h, ok := metricHelp[key]; ok {
		return h
	}
	return "domain-socks metric " + key + "."
}

func promWriteHeader(b *strings.Builder, family, typ, help string) {
	fmt.Fprintf(b, "# HELP %s %s\n", family, help)
	fmt.Fprintf(b, "# TYPE %s %s\n", family, typ)
}

func promFormatFloat(v float64) string {
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// renderPrometheus 输出 /metrics。nil 接收者只报 up=0，便于探针类调用方。
func (s *stats) renderPrometheus() string {
	var b strings.Builder
	promWriteHeader(&b, promPrefix+"up", "gauge",
		"1 if the domain-socks process is serving metrics, 0 otherwise.")
	if s == nil {
		b.WriteString(promPrefix + "up 0\n")
		return b.String()
	}
	b.WriteString(promPrefix + "up 1\n")

	snap := s.snapshot()
	for _, k := range sortedKeys(snap.Counters) {
		family := promPrefix + k + "_total"
		promWriteHeader(&b, family, "counter", promHelp(k))
		fmt.Fprintf(&b, "%s %d\n", family, snap.Counters[k])
	}

	// 动态 gauge + 两个 runtime gauge
	for _, k := range sortedKeys(snap.Gauges) {
		family := promPrefix + k
		promWriteHeader(&b, family, "gauge", "domain-socks instantaneous gauge "+k+".")
		fmt.Fprintf(&b, "%s %d\n", family, snap.Gauges[k])
	}
	promWriteHeader(&b, promPrefix+"uptime_seconds", "gauge", "Process uptime in seconds.")
	fmt.Fprintf(&b, "%suptime_seconds %d\n", promPrefix, snap.UptimeSeconds)
	promWriteHeader(&b, promPrefix+"goroutines", "gauge", "Current number of goroutines.")
	fmt.Fprintf(&b, "%sgoroutines %d\n", promPrefix, snap.Goroutines)

	for _, k := range sortedKeys(snap.Histograms) {
		family := promPrefix + k
		h := snap.Histograms[k]
		promWriteHeader(&b, family, "histogram", promHelp(k))
		for i, le := range h.BucketsLE {
			fmt.Fprintf(&b, "%s_bucket{le=\"%s\"} %d\n",
				family, promFormatFloat(le), h.CumulativeCounts[i])
		}
		fmt.Fprintf(&b, "%s_bucket{le=\"+Inf\"} %d\n", family, h.Count)
		fmt.Fprintf(&b, "%s_sum %s\n", family, promFormatFloat(h.SumSeconds))
		fmt.Fprintf(&b, "%s_count %d\n", family, h.Count)
	}
	return b.String()
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
	UptimeSeconds int64                    `json:"uptime_seconds"`
	Goroutines    int                      `json:"goroutines"`
	Counters      map[string]int64         `json:"counters"`
	Gauges        map[string]int64         `json:"gauges"`
	Histograms    map[string]histogramJSON `json:"histograms"`
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
	hists := make(map[string]histogramJSON, len(s.histograms))
	for k, h := range s.histograms {
		hists[k] = h.snapshot()
	}
	return statsJSON{
		UptimeSeconds: int64(time.Since(s.start).Seconds()),
		Goroutines:    runtime.NumGoroutine(),
		Counters:      counters,
		Gauges:        gauges,
		Histograms:    hists,
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
	if len(snap.Histograms) > 0 {
		out += "histograms:\n"
		for _, k := range sortedKeys(snap.Histograms) {
			h := snap.Histograms[k]
			out += fmt.Sprintf("  %s: count=%d sum=%.3fs\n", k, h.Count, h.SumSeconds)
			for i, le := range h.BucketsLE {
				out += fmt.Sprintf("    le=%-8g %d\n", le, h.CumulativeCounts[i])
			}
			out += fmt.Sprintf("    le=%-8s %d\n", "+Inf", h.CumulativeCounts[len(h.CumulativeCounts)-1])
		}
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// readinessCache 给就绪探测加一个很短的结果缓存：多个监控系统同时抓取
// /readyz 时不会把上游 SOCKS 拨号打爆。探测本身有 5s 超时兜底。
type readinessCache struct {
	probe   func() error
	ttl     time.Duration
	mu      sync.Mutex
	last    time.Time
	lastErr error
}

func (rc *readinessCache) check() error {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if !rc.last.IsZero() && time.Since(rc.last) < rc.ttl {
		return rc.lastErr
	}
	err := rc.probe()
	rc.last = time.Now()
	rc.lastErr = err
	return err
}

// startStatsServer 启动只读指标 HTTP 服务。addr 为空表示禁用；
// 绑定失败不致命（端口冲突不应拖垮代理数据面），仅告警并返回 nil。
// 默认 127.0.0.1:18080 只对本机可达；显式绑定 0.0.0.0/:: 会向 LAN 暴露。
// readyCheck 非 nil 时注册 /readyz（对上游做只读协商探测）。
func startStatsServer(addr string, s *stats, readyCheck func() error) *http.Server {
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
	// /healthz：进程与 HTTP 事件循环存活即 200（liveness），不依赖外部组件
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = fmt.Fprintln(w, "ok")
	})
	// /readyz：对上游 SOCKS5 做只读握手探测。探针未配置时明确 503，
	// 而不是落到 "/" 的文本快照让监控拿到假阳性的 200。
	rc := &readinessCache{probe: readyCheck, ttl: 2 * time.Second}
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if readyCheck == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprintln(w, "not ready: readiness probe not configured")
			return
		}
		if err := rc.check(); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprintf(w, "not ready: %v\n", err)
			return
		}
		_, _ = fmt.Fprintln(w, "ready")
	})
	// /conns：存活透明连接实时视图（拨号卡死/长连接排障），不缓存
	mux.HandleFunc("/conns", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = fmt.Fprint(w, s.renderConns(time.Now()))
	})
	// /top：按域名/客户端聚合的累计流量排行
	mux.HandleFunc("/top", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = fmt.Fprint(w, s.renderTop())
	})
	// /metrics：Prometheus 文本 exposition（0.0.4）
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = fmt.Fprint(w, s.renderPrometheus())
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
	log.Printf("stats server listening on %s (GET / /json /healthz /readyz /conns /top /metrics)", ln.Addr())
	return srv
}
