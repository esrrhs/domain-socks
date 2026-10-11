package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	ghdns "github.com/esrrhs/gohome/dns"
	"github.com/miekg/dns"
)

// shutdownDrainTimeout 限制优雅退出时等待在途连接收尾的最长时间
const shutdownDrainTimeout = 3 * time.Second

func main() {
	socks := flag.String("socks", "192.168.1.101:1081", "upstream socks5")
	socksUser := flag.String("socks-user", "", "upstream socks5 username")
	socksPass := flag.String("socks-pass", "", "upstream socks5 password")
	dnsAddr := flag.String("dns", "[::]:1053", "dns listen address; wildcard listens dual-stack (v4+v6) and falls back to v4-only if the kernel lacks IPv6")
	listen := flag.String("listen", "0.0.0.0:12345", "transparent redirect listen")
	directDNS := flag.String("direct-dns", "223.5.5.5:53,119.29.29.29:53", "domestic upstream DNS servers (comma-separated)")
	directDomainsFile := flag.String("direct-domains-file", "", "optional file containing extra direct domains (e.g. dnsmasq format or line list)")
	proxyDomainsFile := flag.String("proxy-domains-file", "", "optional file containing extra proxy domains (e.g. dnsmasq format or line list)")
	geoipFile := flag.String("geoip", "", "optional GeoLite2-Country.mmdb path for IP-based CN split routing")
	disableAAAA := flag.Bool("disable-aaaa", true, "answer AAAA queries of proxy domains with empty NOERROR to prevent IPv6 bypass leak")
	udpListen := flag.String("udplisten", "", "transparent UDP redirect listen (empty disables UDP relay, e.g. 0.0.0.0:12346; requires matching nat REDIRECT rule)")
	tproxyListen := flag.String("tproxy", "", "TCP TPROXY dual-stack listen (e.g. :12345); enables IPv6 interception; requires mangle TPROXY + policy routing; mutually exclusive with -listen")
	udpTProxy := flag.String("udp-tproxy", "", "UDP TPROXY dual-stack listen (e.g. :12346); enables IPv6 interception; requires mangle TPROXY + policy routing; mutually exclusive with -udplisten")
	statsAddr := flag.String("stats-addr", "127.0.0.1:18080", "read-only runtime metrics HTTP endpoint (GET / text, /json); empty disables; bind 0.0.0.0/:: at your own risk")
	accessLog := flag.Bool("access-log", true, "log one summary line per intercepted TCP connection when it closes (route, up/down bytes, duration, dial error); set -access-log=false to silence")
	flag.Parse()

	listenExplicitlySet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "listen" {
			listenExplicitlySet = true
		}
	})
	if *tproxyListen != "" && listenExplicitlySet {
		log.Fatal("-tproxy is mutually exclusive with -listen (choose one TCP interception mode)")
	}
	if *udpTProxy != "" && *udpListen != "" {
		log.Fatal("-udp-tproxy is mutually exclusive with -udplisten (choose one UDP interception mode)")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// 1. 初始化 gohome DNS Resolver 配置
	cfg := ghdns.DefaultConfig()
	cfg.EnableFakeIP = true // 代理域名返回 Fake-IP；国内直连域名返回真实 IP
	if *directDNS != "" {
		cfg.DirectUpstreams = strings.Split(*directDNS, ",")
	}
	if *directDomainsFile != "" {
		cfg.DirectDomainFiles = []string{*directDomainsFile}
	}
	if *proxyDomainsFile != "" {
		cfg.ProxyDomainFiles = []string{*proxyDomainsFile}
	}
	if *geoipFile != "" {
		cfg.GeoIPFile = *geoipFile
	}

	resolver, err := ghdns.NewResolver(cfg)
	if err != nil {
		log.Fatalf("init resolver failed: %v", err)
	}

	// 2. 包装 Resolver：过滤代理域名的 AAAA，防止客户端走真实 IPv6 绕过透明
	// 代理。始终包装一层以便统计 DNS 平面指标；过滤与否由 enabled 控制。
	appStats := newStats()
	var r ghdns.Resolver = &aaaaFilter{
		Resolver: resolver,
		st:       appStats,
		enabled:  *disableAAAA,
	}

	// 3. 启动 DNS 服务端（双栈监听，使 v4/v6 的 nat REDIRECT 都能送达）
	dnsServer, dnsBoundAddr, err := startDNS(r, *dnsAddr)
	if err != nil {
		log.Fatalf("%v", err)
	}

	// 4. 监听透明入向 TCP：REDIRECT（v4，SO_ORIGINAL_DST）或 TPROXY（双栈）
	var (
		ln    net.Listener
		lnErr error
	)
	tcpMode := "redirect"
	if *tproxyListen != "" {
		ln, lnErr = startTCPTProxy(*tproxyListen)
		tcpMode = "tproxy"
	} else {
		ln, lnErr = net.Listen("tcp", *listen)
	}
	if lnErr != nil {
		log.Fatalf("listen tcp failed: %v", lnErr)
	}

	// 5. UDP 透明转发（默认关闭）：REDIRECT（v4）或 TPROXY（双栈），
	// 需配合对应防火墙规则显式启用
	gw := newUDPGateway(r, *socks, *socksUser, *socksPass)
	gw.setStats(appStats)
	appStats.registerGauges(map[string]func() int64{
		"udp_active_clients": func() int64 { n, _ := gw.activeCounts(); return n },
		"udp_active_flows":   func() int64 { _, n := gw.activeCounts(); return n },
		"udp_assoc_up":       gw.proxy.assocIsUp,
	})
	// /readyz 对上游 SOCKS5 做只读握手探测（不发 CONNECT，无目标流量）
	readyCheck := func() error {
		return probeSocksUpstream(*socks, *socksUser, *socksPass)
	}
	statsSrv := startStatsServer(*statsAddr, appStats, readyCheck)

	gwCtx, gwCancel := context.WithCancel(context.Background())
	defer gwCancel()
	go gw.run(gwCtx)

	var stopUDP func()
	udpMode := "off"
	switch {
	case *udpTProxy != "":
		stop, err := startUDPTProxy(*udpTProxy, gw)
		if err != nil {
			log.Fatalf("start udp tproxy on %s failed: %v", *udpTProxy, err)
		}
		stopUDP = stop
		udpMode = "tproxy=" + *udpTProxy
		log.Printf("udp relay enabled: udp-tproxy=%s -> socks=%s", *udpTProxy, *socks)
	case *udpListen != "":
		stop, err := startUDPFrontend(*udpListen, gw)
		if err != nil {
			log.Fatalf("start udp frontend on %s failed: %v", *udpListen, err)
		}
		stopUDP = stop
		udpMode = "redirect=" + *udpListen
		log.Printf("udp relay enabled: udplisten=%s -> socks=%s", *udpListen, *socks)
	}

	tcpListenDesc := *listen
	if *tproxyListen != "" {
		tcpListenDesc = *tproxyListen
	}
	log.Printf("domain-socks started: socks=%s dns=%s tcp(%s)=%s aaaa-filter=%v udp=%s",
		*socks, dnsBoundAddr, tcpMode, tcpListenDesc, *disableAAAA, udpMode)

	// REDIRECT 模式需 SO_ORIGINAL_DST 反查（v4）；TPROXY 不做 NAT，
	// 已 accept 连接的 LocalAddr 即原始目标（天然支持 v4/v6）。
	dstOf := originalDst
	if *tproxyListen != "" {
		dstOf = localDst
	}

	var wg sync.WaitGroup
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				handleConn(c, r, *socks, *socksUser, *socksPass, dstOf, appStats, *accessLog)
			}()
		}
	}()

	// 6. 等待退出信号并优雅关闭
	<-ctx.Done()
	log.Printf("shutdown signal received, draining connections...")
	if stopUDP != nil {
		stopUDP()
	}
	gwCancel()
	gw.Close()
	if statsSrv != nil {
		_ = statsSrv.Close()
	}
	_ = ln.Close()
	_ = dnsServer.Stop()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(shutdownDrainTimeout):
		log.Printf("drain timeout (%v), forcing exit with active connections", shutdownDrainTimeout)
	}
	_ = resolver.Close()
}

// aaaaFilter 包装 gohome Resolver，承担两件事：
//  1. enabled 时对判定走代理的域名，AAAA 查询直接返回空 NOERROR，迫使客户端
//     回退到 A 记录（Fake-IP），避免拿到真实 IPv6 后绕过透明代理泄漏；
//     直连域名的 AAAA 正常透传，保留国内双栈。ShouldProxy 出错按代理处理。
//  2. DNS 平面指标：查询总数、AAAA 数、拦截数、Fake-IP 应答数、上游错误数。
type aaaaFilter struct {
	ghdns.Resolver
	st      *stats
	enabled bool
}

func (f *aaaaFilter) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	f.st.inc(statDNSQueries)
	if req != nil && len(req.Question) > 0 && req.Question[0].Qtype == dns.TypeAAAA {
		f.st.inc(statDNSAAAA)
		name := strings.TrimSuffix(req.Question[0].Name, ".")
		if f.enabled {
			if proxy, _ := f.Resolver.ShouldProxy(name); proxy {
				f.st.inc(statDNSAAAAFiltered)
				resp := new(dns.Msg)
				resp.SetReply(req)
				return resp, nil
			}
		}
	}
	resp, err := f.Resolver.Exchange(ctx, req)
	if err != nil {
		f.st.inc(statDNSErrors)
		return nil, err
	}
	// Fake-IP 是分流劫持实际生效的证据：任一 A 记录命中 Fake-IP 段即计一次
	if resp != nil {
		for _, rr := range resp.Answer {
			if a, ok := rr.(*dns.A); ok && f.Resolver.IsFakeIP(a.A) {
				f.st.inc(statDNSFakeIP)
				break
			}
		}
	}
	return resp, nil
}

// dstResolver 从已截获的连接上取原始目标：REDIRECT 用 SO_ORIGINAL_DST
// （redirect_linux.go），TPROXY 直接读 LocalAddr。
type dstResolver func(c net.Conn) (net.IP, int, error)

// localDst 用于 TPROXY：TPROXY 不做 NAT，accept 连接的本地端地址
// 就是客户端最初访问的目标。v4-mapped 统一成 4 字节 v4。
func localDst(c net.Conn) (net.IP, int, error) {
	ta, ok := c.LocalAddr().(*net.TCPAddr)
	if !ok || ta == nil {
		return nil, 0, fmt.Errorf("local dst: unexpected addr type %T", c.LocalAddr())
	}
	return canonicalIP(ta.IP), ta.Port, nil
}

// countingConn 包装 net.Conn，累计 Write 成功字节数。每个连接使用独立的
// *int64，且两个方向各由一个固定 goroutine 写入，无需原子操作。
type countingConn struct {
	net.Conn
	n *int64
}

func (c countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	*c.n += int64(n)
	return n, err
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.2fGiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.2fMiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1fKiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%dB", n)
	}
}

// formatConnLine 生成连接结束时的一行访问日志。via 为路由标签
// （socks/direct/captive204/dst-fail）；dialErr 非 nil 表示建连失败。
func formatConnLine(client, target, via string, up, down int64, d time.Duration, dialErr error) string {
	line := fmt.Sprintf("tcp %s -> %s via %s up %s down %s in %s",
		client, target, via, humanBytes(up), humanBytes(down), d.Round(time.Millisecond))
	if dialErr != nil {
		line += " fail: " + dialErr.Error()
	}
	return line
}

func handleConn(c net.Conn, resolver ghdns.Resolver, proxy string, socksUser string, socksPass string, dstOf dstResolver, st *stats, accessLog bool) {
	defer c.Close()
	st.inc(statTCPAccepted)
	st.tcpConnOpened()
	defer st.tcpConnClosed()

	client := c.RemoteAddr().String()
	start := time.Now()
	var (
		target  = "unknown"
		via     string
		dialErr error
		upB     int64 // 客户端 -> 远端
		downB   int64 // 远端 -> 客户端
	)
	// 统一的连接结束日志 + 字节汇总（defer 先于 c.Close() 执行）
	defer func() {
		if accessLog {
			log.Print(formatConnLine(client, target, via, upB, downB, time.Since(start), dialErr))
		}
		switch via {
		case "socks":
			st.add(statTCPProxyBytesUp, upB)
			st.add(statTCPProxyBytesDown, downB)
		case "direct":
			st.add(statTCPDirectBytesUp, upB)
			st.add(statTCPDirectBytesDown, downB)
		}
	}()

	dstIP, dstPort, err := dstOf(c)
	if err != nil {
		via = "dst-fail"
		st.inc(statTCPDstFail)
		dialErr = err
		return
	}
	dstIP = canonicalIP(dstIP)
	target = net.JoinHostPort(dstIP.String(), fmt.Sprintf("%d", dstPort))

	isFake := resolver.IsFakeIP(dstIP)
	var domain string
	if isFake {
		domain, _ = resolver.LookupDomainByFakeIP(dstIP)
	}

	var prefix []byte
	// 如果无法通过 fake-ip 确定域名，或者目标是 HTTP 80 端口，尝试嗅探应用层报文
	if domain == "" || dstPort == 80 {
		var sniffed string
		prefix, sniffed = peekHost(c)
		if domain == "" {
			domain = sniffed
		}
	}

	// 针对网络连通性探测 (Captive portal probe) 快速响应 204
	if dstPort == 80 && captiveProbe(prefix, domain) {
		via = "captive204"
		st.inc(statTCPCaptive)
		_, _ = c.Write([]byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		return
	}

	// 判断是否走代理分流：
	// 1. 若目标 IP 是 Fake-IP，或者域名/IP 经 resolver.ShouldProxy 判定需要走代理 -> 走 SOCKS5
	// 2. 若不是 Fake-IP 且属于直连目标 -> 直接 net.Dial 目标真实地址直连
	shouldProxy := isFake
	if !shouldProxy {
		host := domain
		if host == "" {
			host = dstIP.String()
		}
		sp, _ := resolver.ShouldProxy(host)
		shouldProxy = sp
	}

	var up net.Conn

	if shouldProxy {
		via = "socks"
		up, err = socksConnect(proxy, domain, dstIP, dstPort, socksUser, socksPass)
		if err != nil {
			st.inc(statTCPSocksFail)
			dialErr = err
			return
		}
		st.inc(statTCPProxy)
	} else {
		// 直连直达
		via = "direct"
		up, err = net.DialTimeout("tcp", target, 8*time.Second)
		if err != nil {
			st.inc(statTCPDirectFail)
			dialErr = err
			return
		}
		st.inc(statTCPDirect)
	}
	defer up.Close()

	// 嗅探到域名后，访问日志用域名而非 IP/Fake-IP
	if domain != "" {
		target = net.JoinHostPort(domain, fmt.Sprintf("%d", dstPort))
	}

	upConn := countingConn{Conn: up, n: &upB}
	downConn := countingConn{Conn: c, n: &downB}
	if len(prefix) > 0 {
		if _, err = upConn.Write(prefix); err != nil {
			return
		}
	}

	setKeepAlive(c)
	setKeepAlive(up)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upConn, c)
		closeWrite(up)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(downConn, upConn)
		closeWrite(c)
	}()
	wg.Wait()
}

func isCaptiveHost(host string) bool {
	h := strings.ToLower(strings.Trim(host, "."))
	if h == "" {
		return false
	}
	probes := []string{
		"connectivitycheck.gstatic.com",
		"connectivitycheck.android.com",
		"clients3.google.com",
		"play.googleapis.com",
		"connect.rom.miui.com",
		"wifi.vivo.com.cn",
		"captive.apple.com",
		"detectportal.firefox.com",
	}
	for _, p := range probes {
		if h == p || strings.HasSuffix(h, "."+p) {
			return true
		}
	}
	return false
}

func captiveProbe(prefix []byte, domain string) bool {
	if isCaptiveHost(domain) {
		return true
	}
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
	path = strings.ToLower(path)
	switch path {
	case "/generate_204", "/gen_204", "/ncsi.txt", "/connecttest.txt",
		"/hotspot-detect.html", "/canonical.html", "/success.txt", "/check_network_status.txt":
		return true
	}
	return false
}

// dnsListenCandidates 返回 DNS 监听地址的尝试顺序。
// 通配配置（host 为空 / "::" / "0.0.0.0"）优先绑定 [::]:port：Linux/macOS
// 默认双栈语义下这一个 socket 同时接收 v4 与 v6（v4 以 v4-mapped 到达），
// 可同时接住两族 nat REDIRECT 转来的 DNS 报文；内核无 IPv6 栈时绑定失败，
// 回退 v4 通配。显式指定的具体地址（如 127.0.0.1）原样使用，不扩大范围。
func dnsListenCandidates(addr string) []string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return []string{addr}
	}
	switch host {
	case "", "::", "0.0.0.0":
		return []string{net.JoinHostPort("::", port), net.JoinHostPort("0.0.0.0", port)}
	default:
		return []string{addr}
	}
}

// startDNS 按 dnsListenCandidates 的顺序尝试启动 DNS 服务，
// 返回成功运行的 server 与其实际绑定地址。
func startDNS(r ghdns.Resolver, addr string) (*ghdns.Server, string, error) {
	candidates := dnsListenCandidates(addr)
	var errs []string
	for _, candidate := range candidates {
		srv := ghdns.NewServer(candidate, r)
		if err := srv.Start(); err == nil {
			log.Printf("dns server listening on %s (udp+tcp)", candidate)
			return srv, candidate, nil
		} else {
			errs = append(errs, fmt.Sprintf("%s: %v", candidate, err))
		}
	}
	return nil, "", fmt.Errorf("start dns server failed (%s)", strings.Join(errs, "; "))
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

// peekHost 在有限时间内读取连接前缀，尝试嗅探 TLS SNI 或 HTTP Host。
// 采用循环读取以容忍 ClientHello / HTTP 请求头的 TCP 分段；一旦能确定
// 域名、或确认数据不属于 HTTP(S)、或等待超时，立即返回，避免给 SSH 等
// "服务器先说话"协议增加固定延迟。返回的 prefix 是已读全部字节，
// 调用方必须原样转发给上游，不能丢字节。
func peekHost(c net.Conn) ([]byte, string) {
	_ = c.SetReadDeadline(time.Now().Add(sniffTimeout))
	defer c.SetReadDeadline(time.Time{})

	var prefix []byte
	buf := make([]byte, 2048)
	for len(prefix) < sniffMaxBytes {
		n, err := c.Read(buf)
		if n > 0 {
			prefix = append(prefix, buf[:n]...)
			if host := sniffHost(prefix); host != "" {
				return prefix, strings.TrimSuffix(strings.ToLower(host), ".")
			}
			if sniffConclusive(prefix) {
				return prefix, ""
			}
		}
		if err != nil {
			break
		}
	}
	return prefix, ""
}
