package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	ghdns "github.com/esrrhs/gohome/dns"
	"github.com/miekg/dns"
)

// options 保存全部命令行选项的生效值。定义集中在 defineFlags，因此
// 同一套定义可以在一个临时 FlagSet 上重跑一遍，取出不受配置文件影响
// 的"纯内置默认"——SIGHUP 重读配置文件时用它做优先级回落，默认值
// 不必在两处重复书写。
type options struct {
	socks, socksUser, socksPass         string
	dns, listen                         string
	directDNS                           string
	directDomainsFile, proxyDomainsFile string
	geoipFile                           string
	disableAAAA                         bool
	udpListen, tproxyListen, udpTProxy  string
	statsAddr                           string
	accessLog                           bool
	logFile                             string
	logMaxMB, logBackups                int
	showVersion, pprofEnable            bool
}

// flagPtrs 是 defineFlags 注册的选项指针集合：flag.Parse 之后 deref
// 出 options；同一套定义跑在一个从未 Parse 的临时 FlagSet 上，指针里
// 装的就是纯内置默认值。
type flagPtrs struct {
	socks, socksUser, socksPass         *string
	dns, listen                         *string
	directDNS                           *string
	directDomainsFile, proxyDomainsFile *string
	geoipFile                           *string
	disableAAAA                         *bool
	udpListen, tproxyListen, udpTProxy  *string
	statsAddr                           *string
	accessLog                           *bool
	logFile                             *string
	logMaxMB, logBackups                *int
	showVersion, pprofEnable            *bool
}

// defineFlags 在给定 FlagSet 上注册全部选项。cfg 提供配置文件注入的
// 默认值（命令行显式传参由 flag 包覆盖），传空 config 即可得到内置默认。
func defineFlags(fs *flag.FlagSet, cfg *config) *flagPtrs {
	p := &flagPtrs{}
	p.socks = fs.String("socks", cfg.String("socks", "192.168.1.101:1081"), "upstream socks5")
	fs.String("config", "", "key=value config file supplying flag defaults (comments with #; command line overrides the file; this flag itself is command-line only)")
	p.socksUser = fs.String("socks-user", cfg.String("socks-user", ""), "upstream socks5 username")
	p.socksPass = fs.String("socks-pass", cfg.String("socks-pass", ""), "upstream socks5 password")
	p.dns = fs.String("dns", cfg.String("dns", "[::]:1053"), "dns listen address; wildcard listens dual-stack (v4+v6) and falls back to v4-only if the kernel lacks IPv6")
	p.listen = fs.String("listen", cfg.String("listen", "0.0.0.0:12345"), "transparent redirect listen")
	p.directDNS = fs.String("direct-dns", cfg.String("direct-dns", "223.5.5.5:53,119.29.29.29:53"), "domestic upstream DNS servers (comma-separated)")
	p.directDomainsFile = fs.String("direct-domains-file", cfg.String("direct-domains-file", ""), "optional file containing extra direct domains (e.g. dnsmasq format or line list)")
	p.proxyDomainsFile = fs.String("proxy-domains-file", cfg.String("proxy-domains-file", ""), "optional file containing extra proxy domains (e.g. dnsmasq format or line list)")
	p.geoipFile = fs.String("geoip", cfg.String("geoip", ""), "optional GeoLite2-Country.mmdb path for IP-based CN split routing")
	p.disableAAAA = fs.Bool("disable-aaaa", cfg.Bool("disable-aaaa", true), "answer AAAA queries of proxy domains with empty NOERROR to prevent IPv6 bypass leak")
	p.udpListen = fs.String("udplisten", cfg.String("udplisten", ""), "transparent UDP redirect listen (empty disables UDP relay, e.g. 0.0.0.0:12346; requires matching nat REDIRECT rule)")
	p.tproxyListen = fs.String("tproxy", cfg.String("tproxy", ""), "TCP TPROXY dual-stack listen (e.g. :12345); enables IPv6 interception; requires mangle TPROXY + policy routing; mutually exclusive with -listen")
	p.udpTProxy = fs.String("udp-tproxy", cfg.String("udp-tproxy", ""), "UDP TPROXY dual-stack listen (e.g. :12346); enables IPv6 interception; requires mangle TPROXY + policy routing; mutually exclusive with -udplisten")
	p.statsAddr = fs.String("stats-addr", cfg.String("stats-addr", "127.0.0.1:18080"), "read-only runtime metrics HTTP endpoint (GET / text, /json); empty disables; bind 0.0.0.0/:: at your own risk")
	p.accessLog = fs.Bool("access-log", cfg.Bool("access-log", true), "log one summary line per intercepted TCP connection when it closes (route, up/down bytes, duration, dial error); set -access-log=false to silence")
	p.logFile = fs.String("log-file", cfg.String("log-file", ""), "also append logs to a size-rotating file for post-mortem debugging on the router (empty disables; e.g. /tmp/domain-socks.log)")
	p.logMaxMB = fs.Int("log-max-mb", cfg.Int("log-max-mb", 1), "max size in MB of one log file before it is rotated to .1")
	p.logBackups = fs.Int("log-backups", cfg.Int("log-backups", 3), "number of rotated backup files to keep (.1 newest .. .N oldest)")
	p.showVersion = fs.Bool("version", cfg.Bool("version", false), "print the embedded build version (git commit) and exit")
	p.pprofEnable = fs.Bool("pprof", cfg.Bool("pprof", false), "expose Go runtime pprof diagnostics at /debug/pprof/ on the stats address (goroutine stacks, heap, CPU profile; stats addr defaults to loopback)")
	return p
}

// options 把指针集合解引用成一份普通取值快照。
func (p *flagPtrs) options() *options {
	return &options{
		socks:             derefString(p.socks),
		socksUser:         derefString(p.socksUser),
		socksPass:         derefString(p.socksPass),
		dns:               derefString(p.dns),
		listen:            derefString(p.listen),
		directDNS:         derefString(p.directDNS),
		directDomainsFile: derefString(p.directDomainsFile),
		proxyDomainsFile:  derefString(p.proxyDomainsFile),
		geoipFile:         derefString(p.geoipFile),
		disableAAAA:       derefBool(p.disableAAAA),
		udpListen:         derefString(p.udpListen),
		tproxyListen:      derefString(p.tproxyListen),
		udpTProxy:         derefString(p.udpTProxy),
		statsAddr:         derefString(p.statsAddr),
		accessLog:         derefBool(p.accessLog),
		logFile:           derefString(p.logFile),
		logMaxMB:          derefInt(p.logMaxMB),
		logBackups:        derefInt(p.logBackups),
		showVersion:       derefBool(p.showVersion),
		pprofEnable:       derefBool(p.pprofEnable),
	}
}

func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func derefBool(p *bool) bool {
	if p == nil {
		return false
	}
	return *p
}

func derefInt(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

func main() {
	// 配置文件先行：文件值作为各 flag 的默认注入，命令行显式传参
	// 由 flag 包覆盖 —— 优先级天然是 命令行 > 配置文件 > 内置默认。
	cfgFile, err := loadConfig(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	flagPtrs := defineFlags(flag.CommandLine, cfgFile)
	flag.Parse()
	opts := flagPtrs.options()

	// 配置文件的键必须真实存在、值必须类型正确：路由器上一个拼写错误
	// 就可能让 socks 上游静默回落到内置默认值，等于流量走错方向。
	if err := cfgFile.validate(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	// -version 只输出一行版本信息即退出，不初始化任何服务、不碰日志文件。
	if opts.showVersion {
		fmt.Println("domain-socks version " + readBuildInfo().versionString())
		return
	}

	// 文件日志尽早启用：后续参数校验的 log.Fatal 也要落进文件。
	// 打开失败只告警并退回 stderr-only，与 stats 绑定失败同策略。
	var logWriter *rotatingWriter // 非 nil 时供 SIGHUP reopen
	if opts.logFile != "" {
		if opts.logMaxMB < 1 {
			log.Fatal("-log-max-mb must be >= 1")
		}
		if opts.logBackups < 0 {
			log.Fatal("-log-backups must be >= 0")
		}
		lw, err := newRotatingWriter(opts.logFile, int64(opts.logMaxMB)*1024*1024, opts.logBackups)
		if err != nil {
			log.Printf("warning: open log file %s: %v (continuing with stderr only)", opts.logFile, err)
		} else {
			logWriter = lw
			log.SetOutput(io.MultiWriter(os.Stderr, lw))
			defer lw.Close()
			log.Printf("file logging enabled: %s (rotate at %dMiB, keep %d backups)", opts.logFile, opts.logMaxMB, opts.logBackups)
		}
	}

	// 版本横幅紧跟日志初始化：写入历史日志文件的第一条有效信息就是
	// "跑的是哪个提交"，post-mortem 翻旧日志先确认现场版本。
	binInfo := readBuildInfo()
	log.Printf("domain-socks version %s (go %s)", binInfo.versionString(),
		nonEmpty(binInfo.goVersion, "unknown"))

	// 命令行显式给出的键：优先级最高，SIGHUP 重读配置文件时不允许被
	// 文件覆盖（改文件不该悄悄顶掉管理员在命令行上的决定）。
	listenExplicitlySet := false
	cmdline := map[string]bool{}
	flag.Visit(func(f *flag.Flag) {
		cmdline[f.Name] = true
		if f.Name == "listen" {
			listenExplicitlySet = true
		}
	})
	// 配置文件给出非空 listen 等同于显式指定（它已注入为 flag 默认值，
	// flag.Visit 看不到），互斥校验必须一起算上。
	if !listenExplicitlySet && cfgFile.Has("listen") && opts.listen != "" {
		listenExplicitlySet = true
	}
	if opts.tproxyListen != "" && listenExplicitlySet {
		log.Fatal("-tproxy is mutually exclusive with -listen (choose one TCP interception mode)")
	}
	if opts.udpTProxy != "" && opts.udpListen != "" {
		log.Fatal("-udp-tproxy is mutually exclusive with -udplisten (choose one UDP interception mode)")
	}

	// 内置默认快照：同一套定义在空配置上跑一遍得到。SIGHUP 重读时
	// "文件里删掉的键"据此回落到内置默认，与启动时行为一致。
	builtin := defineFlags(flag.NewFlagSet("builtin-defaults", flag.ContinueOnError),
		&config{vals: map[string]string{}}).options()
	// 当前生效配置：热项（上游/认证/日志开关/规则文件路径）读它，
	// 冷项（监听地址等）只在变更检测时比对。
	rc := newRuntimeConf(newRuntimeOptions(opts))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// 1. 初始化 gohome DNS Resolver 配置
	cfg := ghdns.DefaultConfig()
	cfg.EnableFakeIP = true // 代理域名返回 Fake-IP；国内直连域名返回真实 IP
	if opts.directDNS != "" {
		cfg.DirectUpstreams = strings.Split(opts.directDNS, ",")
	}
	if opts.directDomainsFile != "" {
		cfg.DirectDomainFiles = []string{opts.directDomainsFile}
	}
	if opts.proxyDomainsFile != "" {
		cfg.ProxyDomainFiles = []string{opts.proxyDomainsFile}
	}
	if opts.geoipFile != "" {
		cfg.GeoIPFile = opts.geoipFile
	}
	// 真正需要远端解析的查询（非 A/AAAA 记录、-disable-aaaa=false 时未列入
	// 代理表的域名）会走 gohome 的远程 DoH 上游，而 DoH 必须经 socks 出去：
	// 明文直连 1.1.1.1/8.8.8.8 在国内既不可达（每次等满超时）又是查询泄漏。
	// 上游带认证时 DoH-over-socks5 走不通（见 socksProxyURL），此时直接
	// 禁用远程上游让这些查询回落国内上游，也好过明文直连。
	remoteDoH := "via-socks"
	if url := socksProxyURL(opts.socks, opts.socksUser, opts.socksPass); url != "" {
		cfg.ProxyAddr = url
	} else if opts.socksUser != "" || opts.socksPass != "" {
		cfg.DisableRemoteUpstreams = true
		cfg.RemoteUpstreams = nil
		remoteDoH = "off"
		log.Printf("remote DoH disabled: upstream socks requires auth, which DoH-over-socks5 cannot carry")
	}

	resolver, err := ghdns.NewResolver(cfg)
	if err != nil {
		log.Fatalf("init resolver failed: %v", err)
	}

	// 2. 包装 Resolver：过滤代理域名的 AAAA，防止客户端走真实 IPv6 绕过透明
	// 代理。始终包装一层以便统计 DNS 平面指标；过滤与否每次查询从热配置
	// 读取（SIGHUP 改了 -disable-aaaa 立即生效）。
	appStats := newStats()
	var r ghdns.Resolver = &aaaaFilter{
		Resolver: resolver,
		st:       appStats,
		enabled:  rc.aaaaEnabled,
	}

	// 3. 启动 DNS 服务端（双栈监听，使 v4/v6 的 nat REDIRECT 都能送达）
	dnsServer, dnsBoundAddr, err := startDNS(r, opts.dns)
	if err != nil {
		log.Fatalf("%v", err)
	}

	// 4. 监听透明入向 TCP：REDIRECT（v4，SO_ORIGINAL_DST）或 TPROXY（双栈）
	var (
		ln    net.Listener
		lnErr error
	)
	tcpMode := "redirect"
	if opts.tproxyListen != "" {
		ln, lnErr = startTCPTProxy(opts.tproxyListen)
		tcpMode = "tproxy"
	} else {
		ln, lnErr = net.Listen("tcp", opts.listen)
	}
	if lnErr != nil {
		log.Fatalf("listen tcp failed: %v", lnErr)
	}

	// 5. UDP 透明转发（默认关闭）：REDIRECT（v4）或 TPROXY（双栈），
	// 需配合对应防火墙规则显式启用
	gw := newUDPGateway(r, opts.socks, opts.socksUser, opts.socksPass)
	gw.setStats(appStats)
	appStats.registerGauges(map[string]func() int64{
		"udp_active_clients": func() int64 { n, _ := gw.activeCounts(); return n },
		"udp_active_flows":   func() int64 { _, n := gw.activeCounts(); return n },
		"udp_assoc_up":       gw.proxy.assocIsUp,
	})
	// /readyz 对上游 SOCKS5 做只读握手探测（不发 CONNECT，无目标流量）；
	// 每次探测读热配置，换了上游后探针也跟着指向新上游。
	readyCheck := func() error {
		hs := rc.get()
		return probeSocksUpstream(hs.socks, hs.socksUser, hs.socksPass)
	}
	statsSrv := startStatsServer(opts.statsAddr, appStats, readyCheck, opts.pprofEnable)

	// SIGHUP 热重载：①重读配置文件（热项立即生效，冷项提示需重启）
	// ②重新打开日志文件（外部 logrotate）③全量重载分流域名表/GeoIP、
	// 清 DNS 缓存；不重建监听、不中断在途连接。
	hupCh := notifyReload()
	defer stopReload(hupCh)
	go func() {
		for range hupCh {
			if cfgFile.path != "" {
				prev := rc.get()
				next, changed, cold, err := reloadRuntimeOptions(cfgFile.path, cmdline, builtin, prev)
				if err != nil {
					// 文件写坏了就保持旧配置：绝不能让一次 SIGHUP
					// 把正在跑的代理变成没有上游。
					log.Printf("SIGHUP reload: config %s not applied: %v", cfgFile.path, err)
				} else {
					rc.set(next)
					if len(changed) > 0 {
						log.Printf("SIGHUP reload: applied %s", strings.Join(changed, ", "))
					}
					if len(cold) > 0 {
						log.Printf("SIGHUP reload: %s changed but need a restart to take effect",
							strings.Join(cold, ", "))
					}
					if next.socks != prev.socks || next.socksUser != prev.socksUser ||
						next.socksPass != prev.socksPass {
						// UDP 侧已建立的 ASSOCIATE 属于旧上游，必须作废
						// 重建；TCP 侧本就是每连接读快照，天然生效。
						// resolver 的远程 DoH 也一并指向新代理。
						if err := applyUpstream(gw, resolver, next.socks, next.socksUser, next.socksPass); err != nil {
							log.Printf("SIGHUP reload: remote DNS proxy not updated: %v", err)
						}
						log.Printf("SIGHUP reload: upstream now %s (%s)",
							next.socks, describeAuth(next.socksUser))
						if next.socksUser != "" || next.socksPass != "" {
							log.Printf("SIGHUP reload: upstream needs auth, remote DoH keeps the previous proxy until restart")
						}
					}
				}
			}
			hs := rc.get()
			summary, rerr := reloadConfig(logWriter, resolver,
				hs.directDomainsFile, hs.proxyDomainsFile, hs.geoipFile)
			if rerr != nil {
				log.Printf("SIGHUP reload finished with errors: %s (%v)", summary, rerr)
				continue
			}
			log.Printf("SIGHUP %s", summary)
		}
	}()

	gwCtx, gwCancel := context.WithCancel(context.Background())
	defer gwCancel()
	go gw.run(gwCtx)

	var stopUDP func()
	udpMode := "off"
	switch {
	case opts.udpTProxy != "":
		stop, err := startUDPTProxy(opts.udpTProxy, gw)
		if err != nil {
			log.Fatalf("start udp tproxy on %s failed: %v", opts.udpTProxy, err)
		}
		stopUDP = stop
		udpMode = "tproxy=" + opts.udpTProxy
		log.Printf("udp relay enabled: udp-tproxy=%s -> socks=%s", opts.udpTProxy, opts.socks)
	case opts.udpListen != "":
		stop, err := startUDPFrontend(opts.udpListen, gw)
		if err != nil {
			log.Fatalf("start udp frontend on %s failed: %v", opts.udpListen, err)
		}
		stopUDP = stop
		udpMode = "redirect=" + opts.udpListen
		log.Printf("udp relay enabled: udplisten=%s -> socks=%s", opts.udpListen, opts.socks)
	}

	tcpListenDesc := opts.listen
	if opts.tproxyListen != "" {
		tcpListenDesc = opts.tproxyListen
	}
	log.Printf("domain-socks started: socks=%s dns=%s tcp(%s)=%s aaaa-filter=%v udp=%s",
		opts.socks, dnsBoundAddr, tcpMode, tcpListenDesc, opts.disableAAAA, udpMode)
	// 生效配置单行回显（与上面的版本行一起写进历史日志），排查"配置没生效"
	// 类问题时不用翻 init 脚本；只回显是否有认证与用户名，绝不输出密码。
	statsOpt := nonEmpty(opts.statsAddr, "off")
	// remote-doh：需要真实远端解析的查询走远程 DoH 时的出口。
	log.Printf("config: file=%s auth=%s remote-doh=%s direct-dns=%q stats=%s pprof=%v access-log=%v geoip=%s lists direct=%q proxy=%q",
		nonEmpty(cfgFile.path, "none"),
		describeAuth(opts.socksUser), remoteDoH, opts.directDNS, statsOpt, opts.pprofEnable, opts.accessLog,
		nonEmpty(opts.geoipFile, "off"),
		nonEmpty(opts.directDomainsFile, "-"), nonEmpty(opts.proxyDomainsFile, "-"))

	// REDIRECT 模式需 SO_ORIGINAL_DST 反查（v4）；TPROXY 不做 NAT，
	// 已 accept 连接的 LocalAddr 即原始目标（天然支持 v4/v6）。
	dstOf := originalDst
	if opts.tproxyListen != "" {
		dstOf = localDst
	}

	var wg sync.WaitGroup
	active := newConnRegistry()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// 同步登记（在 go 之前），关闭扫描时不会漏掉已 accept
			// 但尚未调度的连接。
			active.add(c)
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer active.remove(c)
				// 每条连接开始时读一次热配置快照：整条连接用同一份
				// 上游与认证，中途 SIGHUP 不会撕裂已建连的连接。
				hs := rc.get()
				handleConn(c, r, hs.socks, hs.socksUser, hs.socksPass, dstOf, appStats, hs.accessLog)
			}()
		}
	}()

	// 6. 等待退出信号并优雅关闭
	<-ctx.Done()
	log.Printf("shutdown signal received, draining connections...")
	// 第二个 SIGINT/SIGTERM：放弃排空立即退出（procd 的 SIGKILL 兜底同理）
	hardExit := make(chan os.Signal, 1)
	signal.Notify(hardExit, syscall.SIGINT, syscall.SIGTERM)
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

	// 两阶段排空：宽限期内让短请求自然结束；随后强关仍存活的连接，
	// 使 handleConn 的统计/日志 defer 在进程退出前执行落账。
	drained, hard := waitForShutdown(&wg, active, hardExit)
	if drained {
		log.Printf("shutdown complete: all in-flight connections drained")
	}
	_ = resolver.Close()
	if hard {
		// 第二个 SIGTERM/SIGINT：管理员明确要求立即退出
		os.Exit(1)
	}
	// drained=false（预算耗尽放弃卡死连接）仍以 0 退出：进程是被
	// SIGTERM 礼貌关停的，不应被 procd 记为一次崩溃。
}

// aaaaFilter 包装 gohome Resolver，承担两件事：
//  1. enabled 时对判定走代理的域名，AAAA 查询直接返回空 NOERROR，迫使客户端
//     回退到 A 记录（Fake-IP），避免拿到真实 IPv6 后绕过透明代理泄漏；
//     直连域名的 AAAA 正常透传，保留国内双栈。ShouldProxy 出错按代理处理。
//  2. DNS 平面指标：查询总数、AAAA 数、拦截数、Fake-IP 应答数、上游错误数。
//
// enabled 是函数而非常量：SIGHUP 改了 -disable-aaaa 后下一个查询即按新
// 值处理，不必重启（DNS 是查询级无状态路径，中途切换是安全的）。
type aaaaFilter struct {
	ghdns.Resolver
	st      *stats
	enabled func() bool
}

func (f *aaaaFilter) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	f.st.inc(statDNSQueries)
	if req != nil && len(req.Question) > 0 && req.Question[0].Qtype == dns.TypeAAAA {
		f.st.inc(statDNSAAAA)
		name := strings.TrimSuffix(req.Question[0].Name, ".")
		if f.enabled != nil && f.enabled() {
			if proxy, _ := f.Resolver.ShouldProxy(name); proxy {
				f.st.inc(statDNSAAAAFiltered)
				resp := new(dns.Msg)
				resp.SetReply(req)
				return resp, nil
			}
		}
	}
	// 仅真实上游往返进延迟直方图；AAAA 本地短路在上方已返回。
	// 成功与失败都记录：慢超时正是 DNS 平面劣化信号。
	dnsStart := time.Now()
	resp, err := f.Resolver.Exchange(ctx, req)
	f.st.observe(histDNSUpstreamSeconds, time.Since(dnsStart))
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

// countingConn 包装 net.Conn，累计 Write 成功字节数。每连接使用独立
// atomic.Int64：转发 goroutine 写入，/conns 快照可在连接存活期间并发读取。
// io.Copy 每块（32KiB）仅一次原子 Add，开销可忽略。
type countingConn struct {
	net.Conn
	n *atomic.Int64
}

func (c countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.n.Add(int64(n))
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
		upB     atomic.Int64 // 客户端 -> 远端
		downB   atomic.Int64 // 远端 -> 客户端
	)
	// 统一的连接结束日志 + 字节汇总（defer 先于 c.Close() 执行；
	// 此时双向 copy goroutine 已退出，Load 仅为与 /conns 读端统一口径）
	defer func() {
		up, down := upB.Load(), downB.Load()
		if accessLog {
			log.Print(formatConnLine(client, target, via, up, down, time.Since(start), dialErr))
		}
		switch via {
		case "socks":
			st.add(statTCPProxyBytesUp, up)
			st.add(statTCPProxyBytesDown, down)
			// 连接存活时长（accept→关闭，含拨号），dst-fail/captive204 不进
			st.observe(histTCPProxyConnSeconds, time.Since(start))
		case "direct":
			st.add(statTCPDirectBytesUp, up)
			st.add(statTCPDirectBytesDown, down)
			st.observe(histTCPDirectConnSeconds, time.Since(start))
		}
		// /top 聚合：按目标域名(或 IP)与客户端 IP 各记一次
		targetHost, _, _ := net.SplitHostPort(target)
		clientHost, _, _ := net.SplitHostPort(client)
		st.recordFlow(targetHost, clientHost, via, up, down)
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

	// 展示用 target 提前换成嗅探/还原到的域名；直连拨号仍用原始 ip:port，
	// 行为不变（经 SOCKS 的连接本就单独传 domain）。
	dialTarget := target
	if domain != "" {
		target = net.JoinHostPort(domain, fmt.Sprintf("%d", dstPort))
	}
	dialVia := "direct"
	if shouldProxy {
		dialVia = "socks"
	}
	// 登记到 GET /conns：拨号阶段即可见（卡住的拨号是首要排障对象），
	// 连接结束（含拨号失败/ dst 反查失败之后的各 return）统一注销。
	ci, unregisterConn := st.trackConn(client, target, dialVia, &upB, &downB)
	defer unregisterConn()

	if shouldProxy {
		via = "socks"
		// 成功与失败都进直方图：慢失败（超时）本身就是上游劣化信号
		dialStart := time.Now()
		up, err = socksConnect(proxy, domain, dstIP, dstPort, socksUser, socksPass)
		st.observe(histTCPProxyDialSeconds, time.Since(dialStart))
		if err != nil {
			st.inc(statTCPSocksFail)
			dialErr = err
			return
		}
		st.inc(statTCPProxy)
	} else {
		// 直连直达
		via = "direct"
		dialStart := time.Now()
		up, err = net.DialTimeout("tcp", dialTarget, 8*time.Second)
		st.observe(histTCPDirectDialSeconds, time.Since(dialStart))
		if err != nil {
			st.inc(statTCPDirectFail)
			dialErr = err
			return
		}
		st.inc(statTCPDirect)
	}
	defer up.Close()
	ci.setState("forward")

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
