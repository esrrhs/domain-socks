package main

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	ghdns "github.com/esrrhs/gohome/dns"
)

const (
	udpMaxPacket = 65535
	// udpFlowIdle 是单个目标会话的空闲超时；udpClientIdle 是 LAN 客户端
	// 会话（含还原原始目标用的 probe socket）的空闲超时
	udpFlowIdle   = 2 * time.Minute
	udpClientIdle = 3 * time.Minute
	udpSweep      = 30 * time.Second
	// udpAssocTimeout 限制建立 UDP ASSOCIATE 控制连接与握手的时长
	udpAssocTimeout = 10 * time.Second
	// udpAssocCooldown 是建连（拨号/握手）失败后的冷却期：冷却期内
	// 新包快速失败而不是再次堆积一个 10s 握手窗口。服务器正常断连触发
	// 的 teardown 不进入冷却，下一包立即重连。
	udpAssocCooldown = 3 * time.Second
	// udpFwdFailLogInterval 限制代理不可用时转发失败日志的频率，
	// 高包率 UDP 流（游戏/语音）下避免重复错误刷屏
	udpFwdFailLogInterval = 2 * time.Second
)

// udpClient 表示一个 LAN 侧 UDP 会话（由客户端源地址唯一标识）。
// 仅持有平台资源的释放回调（REDIRECT 模式下是关闭 per-client probe
// socket）；回包闭包与目标相关，挂在 udpFlow 上而不是这里。
type udpClient struct {
	addr     string
	release  func()
	lastSeen time.Time
}

// udpFlow 是一条 (客户端 -> 目标) UDP 流向记录。上游回包按目标地址反查
// 到对应 flow，再经 flow.reply 回送——TPROXY 模式下该闭包绑定本目标的
// 透明发送 socket，因此同一客户端并发访问多个目标时回包不会串台。
// 同一目标被多个客户端访问时以后到者为准（UDP 无连接，SOCKS5 回包只
// 携带目标地址，无法区分来源）。
type udpFlow struct {
	clientKey string
	target    string // host:port，与上游回包头中的地址严格一致
	reply     func([]byte) error
	created   time.Time
	lastSeen  time.Time

	// /top 聚合在 flow 过期/关闭时一次性 flush（非每包加锁）：
	// host 是还原出的域名或目标 IP，via 为 socks/direct，
	// up/down 仅统计成功转发/成功回送的载荷字节。
	host     string
	via      string
	up, down int64
}

// udpGateway 串起平台无关的数据面：分流判定 -> 代理/直连 relay ->
// NAT 回映射。平台层（Linux REDIRECT / 测试桩）只需调用 handle。
type udpGateway struct {
	resolver ghdns.Resolver
	proxy    *udpProxyRelay
	direct   *udpDirectRelay
	stats    *stats

	mu             sync.Mutex
	clients        map[string]*udpClient
	flows          map[string]*udpFlow
	lastFwdFailLog time.Time
	closed         bool
}

func newUDPGateway(resolver ghdns.Resolver, proxyAddr, user, pass string) *udpGateway {
	g := &udpGateway{
		resolver: resolver,
		clients:  make(map[string]*udpClient),
		flows:    make(map[string]*udpFlow),
	}
	g.proxy = newUDPProxyRelay(proxyAddr, user, pass, g.onProxyPacket)
	g.direct = newUDPDirectRelay(g.onDirectPacket)
	return g
}

// setStats 绑定运行时指标（nil 安全，不绑定时所有埋点为空操作）
func (g *udpGateway) setStats(s *stats) {
	g.stats = s
	g.proxy.stats = s
}

// setUpstream 热替换上游 SOCKS5 地址与认证：SIGHUP 重读配置文件发现
// socks/socks-user/socks-pass 变了时调用。已在途的 UDP 会话所在连接
// 不受影响，新会话（及旧 ASSOCIATE 重建）走新上游。
func (g *udpGateway) setUpstream(proxyAddr, user, pass string) {
	g.proxy.setUpstream(proxyAddr, user, pass)
}

// run 启动空闲会话回收。返回前阻塞直到 ctx 取消。
func (g *udpGateway) run(ctx context.Context) {
	ticker := time.NewTicker(udpSweep)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			g.sweep()
		}
	}
}

func (g *udpGateway) sweep() {
	var releases []func()
	var flushed []*udpFlow
	g.mu.Lock()
	now := time.Now()
	for key, f := range g.flows {
		if now.Sub(f.lastSeen) > udpFlowIdle {
			delete(g.flows, key)
			flushed = append(flushed, f)
		}
	}
	for key, c := range g.clients {
		if now.Sub(c.lastSeen) > udpClientIdle {
			delete(g.clients, key)
			if c.release != nil {
				releases = append(releases, c.release)
			}
		}
	}
	g.mu.Unlock()
	g.flushFlowStats(flushed)
	for _, r := range releases {
		r()
	}
}

// clientHostFromKey 从 clientKey（生产环境为 ip:port）提取客户端 IP；
// 测试桩等无端口形式原样返回，保证客户端聚合始终有键。
func clientHostFromKey(key string) string {
	if host, _, err := net.SplitHostPort(key); err == nil {
		return host
	}
	return key
}

// flushFlowStats 把已终结（过期/网关关闭）的 UDP flow 累计值写入 /top
// 聚合，每个 flow 只写一次。零流量 flow（建在转发失败前）不产生记录，
// 与 TCP 拨号失败不聚合的口径一致；存活时长直方图走同一道闸门。
func (g *udpGateway) flushFlowStats(flows []*udpFlow) {
	for _, f := range flows {
		if f.up == 0 && f.down == 0 {
			continue
		}
		g.stats.observe(histUDPFlowSeconds, time.Since(f.created))
		g.stats.recordFlow(f.host, clientHostFromKey(f.clientKey), f.via, f.up, f.down)
	}
}

// addFlowBytes 在转发/回送成功后累加 flow 字节。flow 可能恰好被
// sweep 回收，本次值只计入全局字节计数而不入聚合（罕见竞态）。
func (g *udpGateway) addFlowBytes(flowKey string, up, down int64) {
	g.mu.Lock()
	if f, ok := g.flows[flowKey]; ok {
		f.up += up
		f.down += down
	}
	g.mu.Unlock()
}

// canonicalIP 把 IPv4-mapped IPv6（::ffff:x.x.x.x，含 16 字节形式）统一成
// 4 字节 IPv4，保证分流判定、flow key、relay 族选择在 v4/v6 入口下一致。
func canonicalIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4
	}
	return ip.To16()
}

// handle 处理一个被透明重定向的 UDP 报文。
// data 为负载（不含任何 SOCKS5 头），dstIP/dstPort 为原始目标，
// reply 负责把回包送回客户端。该方法在平台读循环中被串行/并发调用。
func (g *udpGateway) handle(data []byte, clientKey string, dstIP net.IP, dstPort int,
	reply func([]byte) error, release func()) {
	if len(data) == 0 || dstIP == nil || dstPort <= 0 || dstPort > 65535 {
		return
	}
	dstIP = canonicalIP(dstIP)
	g.stats.inc(statUDPIn)
	g.stats.add(statUDPBytesIn, int64(len(data)))
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return
	}
	c, ok := g.clients[clientKey]
	if !ok {
		c = &udpClient{addr: clientKey, release: release}
		g.clients[clientKey] = c
	}
	c.lastSeen = time.Now()
	g.mu.Unlock()

	// 与 TCP 路径一致的分流：Fake-IP 还原域名走代理（ATYP=0x03），
	// 其余目标交 ShouldProxy 判定。
	var target, flowKey string
	var viaProxy bool
	if g.resolver.IsFakeIP(dstIP) {
		if domain, ok := g.resolver.LookupDomainByFakeIP(dstIP); ok && domain != "" {
			target = domain
			viaProxy = true
		}
	}
	if target == "" {
		if sp, _ := g.resolver.ShouldProxy(dstIP.String()); sp {
			target = dstIP.String()
			viaProxy = true
		} else {
			target = dstIP.String()
		}
	}

	flowKey = net.JoinHostPort(target, strconv.Itoa(dstPort))
	kind := "D"
	via := "direct"
	if viaProxy {
		kind = "P"
		via = "socks"
	}
	fkey := kind + "|" + flowKey
	g.mu.Lock()
	if g.closed {
		// Close 可能与首包并发：关闭后不再登记 flow，也不向已关停的
		// relay 发送（relay 自身同样有 closed 检查，这里提前返回）
		g.mu.Unlock()
		return
	}
	if f, exists := g.flows[fkey]; exists {
		// 已有 flow：刷新时间戳与回包闭包。TPROXY 每包的闭包语义等价
		// （内部按目标复用同一透明发送 socket）；REDIRECT 闭包绑定的
		// probe 也不变，刷新仅为兼容 probe 被回收后重建的场景。
		f.lastSeen = time.Now()
		f.reply = reply
	} else {
		g.flows[fkey] = &udpFlow{
			clientKey: clientKey,
			target:    flowKey,
			reply:     reply,
			created:   time.Now(),
			lastSeen:  time.Now(),
			host:      target,
			via:       via,
		}
	}
	g.mu.Unlock()

	var err error
	if viaProxy {
		g.stats.inc(statUDPProxyIn)
		err = g.proxy.send(target, dstPort, data)
	} else {
		g.stats.inc(statUDPDirectIn)
		err = g.direct.send(dstIP, dstPort, data)
	}
	if err != nil {
		g.stats.inc(statUDPFwdFail)
		if g.shouldLogFwdFail() {
			log.Printf("udp forward fail %s -> %s: %v", c.addr, flowKey, err)
		}
		return
	}
	// 仅成功转发才计入 flow 上行（与 TCP 字节计数口径一致）
	g.addFlowBytes(fkey, int64(len(data)), 0)
}

// shouldLogFwdFail 以 udpFwdFailLogInterval 为窗口限频转发失败日志。
// 代理持续不可用时入站包可能每秒数十个，逐条打印会刷爆路由器日志。
func (g *udpGateway) shouldLogFwdFail() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	if now.Sub(g.lastFwdFailLog) >= udpFwdFailLogInterval {
		g.lastFwdFailLog = now
		return true
	}
	return false
}

// onProxyPacket 处理 SOCKS5 relay 回来的报文（已剥离 UDP 头）。
func (g *udpGateway) onProxyPacket(host string, port int, data []byte) {
	g.deliverBack("P|"+net.JoinHostPort(host, strconv.Itoa(port)), data)
}

func (g *udpGateway) onDirectPacket(src *net.UDPAddr, data []byte) {
	ip := canonicalIP(src.IP)
	g.deliverBack("D|"+net.JoinHostPort(ip.String(), strconv.Itoa(src.Port)), data)
}

func (g *udpGateway) deliverBack(flowKey string, data []byte) {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return
	}
	f, ok := g.flows[flowKey]
	if !ok {
		g.mu.Unlock()
		// flow 已被空闲回收，或 SOCKS5 回包头与任何在途目标都不匹配
		g.stats.inc(statUDPReplyMiss)
		return
	}
	f.lastSeen = time.Now()
	reply := f.reply
	c := g.clients[f.clientKey]
	g.mu.Unlock()
	if reply == nil {
		return
	}
	addr := flowKey
	if c != nil {
		addr = c.addr
	}
	if err := reply(data); err != nil {
		log.Printf("udp reply fail %s <- %s: %v", addr, flowKey, err)
		return
	}
	g.stats.inc(statUDPReplies)
	g.stats.add(statUDPBytesOut, int64(len(data)))
	g.addFlowBytes(flowKey, 0, int64(len(data)))
}

// activeCounts 返回瞬时活跃 client/flow 数（统计 gauge 用）
func (g *udpGateway) activeCounts() (clients, flows int64) {
	g.mu.Lock()
	clients = int64(len(g.clients))
	flows = int64(len(g.flows))
	g.mu.Unlock()
	return
}

func (g *udpGateway) Close() {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return
	}
	g.closed = true
	clients := g.clients
	flows := g.flows
	g.clients = make(map[string]*udpClient)
	g.flows = make(map[string]*udpFlow)
	g.mu.Unlock()

	// 关闭即所有 UDP flow 终结：累计流量 flush 进 /top 聚合
	flushed := make([]*udpFlow, 0, len(flows))
	for _, f := range flows {
		flushed = append(flushed, f)
	}
	g.flushFlowStats(flushed)
	for _, c := range clients {
		if c.release != nil {
			c.release()
		}
	}
	g.proxy.close()
	g.direct.close()
}

// ---------------- 上游 SOCKS5 UDP ASSOCIATE ----------------

type udpProxyRelay struct {
	proxyAddr, user, pass string
	inbound               func(host string, port int, data []byte)

	// creating 非 nil 表示已有 goroutine 在建立 association，后来者
	// 等该 channel 关闭后复用结果，避免并发首包触发多次 SOCKS5 握手。
	// cooldownUntil/lastDialErr 记录最近一次建连失败：冷却期内请求快速
	// 失败，避免持续不可用时代理以 10s 握手为节奏反复重拨。
	mu            sync.Mutex
	control       net.Conn
	relay         *net.UDPConn
	relayAddr     *net.UDPAddr
	creating      chan struct{}
	cooldownUntil time.Time
	lastDialErr   error
	closed        bool
	stats         *stats
	// gen 是上游代次：SIGHUP 换了上游就自增。在途握手发现代次变了会
	// 丢弃自己刚建好的 association，不会把旧上游的端点装回 relay。
	gen uint64
}

// creds 取一份上游地址与认证的快照：握手在锁外进行，必须一次性读齐，
// 否则与热更新并发时会出现"新地址 + 旧密码"。
func (r *udpProxyRelay) creds() (addr, user, pass string, gen uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.proxyAddr, r.user, r.pass, r.gen
}

// setUpstream 热更新上游地址与认证（SIGHUP 重读配置文件后调用）。
// 已建立的 ASSOCIATE 属于旧上游，立即作废：下一个入站包用新地址重新
// 握手。不置 closed，relay 仍可重建。
func (r *udpProxyRelay) setUpstream(proxyAddr, user, pass string) {
	r.mu.Lock()
	r.proxyAddr, r.user, r.pass = proxyAddr, user, pass
	r.gen++
	control, relay := r.control, r.relay
	r.control, r.relay, r.relayAddr = nil, nil, nil
	// 上游换了，旧地址上的失败冷却不再有意义
	r.cooldownUntil, r.lastDialErr = time.Time{}, nil
	r.mu.Unlock()
	if control != nil {
		control.Close()
	}
	if relay != nil {
		relay.Close()
	}
}

// assocIsUp 供统计 gauge 查询 association 在线状态
func (r *udpProxyRelay) assocIsUp() int64 {
	r.mu.Lock()
	up := r.relay != nil
	r.mu.Unlock()
	if up {
		return 1
	}
	return 0
}

func newUDPProxyRelay(proxyAddr, user, pass string, inbound func(string, int, []byte)) *udpProxyRelay {
	return &udpProxyRelay{proxyAddr: proxyAddr, user: user, pass: pass, inbound: inbound}
}

// send 封装 RFC 1928 UDP 报文并发往代理的 relay 端口。
// ASSOCIATE 只在首次发送时建立一次（控制连接 + relay socket），
// 控制连接断开后自动重建；数据面不做 TCP CONNECT 式的逐包握手。
func (r *udpProxyRelay) send(host string, port int, data []byte) error {
	if err := r.ensureAssoc(); err != nil {
		return err
	}
	pkt, err := packSocks5UDP(host, port, data)
	if err != nil {
		return err
	}
	r.mu.Lock()
	relay, addr := r.relay, r.relayAddr
	r.mu.Unlock()
	if relay == nil {
		return errors.New("udp associate not ready")
	}
	_, err = relay.WriteToUDP(pkt, addr)
	return err
}

// errAssocClosed 在 relay 已关闭时返回。
var errAssocClosed = errors.New("udp associate closed")

func (r *udpProxyRelay) ensureAssoc() error {
	for {
		r.mu.Lock()
		if r.closed {
			r.mu.Unlock()
			return errAssocClosed
		}
		if r.relay != nil {
			r.mu.Unlock()
			return nil
		}
		// 建连失败冷却中：快速失败，不让每个入站包都堆积一个 10s 窗口
		if err := r.lastDialErr; time.Now().Before(r.cooldownUntil) && err != nil {
			r.mu.Unlock()
			r.stats.inc(statAssocCool)
			return err
		}
		if r.creating == nil {
			// 本 goroutine 成为唯一建连者
			r.creating = make(chan struct{})
			r.mu.Unlock()
			// 成功与失败都记录（慢握手/超时是 UDP 链路劣化信号）；
			// 冷却快速失败在上方分支返回，不会混入这张图。
			dialStart := time.Now()
			err := r.buildAssoc()
			r.stats.observe(histUDPAssocDialSeconds, time.Since(dialStart))
			r.mu.Lock()
			if err != nil {
				r.cooldownUntil = time.Now().Add(udpAssocCooldown)
				r.lastDialErr = err
			} else {
				r.cooldownUntil = time.Time{}
				r.lastDialErr = nil
			}
			close(r.creating)
			r.creating = nil
			r.mu.Unlock()
			return err
		}
		// 已有建连在途：等待完成后复查（成功则 relay 已就位，
		// 失败则进入冷却快速失败，冷却结束后再成为新的建连者重试）
		ch := r.creating
		r.mu.Unlock()
		<-ch
	}
}

// buildAssoc 执行一次完整的 ASSOCIATE 握手，调用方必须已持有"建连者"
// 身份（ensureAssoc 保证全局唯一在途）。
func (r *udpProxyRelay) buildAssoc() error {
	// 一次性取齐凭证与代次：握手全程在锁外，热更新可能中途发生。
	addr, user, pass, gen := r.creds()
	control, err := net.DialTimeout("tcp", addr, udpAssocTimeout)
	if err != nil {
		return err
	}
	_ = control.SetDeadline(time.Now().Add(udpAssocTimeout))
	if err = socksNegotiate(control, user, pass); err != nil {
		control.Close()
		return err
	}
	// DST 0.0.0.0:0：客户端不限制允许向 relay 发送的源地址/端口，
	// 让服务器自行分配并在 BND.ADDR/BND.PORT 中告知 relay 端点。
	if err = socksWriteRequest(control, socksCmdUDPAssociate, "", nil, 0); err != nil {
		control.Close()
		return err
	}
	bndHost, bndIP, bndPort, err := socksReadReply(control)
	if err != nil {
		control.Close()
		return err
	}
	_ = control.SetDeadline(time.Time{})

	relayAddr, err := resolveRelayAddr(control, bndHost, bndIP, bndPort)
	if err != nil {
		control.Close()
		return err
	}
	network := "udp4"
	if relayAddr.IP.To4() == nil {
		network = "udp6"
	}
	relayConn, err := net.ListenUDP(network, &net.UDPAddr{})
	if err != nil {
		control.Close()
		return err
	}

	// 控制连接平时完全空闲（仅承载 association 生命周期），WAN/运营商
	// NAT 的空闲 TCP 超时会静默掐断它而两端不知；开启 keepalive（30s）
	// 让 watchControl 在几个探测周期内感知半开并触发 teardown/重建。
	setKeepAlive(control)

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		relayConn.Close()
		control.Close()
		return errAssocClosed
	}
	if r.gen != gen {
		// 握手期间上游被热更新替换：这次结果属于旧上游，直接丢弃，
		// 下一个包会用新地址重拨。
		r.mu.Unlock()
		relayConn.Close()
		control.Close()
		return errors.New("udp upstream changed during associate")
	}
	r.control = control
	r.relay = relayConn
	r.relayAddr = relayAddr
	r.mu.Unlock()

	log.Printf("udp associate established: relay=%s", relayAddr.String())
	r.stats.inc(statAssocUp)

	go r.watchControl(control, relayConn)
	go r.readRelay(relayConn, relayAddr, control)
	return nil
}

// resolveRelayAddr 解析 ASSOCIATE 应答里的 relay 端点。
// 服务器常回 0.0.0.0:0 表示"与控制连接同地址"，此时用 TCP 控制连接
// 的对端 IP 和/或配置端口补全；域名型应答按 A 记录解析。
func resolveRelayAddr(control net.Conn, bndHost string, bndIP net.IP, bndPort int) (*net.UDPAddr, error) {
	tcpAddr, _ := control.RemoteAddr().(*net.TCPAddr)
	if bndHost != "" {
		ips, err := net.LookupIP(bndHost)
		if err != nil || len(ips) == 0 {
			return nil, err
		}
		ip := ips[0]
		if tcpAddr != nil && ip.To4() == nil && tcpAddr.IP.To4() != nil {
			return nil, errors.New("udp relay domain resolved to ipv6 but proxy is ipv4")
		}
		return &net.UDPAddr{IP: ip, Port: bndPort}, nil
	}
	ip := bndIP
	port := bndPort
	if ip.IsUnspecified() && tcpAddr != nil {
		ip = tcpAddr.IP
	}
	if port == 0 && tcpAddr != nil {
		port = tcpAddr.Port
	}
	if ip == nil || port == 0 || ip.IsUnspecified() {
		return nil, errors.New("udp associate returned unusable relay address")
	}
	return &net.UDPAddr{IP: ip, Port: port}, nil
}

// watchControl 阻塞读取控制连接；控制连接存活即代表 association 有效，
// 一旦 EOF/出错就拆除本条 association，下次发送时自动重建。
func (r *udpProxyRelay) watchControl(control net.Conn, relayConn *net.UDPConn) {
	_, _ = io.Copy(io.Discard, control)
	r.teardown(control, relayConn)
}

func (r *udpProxyRelay) readRelay(relayConn *net.UDPConn, expected *net.UDPAddr, control net.Conn) {
	buf := make([]byte, udpMaxPacket)
	for {
		n, src, err := relayConn.ReadFromUDP(buf)
		if err != nil {
			r.teardown(control, relayConn)
			return
		}
		// 只接受声明的 relay 端点回包，拒绝其他来源的伪造数据报
		if src == nil || !src.IP.Equal(expected.IP) || src.Port != expected.Port {
			continue
		}
		host, port, payload, err := unpackSocks5UDP(buf[:n])
		if err != nil {
			r.stats.inc(statAssocBadPkt)
			log.Printf("udp relay unpack from %s: %v", src, err)
			continue
		}
		r.inbound(host, port, append([]byte(nil), payload...))
	}
}

func (r *udpProxyRelay) teardown(control net.Conn, relayConn *net.UDPConn) {
	r.mu.Lock()
	if r.control == control && r.relay == relayConn {
		r.control = nil
		r.relay = nil
		r.relayAddr = nil
	} else {
		r.mu.Unlock()
		return
	}
	r.mu.Unlock()
	// 仅当前代 association 的真实拆除才计数（close() 走自己的路径，
	// 其控制/relay 已先置空，不会误计）
	r.stats.inc(statAssocDown)
	_ = relayConn.Close()
	_ = control.Close()
}

func (r *udpProxyRelay) close() {
	r.mu.Lock()
	r.closed = true
	control, relay := r.control, r.relay
	r.control = nil
	r.relay = nil
	r.relayAddr = nil
	r.mu.Unlock()
	if relay != nil {
		_ = relay.Close()
	}
	if control != nil {
		_ = control.Close()
	}
}

// ---------------- 直连 UDP ----------------

type udpDirectRelay struct {
	inbound func(src *net.UDPAddr, data []byte)

	mu    sync.Mutex
	conns map[string]*net.UDPConn // 按地址族各持一个："udp4" / "udp6"
}

func newUDPDirectRelay(inbound func(*net.UDPAddr, []byte)) *udpDirectRelay {
	return &udpDirectRelay{inbound: inbound, conns: make(map[string]*net.UDPConn)}
}

func (d *udpDirectRelay) send(ip net.IP, port int, data []byte) error {
	network := "udp4"
	if ip.To4() == nil {
		network = "udp6"
	}
	conn, err := d.ensure(network)
	if err != nil {
		return err
	}
	_, err = conn.WriteToUDP(data, &net.UDPAddr{IP: ip, Port: port})
	return err
}

func (d *udpDirectRelay) ensure(network string) (*net.UDPConn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if conn := d.conns[network]; conn != nil {
		return conn, nil
	}
	conn, err := net.ListenUDP(network, &net.UDPAddr{})
	if err != nil {
		return nil, err
	}
	d.conns[network] = conn
	go d.readLoop(conn)
	return conn, nil
}

func (d *udpDirectRelay) readLoop(conn *net.UDPConn) {
	buf := make([]byte, udpMaxPacket)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		d.inbound(src, append([]byte(nil), buf[:n]...))
	}
}

func (d *udpDirectRelay) close() {
	d.mu.Lock()
	conns := d.conns
	d.conns = make(map[string]*net.UDPConn)
	d.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}
