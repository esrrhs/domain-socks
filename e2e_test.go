package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	ghdns "github.com/esrrhs/gohome/dns"
)

// TestE2ERouterFlow 模拟路由器端到端完整网络流程：
// 1. 模拟上游 SOCKS5 代理服务器（带用户名密码认证）
// 2. 模拟国内真实 HTTP Web 服务器（代表直连目标）
// 3. 模拟海外 HTTP Web 服务器（通过 SOCKS5 代理访问的目标）
// 4. 初始化带有 Fake-IP + 国内分流的 domain-socks 核心逻辑
// 5. 测试场景 A：国内域名（如 baidu.com、qq.com）-> 确保走直连，不走 SOCKS5
// 6. 测试场景 B：海外域名（如 google.com）-> DNS 返回 Fake-IP -> 还原原始域名走 SOCKS5 代理
// 7. 测试场景 C：Android / 厂商连通性探测（Captive portal 204）-> 秒回 204，消除叹号
func TestE2ERouterFlow(t *testing.T) {
	// --- 1. 启动模拟 SOCKS5 代理服务器 ---
	socksUser := "mockuser"
	socksPass := "mockpass"
	var socksHits int
	var socksHitsMu sync.Mutex

	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mock socks: %v", err)
	}
	defer socksLn.Close()

	go func() {
		for {
			c, err := socksLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 512)
				// Greeting
				n, err := conn.Read(buf)
				if err != nil || n < 3 || buf[0] != 0x05 {
					return
				}
				conn.Write([]byte{0x05, 0x02}) // User/Pass method

				// Auth
				n, err = conn.Read(buf)
				if err != nil || n < 5 || buf[0] != 0x01 {
					return
				}
				ulen := int(buf[1])
				u := string(buf[2 : 2+ulen])
				plen := int(buf[2+ulen])
				p := string(buf[3+ulen : 3+ulen+plen])
				if u != socksUser || p != socksPass {
					conn.Write([]byte{0x01, 0x01})
					return
				}
				conn.Write([]byte{0x01, 0x00}) // Auth OK

				// Connect request
				n, err = conn.Read(buf)
				if err != nil || n < 7 || buf[1] != 0x01 {
					return
				}
				// 提取目标
				var targetHost string
				var targetPort int
				if buf[3] == 0x03 { // Domain
					dlen := int(buf[4])
					targetHost = string(buf[5 : 5+dlen])
					targetPort = int(buf[5+dlen])<<8 | int(buf[6+dlen])
				} else if buf[3] == 0x01 { // IPv4
					targetHost = net.IP(buf[4:8]).String()
					targetPort = int(buf[8])<<8 | int(buf[9])
				}

				socksHitsMu.Lock()
				socksHits++
				socksHitsMu.Unlock()

				// 模拟连接到实际目标
				targetConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", targetHost, targetPort), 2*time.Second)
				if err != nil {
					conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
					return
				}
				defer targetConn.Close()

				conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Connect OK

				// 双向转发
				var wg sync.WaitGroup
				wg.Add(2)
				go func() {
					defer wg.Done()
					io.Copy(targetConn, conn)
				}()
				go func() {
					defer wg.Done()
					io.Copy(conn, targetConn)
				}()
				wg.Wait()
			}(c)
		}
	}()

	// --- 2. 启动国内与海外模拟 Web 服务 ---
	directWebLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer directWebLn.Close()
	directPort := directWebLn.Addr().(*net.TCPAddr).Port

	remoteWebLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer remoteWebLn.Close()
	remotePort := remoteWebLn.Addr().(*net.TCPAddr).Port

	go http.Serve(directWebLn, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("DIRECT_OK"))
	}))

	go http.Serve(remoteWebLn, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("REMOTE_PROXY_OK"))
	}))

	// --- 3. 初始化 domain-socks Resolver ---
	cfg := ghdns.DefaultConfig()
	cfg.EnableFakeIP = true
	// 注册本地测试直连域名，其余走代理
	cfg.DirectDomains = []string{"direct.internal", "baidu.com"}

	resolver, err := ghdns.NewResolver(cfg)
	if err != nil {
		t.Fatalf("init resolver failed: %v", err)
	}

	// 场景 A：国内域名（如 baidu.com、direct.internal）分流判定
	isProxy, err := resolver.ShouldProxy("direct.internal")
	if err != nil || isProxy {
		t.Fatalf("expected direct.internal to NOT proxy, got isProxy=%v err=%v", isProxy, err)
	}
	isProxyCN, _ := resolver.ShouldProxy("baidu.com")
	if isProxyCN {
		t.Fatalf("expected baidu.com to be direct")
	}

	// 场景 B：海外域名（google.com）走 Fake-IP 与代理 SOCKS5 连接
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ips, err := resolver.Resolve(ctx, "www.google.com")
	if err != nil || len(ips) == 0 {
		t.Fatalf("resolve google.com failed: %v", err)
	}
	fakeIP := ips[0]
	if !resolver.IsFakeIP(fakeIP) {
		t.Fatalf("expected fake IP, got %v", fakeIP)
	}
	origDomain, ok := resolver.LookupDomainByFakeIP(fakeIP)
	if !ok || origDomain != "www.google.com" {
		t.Fatalf("lookup fake IP failed: %s (ok=%v)", origDomain, ok)
	}

	// 经由 socksConnect 连接到模拟远程 Web 服务
	conn, err := socksConnect(socksLn.Addr().String(), "127.0.0.1", nil, remotePort, socksUser, socksPass)
	if err != nil {
		t.Fatalf("socksConnect to remote web failed: %v", err)
	}
	defer conn.Close()

	req := "GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	respBuf := make([]byte, 512)
	n, err := conn.Read(respBuf)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if !bytes.Contains(respBuf[:n], []byte("REMOTE_PROXY_OK")) {
		t.Fatalf("expected proxy response, got: %s", string(respBuf[:n]))
	}

	socksHitsMu.Lock()
	hits := socksHits
	socksHitsMu.Unlock()
	if hits == 0 {
		t.Fatalf("expected socks proxy to be hit at least once, got %d", hits)
	}

	// 场景 C：Android / 手机 Captive Portal 连通性探测 (204 快速响应)
	probeRequests := []struct {
		req    string
		domain string
	}{
		{"GET /generate_204 HTTP/1.1\r\nHost: connectivitycheck.gstatic.com\r\n\r\n", "connectivitycheck.gstatic.com"},
		{"GET /gen_204 HTTP/1.1\r\nHost: play.googleapis.com\r\n\r\n", "play.googleapis.com"},
		{"GET /generate_204 HTTP/1.1\r\nHost: connect.rom.miui.com\r\n\r\n", "connect.rom.miui.com"},
		{"GET /check_network_status.txt HTTP/1.1\r\nHost: wifi.vivo.com.cn\r\n\r\n", "wifi.vivo.com.cn"},
		{"GET /hotspot-detect.html HTTP/1.1\r\nHost: captive.apple.com\r\n\r\n", "captive.apple.com"},
		{"GET /ncsi.txt HTTP/1.1\r\nHost: www.msftncsi.com\r\n\r\n", "www.msftncsi.com"},
	}

	for _, pr := range probeRequests {
		if !captiveProbe([]byte(pr.req), pr.domain) {
			t.Errorf("failed to recognize captive probe: %s on %s", pr.req, pr.domain)
		}
	}

	// 直连 Web 确认正常可达
	directConn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", directPort), 2*time.Second)
	if err != nil {
		t.Fatalf("dial direct web failed: %v", err)
	}
	defer directConn.Close()
	directConn.Write([]byte("GET / HTTP/1.1\r\nHost: direct.internal\r\nConnection: close\r\n\r\n"))
	n, _ = directConn.Read(respBuf)
	if !bytes.Contains(respBuf[:n], []byte("DIRECT_OK")) {
		t.Fatalf("expected direct response, got: %s", string(respBuf[:n]))
	}
}

// TestHandleConnByteCounting 走一遍真实 handleConn 直连路径，验证连接结束时
// 上下行字节按路由汇总到统计计数器（prefix 重放字节计入上行）。
func TestHandleConnByteCounting(t *testing.T) {
	// 上游回显服务：读到 EOF 后回 "ECHO:" + 原文
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upLn.Close()
	go func() {
		c, err := upLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		all, _ := io.ReadAll(c)
		_, _ = c.Write(append([]byte("ECHO:"), all...))
	}()
	upPort := upLn.Addr().(*net.TCPAddr).Port

	// 前端模拟透明监听；dstOf 直接返回上游（无需 REDIRECT/TPROXY）
	frontLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer frontLn.Close()

	res := &stubExchangeResolver{proxyDomains: map[string]bool{}}
	st := newStats()
	dstOf := func(net.Conn) (net.IP, int, error) {
		return net.ParseIP("127.0.0.1"), upPort, nil
	}
	done := make(chan struct{})
	go func() {
		c, err := frontLn.Accept()
		if err != nil {
			t.Errorf("front accept: %v", err)
			close(done)
			return
		}
		handleConn(c, res, "127.0.0.1:0", "", "", dstOf, st, false)
		close(done)
	}()

	cc, err := net.DialTimeout("tcp", frontLn.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	payload := "HELLO-WORLD" // 非 HTTP/TLS 首字节，嗅探立即放弃，走 prefix 重放
	if _, err := cc.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	_ = cc.(*net.TCPConn).CloseWrite()
	reply, err := io.ReadAll(cc)
	if err != nil {
		t.Fatal(err)
	}
	_ = cc.Close()
	<-done

	if want := "ECHO:" + payload; string(reply) != want {
		t.Fatalf("reply=%q want %q", reply, want)
	}
	snap := st.snapshot().Counters
	if snap[statTCPDirect] != 1 {
		t.Fatalf("tcp_direct=%d want 1", snap[statTCPDirect])
	}
	if snap[statTCPDirectBytesUp] != int64(len(payload)) {
		t.Fatalf("direct up bytes=%d want %d (prefix replay must count)",
			snap[statTCPDirectBytesUp], len(payload))
	}
	if want := int64(len("ECHO:") + len(payload)); snap[statTCPDirectBytesDown] != want {
		t.Fatalf("direct down bytes=%d want %d", snap[statTCPDirectBytesDown], want)
	}
	// 直连路径不应产生代理字节计数
	if snap[statTCPProxyBytesUp] != 0 || snap[statTCPProxyBytesDown] != 0 {
		t.Fatalf("proxy byte counters must stay zero, got up=%d down=%d",
			snap[statTCPProxyBytesUp], snap[statTCPProxyBytesDown])
	}
	// 直连拨号必须被直方图记录一次（代理直方图保持零）
	hists := st.snapshot().Histograms
	if hists[histTCPDirectDialSeconds].Count != 1 {
		t.Fatalf("direct dial histogram count=%d want 1", hists[histTCPDirectDialSeconds].Count)
	}
	if hists[histTCPProxyDialSeconds].Count != 0 {
		t.Fatalf("proxy dial histogram must stay zero, got %d", hists[histTCPProxyDialSeconds].Count)
	}
	// 关闭后流量必须进入 /top 聚合（回环场景 client 与 target 同为 127.0.0.1）
	top := st.renderTop()
	for _, want := range []string{"top domains", "top clients", "127.0.0.1"} {
		if !strings.Contains(top, want) {
			t.Fatalf("renderTop missing %q:\n%s", want, top)
		}
	}
}

// TestHandleConnProxyDialHistogram 走完整 handleConn 代理路径：真实
// socksConnect 对 mock SOCKS5 发 CONNECT，验证代理拨号直方图与代理
// 字节计数接线（与直连路径测试成对覆盖）。
func TestHandleConnProxyDialHistogram(t *testing.T) {
	// mock SOCKS5：免密协商 + IPv4 CONNECT 成功 + 回显载荷
	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socksLn.Close()
	go func() {
		c, err := socksLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		hdr := make([]byte, 2)
		if _, err := io.ReadFull(c, hdr); err != nil || hdr[0] != 0x05 {
			return
		}
		methods := make([]byte, hdr[1])
		if _, err := io.ReadFull(c, methods); err != nil {
			return
		}
		if _, err := c.Write([]byte{0x05, 0x00}); err != nil { // 免密
			return
		}
		reqHdr := make([]byte, 4)
		if _, err := io.ReadFull(c, reqHdr); err != nil || reqHdr[1] != socksCmdConnect || reqHdr[3] != 0x01 {
			return
		}
		addr4 := make([]byte, 6) // 4B ip + 2B port
		if _, err := io.ReadFull(c, addr4); err != nil {
			return
		}
		if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
			return
		}
		all, _ := io.ReadAll(c)
		_, _ = c.Write(append([]byte("ECHO:"), all...))
	}()

	frontLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer frontLn.Close()

	// dstIP 127.0.0.1 被判为代理域名 -> 走 SOCKS5，且无嗅探域名 -> ATYP=0x01
	res := &stubExchangeResolver{proxyDomains: map[string]bool{"127.0.0.1": true}}
	st := newStats()
	dstOf := func(net.Conn) (net.IP, int, error) {
		return net.ParseIP("127.0.0.1"), 9, nil
	}
	done := make(chan struct{})
	go func() {
		c, err := frontLn.Accept()
		if err != nil {
			t.Errorf("front accept: %v", err)
			close(done)
			return
		}
		handleConn(c, res, socksLn.Addr().String(), "", "", dstOf, st, false)
		close(done)
	}()

	cc, err := net.DialTimeout("tcp", frontLn.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	payload := "PROXY-PAYLOAD" // 非 HTTP/TLS 首字节，嗅探放弃 -> prefix 重放
	if _, err := cc.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	_ = cc.(*net.TCPConn).CloseWrite()
	reply, err := io.ReadAll(cc)
	if err != nil {
		t.Fatal(err)
	}
	_ = cc.Close()
	<-done

	if want := "ECHO:" + payload; string(reply) != want {
		t.Fatalf("reply=%q want %q", reply, want)
	}
	snap := st.snapshot()
	if snap.Counters[statTCPProxy] != 1 || snap.Counters[statTCPSocksFail] != 0 {
		t.Fatalf("proxy=%d socks_fail=%d want 1/0", snap.Counters[statTCPProxy], snap.Counters[statTCPSocksFail])
	}
	if snap.Counters[statTCPProxyBytesUp] != int64(len(payload)) {
		t.Fatalf("proxy up bytes=%d want %d", snap.Counters[statTCPProxyBytesUp], len(payload))
	}
	if want := int64(len("ECHO:") + len(payload)); snap.Counters[statTCPProxyBytesDown] != want {
		t.Fatalf("proxy down bytes=%d want %d", snap.Counters[statTCPProxyBytesDown], want)
	}
	if snap.Counters[statTCPDirect] != 0 || snap.Counters[statTCPDirectBytesUp] != 0 {
		t.Fatalf("direct counters must stay zero: %v", snap.Counters)
	}
	h := snap.Histograms[histTCPProxyDialSeconds]
	if h.Count != 1 || h.SumSeconds <= 0 {
		t.Fatalf("proxy dial histogram=%+v want count=1 sum>0", h)
	}
	if h.CumulativeCounts[len(h.CumulativeCounts)-1] != 1 {
		t.Fatalf("proxy dial +Inf bucket=%v", h.CumulativeCounts)
	}
	if snap.Histograms[histTCPDirectDialSeconds].Count != 0 {
		t.Fatalf("direct dial histogram must stay zero")
	}
}

// TestHandleConnActiveConnsView 验证存活连接实时视图：转发进行中的
// 连接必须出现在 renderConns（forward 状态、实时字节），结束后消失。
func TestHandleConnActiveConnsView(t *testing.T) {
	gotData := make(chan struct{}, 1)
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upLn.Close()
	go func() {
		c, err := upLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		head := make([]byte, 256)
		n, _ := c.Read(head)
		if n > 0 {
			gotData <- struct{}{}
		}
		rest, _ := io.ReadAll(c) // 阻塞到客户端 CloseWrite
		_, _ = c.Write(append(append([]byte("GOT:"), head[:n]...), rest...))
	}()
	upPort := upLn.Addr().(*net.TCPAddr).Port
	upTarget := fmt.Sprintf("127.0.0.1:%d", upPort)

	frontLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer frontLn.Close()
	res := &stubExchangeResolver{proxyDomains: map[string]bool{}}
	st := newStats()
	dstOf := func(net.Conn) (net.IP, int, error) {
		return net.ParseIP("127.0.0.1"), upPort, nil
	}
	done := make(chan struct{})
	go func() {
		c, err := frontLn.Accept()
		if err != nil {
			t.Errorf("front accept: %v", err)
			close(done)
			return
		}
		handleConn(c, res, "127.0.0.1:0", "", "", dstOf, st, false)
		close(done)
	}()

	cc, err := net.DialTimeout("tcp", frontLn.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	payload := "HOLD-DATA"
	if _, err := cc.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-gotData:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream never received payload")
	}

	// 转发中：轮询实时视图（给 setState/prefix 重放一点调度余量）
	deadline := time.Now().Add(2 * time.Second)
	var view string
	for time.Now().Before(deadline) {
		view = st.renderConns(time.Now())
		if strings.Contains(view, upTarget) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, want := range []string{upTarget, "direct", "forward", humanBytes(int64(len(payload)))} {
		if !strings.Contains(view, want) {
			t.Fatalf("active conn view missing %q:\n%s", want, view)
		}
	}

	// 放行结束连接，视图必须清空
	if err := cc.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	reply, err := io.ReadAll(cc)
	if err != nil {
		t.Fatal(err)
	}
	if want := "GOT:" + payload; string(reply) != want {
		t.Fatalf("reply=%q want %q", reply, want)
	}
	_ = cc.Close()
	<-done

	if got := st.renderConns(time.Now()); !strings.Contains(got, "no active connections") {
		t.Fatalf("view after close must be empty:\n%s", got)
	}
}
