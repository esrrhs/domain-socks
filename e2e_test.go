package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
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
