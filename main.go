package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	ghdns "github.com/esrrhs/gohome/dns"
)

func main() {
	socks := flag.String("socks", "192.168.1.101:1081", "upstream socks5")
	dnsAddr := flag.String("dns", "127.0.0.1:1053", "dns listen address")
	listen := flag.String("listen", "0.0.0.0:12345", "transparent redirect listen")
	directDNS := flag.String("direct-dns", "223.5.5.5:53,119.29.29.29:53", "domestic upstream DNS servers (comma-separated)")
	directDomainsFile := flag.String("direct-domains-file", "", "optional file containing extra direct domains (e.g. dnsmasq format or line list)")
	flag.Parse()

	// 1. 初始化 gohome DNS Resolver 配置
	cfg := ghdns.DefaultConfig()
	cfg.EnableFakeIP = true // 代理域名返回 Fake-IP；国内直连域名返回真实 IP
	if *directDNS != "" {
		cfg.DirectUpstreams = strings.Split(*directDNS, ",")
	}
	if *directDomainsFile != "" {
		cfg.DirectDomainFiles = []string{*directDomainsFile}
	}

	resolver, err := ghdns.NewResolver(cfg)
	if err != nil {
		log.Fatalf("init resolver failed: %v", err)
	}

	// 2. 启动 DNS 服务端
	dnsServer := ghdns.NewServer(*dnsAddr, resolver)
	if err := dnsServer.Start(); err != nil {
		log.Fatalf("start dns server on %s failed: %v", *dnsAddr, err)
	}
	defer dnsServer.Stop()

	log.Printf("domain-socks started: socks=%s dns=%s listen=%s", *socks, *dnsAddr, *listen)

	// 3. 监听透明重定向连接
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("listen tcp %s: %v", *listen, err)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleConn(c, resolver, *socks)
	}
}

func handleConn(c net.Conn, resolver ghdns.Resolver, proxy string) {
	defer c.Close()
	dstIP, dstPort, err := originalDst(c)
	if err != nil {
		log.Printf("original dst: %v", err)
		return
	}

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
	if dstPort == 80 && captiveProbe(prefix) {
		_, _ = c.Write([]byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		return
	}

	// 判断是否走代理分流：
	// 1. 若目标 IP 是 Fake-IP，或者域名/IP 经 resolver.ShouldProxy 判定需要走代理 -> 走 SOCKS5
	// 2. 若不是 Fake-IP 且属于直连目标 -> 直接 net.Dial 目标真实地址直连
	shouldProxy := isFake
	if !shouldProxy {
		target := domain
		if target == "" {
			target = dstIP.String()
		}
		sp, _ := resolver.ShouldProxy(target)
		shouldProxy = sp
	}

	var up net.Conn
	var how string
	var targetDesc string

	if shouldProxy {
		targetDesc = domain
		if targetDesc == "" {
			targetDesc = dstIP.String()
		}
		how = "socks"
		up, err = socksConnect(proxy, domain, dstIP, dstPort)
		if err != nil {
			log.Printf("socks fail %s -> %s:%d: %v", c.RemoteAddr(), targetDesc, dstPort, err)
			return
		}
	} else {
		// 直连直达
		targetDesc = dstIP.String()
		how = "direct"
		up, err = net.DialTimeout("tcp", net.JoinHostPort(targetDesc, fmt.Sprintf("%d", dstPort)), 8*time.Second)
		if err != nil {
			log.Printf("direct fail %s -> %s:%d: %v", c.RemoteAddr(), targetDesc, dstPort, err)
			return
		}
	}
	defer up.Close()

	log.Printf("conn ok [%s] %s -> %s:%d", how, c.RemoteAddr(), targetDesc, dstPort)

	if len(prefix) > 0 {
		if _, err = up.Write(prefix); err != nil {
			return
		}
	}

	setKeepAlive(c)
	setKeepAlive(up)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(up, c)
		closeWrite(up)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(c, up)
		closeWrite(c)
	}()
	wg.Wait()
}

func captiveProbe(prefix []byte) bool {
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
	return path == "/generate_204" || path == "/gen_204"
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

func peekHost(c net.Conn) ([]byte, string) {
	_ = c.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	buf := make([]byte, 2048)
	n, _ := c.Read(buf)
	_ = c.SetReadDeadline(time.Time{})
	if n <= 0 {
		return nil, ""
	}
	prefix := append([]byte(nil), buf[:n]...)
	host := strings.TrimSuffix(strings.ToLower(sniffHost(prefix)), ".")
	return prefix, host
}
