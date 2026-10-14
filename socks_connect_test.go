package main

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// startSocksTestServer 启动一个由测试完全掌控回包行为的 TCP 服务：
// 每条接入连接交给 handler(c) 处理，地址随 t.Cleanup 释放。
func startSocksTestServer(t *testing.T, handler func(c net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handler(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String()
}

// TestSocksConnectOnceErrors 用真实 TCP 上游逐分支驱动 socksConnectOnce
// 的三条失败路径（协商、请求、应答），断言错误语义与错误消息，并确认
// 失败后连接已被关闭（对已关闭 conn 再写会报错而非无限阻塞）。
func TestSocksConnectOnceErrors(t *testing.T) {
	cases := []struct {
		name    string
		user    string
		pass    string
		handler func(c net.Conn)
		wantErr string // "" 表示只要求出错，不校验消息（内核回 EOF/reset 二选一）
	}{
		{
			name: "bad socks version",
			handler: func(c net.Conn) {
				_, _ = io.ReadFull(c, make([]byte, 3))
				_, _ = c.Write([]byte{0x04, 0x00}) // 非法版本应答
			},
			wantErr: "socks version 4",
		},
		{
			name: "auth refused",
			user: "u", pass: "p",
			handler: func(c net.Conn) {
				_, _ = io.ReadFull(c, make([]byte, 4))                   // greeting(含两个方法)
				_, _ = c.Write([]byte{0x05, 0x02})                       // 要求 RFC1929
				_, _ = io.ReadFull(c, make([]byte, 3+len("u")+len("p"))) // ver,ulen,user,plen,pass
				_, _ = c.Write([]byte{0x01, 0x01})                       // 认证失败
			},
			wantErr: "socks auth failed",
		},
		{
			name: "connect refused",
			handler: func(c net.Conn) {
				_, _ = io.ReadFull(c, make([]byte, 3))                           // greeting
				_, _ = c.Write([]byte{0x05, 0x00})                               // 免密通过
				_, _ = io.ReadFull(c, make([]byte, 18))                          // CONNECT example.com
				_, _ = c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // 拒绝
			},
			wantErr: "socks refused code 5",
		},
		{
			name: "server closes after negotiate",
			handler: func(c net.Conn) {
				_, _ = io.ReadFull(c, make([]byte, 3))
				_, _ = c.Write([]byte{0x05, 0x00})
				_ = c.Close() // 应答永远不来
			},
			wantErr: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr := startSocksTestServer(t, tc.handler)
			conn, err := socksConnectOnce(addr, "example.com", nil, 443, tc.user, tc.pass)
			if err == nil {
				_ = conn.Close()
				t.Fatal("expected error")
			}
			if conn != nil {
				t.Fatalf("failed connect must return nil conn, got %v", conn)
			}
			if tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err=%v want contains %q", err, tc.wantErr)
			}
			if len(handshakeSlots) != 0 {
				t.Fatalf("handshakeSlots leaked: %d", len(handshakeSlots))
			}
		})
	}
}

// TestSocksConnectOnceDialRefused 验证上游端口无人监听时直接返回
// 拨号错误，不进入协议层。
func TestSocksConnectOnceDialRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	conn, err := socksConnectOnce(addr, "example.com", nil, 443, "", "")
	if err == nil {
		_ = conn.Close()
		t.Fatal("expected dial error")
	}
	if conn != nil {
		t.Fatalf("conn=%v want nil", conn)
	}
}

// TestSocksConnectOnceSuccess 走通完整握手（无认证）：校验客户端按
// ATYP=0x03 发送域名，握手后隧道双向可用，且 12s 握手 deadline
// 已被清除（后续空闲不触发超时）。
func TestSocksConnectOnceSuccess(t *testing.T) {
	reqSeen := make(chan []byte, 1)
	addr := startSocksTestServer(t, func(c net.Conn) {
		defer c.Close()
		if _, err := io.ReadFull(c, make([]byte, 3)); err != nil { // greeting
			return
		}
		if _, err := c.Write([]byte{0x05, 0x00}); err != nil { // 免密
			return
		}
		req := make([]byte, 18) // ver,cmd,rsv,atyp,elen + "example.com" + port
		if _, err := io.ReadFull(c, req); err != nil {
			return
		}
		reqSeen <- req
		if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0x1f, 0x90}); err != nil {
			return
		}
		_, _ = io.Copy(c, c) // 隧道 echo
	})

	conn, err := socksConnectOnce(addr, "example.com", nil, 443, "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	select {
	case req := <-reqSeen:
		if req[0] != 0x05 || req[1] != socksCmdConnect || req[2] != 0x00 {
			t.Fatalf("bad request header: %x", req[:3])
		}
		if req[3] != 0x03 || int(req[4]) != len("example.com") {
			t.Fatalf("not a domain request: %x", req[:6])
		}
		if string(req[5:5+11]) != "example.com" {
			t.Fatalf("host=%q", req[5:5+11])
		}
		if port := int(req[16])<<8 | int(req[17]); port != 443 {
			t.Fatalf("port=%d", port)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server never saw CONNECT request")
	}

	// 隧道可用 + deadline 已清除：写读一轮，再闲置跨过握手预算的
	// 一小段时间确认不会因残留 deadline 报错。
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo=%q", buf)
	}
	if len(handshakeSlots) != 0 {
		t.Fatalf("handshakeSlots leaked: %d", len(handshakeSlots))
	}
}

// TestSocksConnectNoRetryOnNonTimeout 验证 socksConnect 的重试闸门：
// 上游明确拒绝（refused code 5，非超时）时必须立刻返回，
// 不允许付出 300ms 重试等待的代价。
func TestSocksConnectNoRetryOnNonTimeout(t *testing.T) {
	attempts := make(chan struct{}, 4)
	addr := startSocksTestServer(t, func(c net.Conn) {
		attempts <- struct{}{}
		_, _ = io.ReadFull(c, make([]byte, 3))
		_, _ = c.Write([]byte{0x05, 0x00})
		_, _ = io.ReadFull(c, make([]byte, 18))
		_, _ = c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		_ = c.Close()
	})
	start := time.Now()
	conn, err := socksConnect(addr, "example.com", nil, 443, "", "")
	elapsed := time.Since(start)
	if err == nil {
		_ = conn.Close()
		t.Fatal("expected refused error")
	}
	if conn != nil {
		t.Fatalf("conn=%v want nil", conn)
	}
	if elapsed >= 300*time.Millisecond {
		t.Fatalf("non-timeout error should not retry, elapsed=%v", elapsed)
	}
	if len(attempts) != 1 {
		t.Fatalf("expected exactly 1 upstream attempt, got %d", len(attempts))
	}
}
