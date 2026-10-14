package main

import (
	"net"
	"strings"
	"testing"
)

// fakeControl 只为 resolveRelayAddr 提供可控的 RemoteAddr——该函数只读
// 控制连接的对端地址，不做任何 IO，嵌入的 nil net.Conn 不会被触碰。
type fakeControl struct {
	net.Conn
	remote net.Addr
}

func (f *fakeControl) RemoteAddr() net.Addr { return f.remote }

// TestResolveRelayAddrHostBranches 覆盖 bndHost 分支与地址兜底分支：
// 确定性解析失败（.invalid 为 RFC 6761 保留 TLD，保证 NXDOMAIN）、
// 控制连接为 IPv6 时域名 relay 正常返回、控制连接不是 TCPAddr 且
// 地址/端口不完整时兜底报错、显式 IPv6 relay 原样使用。
func TestResolveRelayAddrHostBranches(t *testing.T) {
	v6ctl := &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1080}
	nonTCP := &net.UnixAddr{Name: "dumb", Net: "unix"}

	// 域名解析失败必须原样返回错误
	if _, err := resolveRelayAddr(&fakeControl{remote: v6ctl}, "nxdomain.invalid", nil, 0); err == nil {
		t.Fatal("expected lookup error for .invalid host")
	}

	// 控制连接是 IPv6 时不触发 v4/v6 错配检查，localhost 无论先回
	// v4 还是 v6 都应得到 :43 的 relay 地址
	a, err := resolveRelayAddr(&fakeControl{remote: v6ctl}, "localhost", nil, 43)
	if err != nil {
		t.Fatal(err)
	}
	if a.Port != 43 || !a.IP.IsLoopback() {
		t.Fatalf("relay=%s want loopback:43", a)
	}

	// bndIP 为 nil 且控制连接非 TCP：无从补全，必须报错
	if _, err := resolveRelayAddr(&fakeControl{remote: nonTCP}, "", nil, 43); err == nil ||
		!strings.Contains(err.Error(), "unusable") {
		t.Fatalf("nil ip err=%v want unusable relay address", err)
	}

	// port 为 0 且控制连接非 TCP：同样不可用
	if _, err := resolveRelayAddr(&fakeControl{remote: nonTCP}, "", net.IPv4(8, 8, 8, 8), 0); err == nil ||
		!strings.Contains(err.Error(), "unusable") {
		t.Fatalf("zero port err=%v want unusable relay address", err)
	}

	// 0.0.0.0 且无法从控制连接补全
	if _, err := resolveRelayAddr(&fakeControl{remote: nonTCP}, "", net.IPv4zero, 43); err == nil ||
		!strings.Contains(err.Error(), "unusable") {
		t.Fatalf("unspecified err=%v want unusable relay address", err)
	}

	// 显式 IPv6 relay 地址原样使用
	a, err = resolveRelayAddr(&fakeControl{remote: nonTCP}, "", net.ParseIP("2001:db8::5"), 43)
	if err != nil {
		t.Fatal(err)
	}
	if a.String() != "[2001:db8::5]:43" {
		t.Fatalf("relay=%s want [2001:db8::5]:43", a)
	}
}

// TestResolveRelayAddrV4DomainMismatch 覆盖"上游控制连接是 IPv4、
// relay 域名却解析出 IPv6"的错配保护。离线环境无法构造 v6-only
// 域名，因此断言收敛为不变量：v4 控制 + localhost 时，要么解析到
// v4 地址成功，要么触发错配错误——绝不能静默返回一个 v4 拨不通的
// v6 relay。
func TestResolveRelayAddrV4DomainMismatch(t *testing.T) {
	v4ctl := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1080}
	a, err := resolveRelayAddr(&fakeControl{remote: v4ctl}, "localhost", nil, 43)
	if err != nil {
		if !strings.Contains(err.Error(), "resolved to ipv6 but proxy is ipv4") {
			t.Fatalf("unexpected err: %v", err)
		}
		return
	}
	if a.IP.To4() == nil {
		t.Fatalf("v6 relay %s returned for ipv4 proxy without error", a)
	}
	if a.Port != 43 || !a.IP.IsLoopback() {
		t.Fatalf("relay=%s want loopback:43", a)
	}
}
