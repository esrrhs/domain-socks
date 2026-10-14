package main

import (
	"errors"
	"io"
	"net"
	"runtime/debug"
	"strings"
	"testing"

	ghdns "github.com/esrrhs/gohome/dns"
)

// fakeLocalConn 只为 localDst 提供可控的 LocalAddr。
type fakeLocalConn struct {
	net.Conn
	local net.Addr
}

func (f *fakeLocalConn) LocalAddr() net.Addr { return f.local }

// TestLocalDstBranches 在 tproxy_test.go 的正常路径之外，补齐
// localDst 的三条分支：非 TCP 地址报错、v4-mapped 归一成 4 字节 v4、
// 纯 v6 直通。
func TestLocalDstBranches(t *testing.T) {
	_, _, err := localDst(&fakeLocalConn{local: &net.UnixAddr{Name: "x", Net: "unix"}})
	if err == nil || !strings.Contains(err.Error(), "unexpected addr type") {
		t.Fatalf("non-tcp err=%v want addr-type error", err)
	}

	ip, port, err := localDst(&fakeLocalConn{local: &net.TCPAddr{IP: net.ParseIP("::ffff:1.2.3.4"), Port: 443}})
	if err != nil {
		t.Fatal(err)
	}
	if len(ip) != net.IPv4len || !ip.Equal(net.IPv4(1, 2, 3, 4)) || port != 443 {
		t.Fatalf("mapped: ip=%v(%d bytes) port=%d want 1.2.3.4:443", ip, len(ip), port)
	}

	ip, port, err = localDst(&fakeLocalConn{local: &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 53}})
	if err != nil {
		t.Fatal(err)
	}
	if !ip.Equal(net.ParseIP("2001:db8::1")) || port != 53 {
		t.Fatalf("v6: got %s:%d", ip, port)
	}
}

// TestCloseWrite 验证半关闭：非 TCP 连接静默跳过（*net.UnixConn 走
// 不进类型断言，也不能 panic），TCP 连接上调用后对端读到 EOF、
// 本端仍可继续收数据。
func TestCloseWrite(t *testing.T) {
	closeWrite(&net.UnixConn{}) // 非 TCP：直接返回，不 panic

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type accept struct {
		c   net.Conn
		err error
	}
	accepted := make(chan accept, 1)
	go func() {
		c, err := ln.Accept()
		accepted <- accept{c, err}
	}()
	cli, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	srv := <-accepted
	if srv.err != nil {
		t.Fatal(srv.err)
	}
	defer srv.c.Close()

	closeWrite(cli)
	if _, err := io.ReadAll(srv.c); err != nil {
		t.Fatalf("server should see clean EOF after client CloseWrite: %v", err)
	}
	// 本端接收方向仍然可用
	if _, err := srv.c.Write([]byte("still-on")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	if _, err := io.ReadFull(cli, buf); err != nil {
		t.Fatalf("client read after half-close: %v", err)
	}
	if string(buf) != "still-on" {
		t.Fatalf("got %q", buf)
	}
}

// TestBuildInfoFromBranches 用伪造的 BuildInfo 驱动 readBuildInfo 的
// 解析分支：40 位 SHA 截 7 位、不足 7 位原样保留、modified 严格等于
// "true" 才算脏、无关 Setting 忽略。
func TestBuildInfoFromBranches(t *testing.T) {
	settings := func(kv ...string) []debug.BuildSetting {
		var out []debug.BuildSetting
		for i := 0; i+1 < len(kv); i += 2 {
			out = append(out, debug.BuildSetting{Key: kv[i], Value: kv[i+1]})
		}
		return out
	}
	cases := []struct {
		name       string
		settings   []debug.BuildSetting
		wantCommit string
		wantFull   string
		wantAt     string
		dirty      bool
	}{
		{"full sha", settings(
			"vcs.revision", "0123456789abcdef0123456789abcdef01234567",
			"vcs.time", "2026-10-13T09:00:00Z",
			"vcs.modified", "true"), "0123456", "0123456789abcdef0123456789abcdef01234567", "2026-10-13T09:00:00Z", true},
		{"short sha kept", settings("vcs.revision", "abc12"), "abc12", "abc12", "", false},
		{"modified false", settings(
			"vcs.revision", "abcdef0123456789",
			"vcs.modified", "false"), "abcdef0", "abcdef0123456789", "", false},
		{"modified junk is not dirty", settings(
			"vcs.revision", "abcdef0123456789",
			"vcs.modified", "yes"), "abcdef0", "abcdef0123456789", "", false},
		{"unknown keys ignored", settings("goos", "linux"), "", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := buildInfoFrom(&debug.BuildInfo{GoVersion: "go1.27.1", Settings: tc.settings})
			if b.goVersion != "go1.27.1" {
				t.Fatalf("goVersion=%q", b.goVersion)
			}
			if b.commit != tc.wantCommit || b.fullSHA != tc.wantFull {
				t.Fatalf("commit=%q full=%q want %q/%q", b.commit, b.fullSHA, tc.wantCommit, tc.wantFull)
			}
			if b.commitAt != tc.wantAt || b.modified != tc.dirty {
				t.Fatalf("at=%q dirty=%v want %q/%v", b.commitAt, b.modified, tc.wantAt, tc.dirty)
			}
		})
	}
}

func newTestUDPGateway(t *testing.T) (*udpGateway, *stats) {
	t.Helper()
	cfg := ghdns.DefaultConfig()
	cfg.EnableFakeIP = true
	resolver, err := ghdns.NewResolver(cfg)
	if err != nil {
		t.Fatal(err)
	}
	gw := newUDPGateway(resolver, "127.0.0.1:1", "", "")
	st := newStats()
	gw.setStats(st)
	return gw, st
}

// TestDeliverBackBranches 直接驱动回包分发器的四个分支：flow 缺失
// （空闲回收/串台）计 udp_reply_miss、网关已关闭静默丢弃、flow 没有
// reply 闭包不误发、reply 报错只记日志不计数；成功路径计数并把字节
// 记入该 flow 的下行方向。
func TestDeliverBackBranches(t *testing.T) {
	// flow 缺失 → miss 计数
	gw, st := newTestUDPGateway(t)
	gw.deliverBack("P|nowhere:9", []byte("x"))
	if got := st.snapshot().Counters[statUDPReplyMiss]; got != 1 {
		t.Fatalf("miss=%d want 1", got)
	}

	// 已关闭 → 不查 flow、不计数
	gw, st = newTestUDPGateway(t)
	gw.mu.Lock()
	gw.closed = true
	gw.mu.Unlock()
	gw.deliverBack("P|t:9", []byte("x"))
	snap := st.snapshot()
	if snap.Counters[statUDPReplyMiss] != 0 || snap.Counters[statUDPReplies] != 0 {
		t.Fatalf("closed gateway must not count: %v", snap.Counters)
	}

	// flow 存在但 reply 为 nil → 安全返回
	gw, st = newTestUDPGateway(t)
	gw.mu.Lock()
	gw.flows["P|t:9"] = &udpFlow{clientKey: "c"}
	gw.mu.Unlock()
	gw.deliverBack("P|t:9", []byte("x"))
	if got := st.snapshot().Counters[statUDPReplies]; got != 0 {
		t.Fatalf("nil reply counted %d", got)
	}

	// reply 报错 → 不计 replies/bytes
	gw, st = newTestUDPGateway(t)
	gw.mu.Lock()
	gw.flows["P|t:9"] = &udpFlow{clientKey: "c", reply: func([]byte) error { return errors.New("boom") }}
	gw.mu.Unlock()
	gw.deliverBack("P|t:9", []byte("x"))
	snap = st.snapshot()
	if snap.Counters[statUDPReplies] != 0 || snap.Counters[statUDPBytesOut] != 0 {
		t.Fatalf("failed reply must not count: %v", snap.Counters)
	}

	// 成功 → 载荷送达、计数、下行字节记到 flow
	gw, st = newTestUDPGateway(t)
	var got []byte
	gw.mu.Lock()
	gw.clients["c"] = &udpClient{addr: "192.168.1.5:40000"}
	gw.flows["P|t:9"] = &udpFlow{
		clientKey: "c",
		target:    "t:9",
		host:      "t",
		via:       "socks",
		reply:     func(b []byte) error { got = append([]byte(nil), b...); return nil },
	}
	gw.mu.Unlock()
	gw.deliverBack("P|t:9", []byte("payload"))
	snap = st.snapshot()
	if string(got) != "payload" {
		t.Fatalf("payload=%q", got)
	}
	if snap.Counters[statUDPReplies] != 1 || snap.Counters[statUDPBytesOut] != 7 {
		t.Fatalf("success counters=%v", snap.Counters)
	}
	gw.mu.Lock()
	f := gw.flows["P|t:9"]
	down := f.down
	gw.mu.Unlock()
	if down != 7 {
		t.Fatalf("flow down=%d want 7", down)
	}
}
