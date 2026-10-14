package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	ghdns "github.com/esrrhs/gohome/dns"
	"github.com/miekg/dns"
)

// registerOptionsOnce 保证真实选项只在 flag.CommandLine 上注册一次：
// config.validate 用 flag.Lookup 判断键是否真实存在，而测试不会执行
// main()，必须先注册，否则每个键都会误报 unknown option。
var registerOptionsOnce sync.Once

// testBuiltinOptions 注册真实选项并返回一份纯内置默认值。
func testBuiltinOptions(t *testing.T) *options {
	t.Helper()
	registerOptionsOnce.Do(func() {
		defineFlags(flag.CommandLine, &config{vals: map[string]string{}})
	})
	scratch := defineFlags(flag.NewFlagSet("builtin-defaults", flag.ContinueOnError),
		&config{vals: map[string]string{}})
	return scratch.options()
}

func writeConf(t *testing.T, dir, body string) string {
	t.Helper()
	path := filepath.Join(dir, "domain-socks.conf")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// TestReloadRuntimeOptionsHotApply 验证 SIGHUP 重读后热项立即生效：
// 上游、认证、访问日志开关、AAAA 过滤、规则文件路径都换到文件里的新值，
// 且被准确无误地列进 changed。
func TestReloadRuntimeOptionsHotApply(t *testing.T) {
	builtin := testBuiltinOptions(t)
	dir := t.TempDir()
	path := writeConf(t, dir, strings.Join([]string{
		"socks = 10.0.0.2:1080",
		"socks-user = alice",
		"socks-pass = s3cret",
		"access-log = false",
		"disable-aaaa = false",
		"direct-domains-file = /tmp/direct.txt",
		"",
	}, "\n"))

	// 从内置默认起算，只改被测项：否则构造出的空冷项会被误判为变更
	base := *builtin
	base.socks, base.accessLog, base.disableAAAA = "10.0.0.1:1080", true, true
	cur := newRuntimeOptions(&base)
	next, changed, cold, err := reloadRuntimeOptions(path, nil, builtin, cur)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if next.socks != "10.0.0.2:1080" || next.socksUser != "alice" || next.socksPass != "s3cret" {
		t.Fatalf("upstream not applied: %+v", next)
	}
	if next.accessLog {
		t.Fatal("access-log=false not applied")
	}
	if next.aaaaOn {
		t.Fatal("disable-aaaa=false not applied")
	}
	if next.directDomainsFile != "/tmp/direct.txt" {
		t.Fatalf("direct-domains-file=%q", next.directDomainsFile)
	}
	for _, want := range []string{"socks", "socks-user", "socks-pass", "access-log", "disable-aaaa", "direct-domains-file"} {
		if !contains(changed, want) {
			t.Fatalf("changed=%v missing %q", changed, want)
		}
	}
	if len(cold) != 0 {
		t.Fatalf("unexpected cold changes: %v", cold)
	}
}

// TestReloadRuntimeOptionsCmdlineWins 验证命令行显式给过的项不会被配置
// 文件顶掉：管理员在命令行上的决定优先级最高，改文件不该悄悄生效。
func TestReloadRuntimeOptionsCmdlineWins(t *testing.T) {
	builtin := testBuiltinOptions(t)
	dir := t.TempDir()
	path := writeConf(t, dir, "socks = 10.0.0.2:1080\naccess-log = false\n")

	base := *builtin
	base.socks, base.accessLog = "192.168.9.9:1080", true
	cur := newRuntimeOptions(&base)
	next, changed, _, err := reloadRuntimeOptions(path,
		map[string]bool{"socks": true}, builtin, cur)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if next.socks != "192.168.9.9:1080" {
		t.Fatalf("command-line socks must win, got %q", next.socks)
	}
	if contains(changed, "socks") {
		t.Fatalf("socks must not be reported as changed: %v", changed)
	}
	// 未显式指定的项照常跟随文件
	if next.accessLog {
		t.Fatal("access-log from file must still apply")
	}
}

// TestReloadRuntimeOptionsFallsBackToBuiltin 验证文件里删掉的键回落到
// 内置默认，与"启动时没有这一行"完全一致，避免配置项残留。
func TestReloadRuntimeOptionsFallsBackToBuiltin(t *testing.T) {
	builtin := testBuiltinOptions(t)
	dir := t.TempDir()
	path := writeConf(t, dir, "# socks 这一行已被删除\n")

	base := *builtin
	base.socks = "10.0.0.2:1080"
	cur := newRuntimeOptions(&base)
	next, changed, _, err := reloadRuntimeOptions(path, nil, builtin, cur)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if next.socks != builtin.socks {
		t.Fatalf("socks=%q want builtin %q", next.socks, builtin.socks)
	}
	if !contains(changed, "socks") {
		t.Fatalf("changed=%v missing socks", changed)
	}
}

// TestReloadRuntimeOptionsColdDetected 验证冷项（监听地址、DNS、日志轮转
// 等）只做检测：不写进热字段，但明确列出来提示需要重启。
func TestReloadRuntimeOptionsColdDetected(t *testing.T) {
	builtin := testBuiltinOptions(t)
	dir := t.TempDir()
	path := writeConf(t, dir, "listen = 0.0.0.0:9999\ndns = 127.0.0.1:15353\nlog-max-mb = 5\n")

	cur := newRuntimeOptions(builtin)
	next, changed, cold, err := reloadRuntimeOptions(path, nil, builtin, cur)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{"listen", "dns", "log-max-mb"} {
		if !contains(cold, want) {
			t.Fatalf("cold=%v missing %q", cold, want)
		}
	}
	if len(changed) != 0 {
		t.Fatalf("cold options must not be hot-applied: %v", changed)
	}
	// 冷项的新值记录在快照里，供下一次 SIGHUP 继续比对（幂等）
	next2, _, cold2, err := reloadRuntimeOptions(path, nil, builtin, next)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cold2) != 0 {
		t.Fatalf("second reload must be a no-op, got %v", cold2)
	}
	_ = next2
}

// TestReloadRuntimeOptionsBadFileKeepsCurrent 验证写坏的文件不会让进程
// 失去上游：非法字面量、未知键、读不到文件都返回错误并保持旧快照。
func TestReloadRuntimeOptionsBadFileKeepsCurrent(t *testing.T) {
	builtin := testBuiltinOptions(t)
	dir := t.TempDir()
	cur := newRuntimeOptions(builtin)

	cases := map[string]string{
		"invalid bool":   "access-log = maybe\n",
		"invalid int":    "log-backups = many\n",
		"unknown key":    "socks-server = 10.0.0.2:1080\n",
		"malformed line": "socks\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			path := writeConf(t, dir, body)
			next, changed, cold, err := reloadRuntimeOptions(path, nil, builtin, cur)
			if err == nil {
				t.Fatalf("expected error for %q", body)
			}
			if next != cur {
				t.Fatal("must keep the current snapshot on error")
			}
			if len(changed) != 0 || len(cold) != 0 {
				t.Fatalf("no changes may be reported: %v %v", changed, cold)
			}
		})
	}

	t.Run("missing file", func(t *testing.T) {
		if _, _, _, err := reloadRuntimeOptions(filepath.Join(dir, "gone.conf"), nil, builtin, cur); err == nil {
			t.Fatal("expected error for missing file")
		}
	})
}

// TestRuntimeConfConcurrentSwap 验证热配置换快照是原子的：读侧永远看到
// 一个自洽集合（-race 下不得报竞争，也不得读到 nil）。
func TestRuntimeConfConcurrentSwap(t *testing.T) {
	initial := newRuntimeOptions(&options{socks: "10.0.0.1:1080"})
	rc := newRuntimeConf(initial)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 2000; i++ {
			// 代次标记：socks 末段与用户名绑定，读侧可校验二者同源
			gen := i%250 + 1
			rc.set(&runtimeOptions{
				socks:     fmt.Sprintf("10.0.0.%d:1080", gen),
				socksUser: fmt.Sprintf("u%d", gen),
				cold:      map[string]string{},
			})
		}
		close(done)
	}()
	for i := 0; i < 2000; i++ {
		o := rc.get()
		if o == nil {
			t.Fatal("nil snapshot")
		}
		if o.socks == "" {
			t.Fatal("torn snapshot: empty socks")
		}
		// 快照整体替换：地址与用户名必须来自同一代，混代即为撕裂
		if o.socksUser != "" {
			want := "10.0.0." + strings.TrimPrefix(o.socksUser, "u") + ":1080"
			if o.socks != want {
				t.Fatalf("torn snapshot: socks=%q user=%q", o.socks, o.socksUser)
			}
		}
	}
	<-done
}

// TestAAAAFilterFollowsHotConfig 验证 -disable-aaaa 的热开关真的生效：
// 同一个 filter 在 SIGHUP 之后立即改变行为，无需重启进程。
func TestAAAAFilterFollowsHotConfig(t *testing.T) {
	stub := &stubExchangeResolver{proxyDomains: map[string]bool{"www.google.com": true}}
	st := newStats()
	rc := newRuntimeConf(&runtimeOptions{aaaaOn: true, cold: map[string]string{}})
	f := &aaaaFilter{Resolver: stub, st: st, enabled: rc.aaaaEnabled}

	aaaa := new(dns.Msg)
	aaaa.SetQuestion("www.google.com.", dns.TypeAAAA)

	if _, err := f.Exchange(context.Background(), aaaa); err != nil {
		t.Fatal(err)
	}
	if got := st.snapshot().Counters[statDNSAAAAFiltered]; got != 1 {
		t.Fatalf("filtered=%d want 1 while enabled", got)
	}
	if stub.upstreamHits != 0 {
		t.Fatalf("enabled filter must not hit upstream, got %d", stub.upstreamHits)
	}

	// SIGHUP：disable-aaaa = false
	rc.set(&runtimeOptions{aaaaOn: false, cold: map[string]string{}})
	if _, err := f.Exchange(context.Background(), aaaa); err != nil {
		t.Fatal(err)
	}
	if stub.upstreamHits != 1 {
		t.Fatalf("disabled filter must forward AAAA upstream, hits=%d", stub.upstreamHits)
	}
	if got := st.snapshot().Counters[statDNSAAAAFiltered]; got != 1 {
		t.Fatalf("filtered must stay 1 after disable, got %d", got)
	}
}

// TestUDPGatewaySetUpstream 验证换了上游之后 UDP 侧会用新地址重新握手：
// 旧 ASSOCIATE 作废，新包走新上游（否则换 socks 后 UDP 流量仍打向旧代理）。
func TestUDPGatewaySetUpstream(t *testing.T) {
	old := startMockSocks5UDP(t)
	defer old.stop()
	next := startMockSocks5UDP(t)
	defer next.stop()

	cfg := ghdns.DefaultConfig()
	cfg.EnableFakeIP = true
	resolver, err := ghdns.NewResolver(cfg)
	if err != nil {
		t.Fatal(err)
	}
	gw := newUDPGateway(resolver, old.addr(), "", "")
	gw.setStats(newStats())
	defer gw.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ip, _ := resolver.ResolveOne(ctx, "www.google.com")

	replies := make(chan []byte, 4)
	reply := func(b []byte) error { replies <- b; return nil }

	gw.handle([]byte("OLD"), "c", ip, 1000, reply, func() {})
	waitUDPReply(t, replies, "OLD")

	gw.setUpstream(next.addr(), "", "")
	gw.handle([]byte("NEW"), "c", ip, 1000, reply, func() {})
	waitUDPReply(t, replies, "NEW")

	// 新上游确实接到了握手与数据
	deadline := time.Now().Add(2 * time.Second)
	for {
		next.mu.Lock()
		hits, host := next.controlCount, next.lastHost
		next.mu.Unlock()
		if hits > 0 && host == "www.google.com" {
			break
		}
		if time.Now().After(deadline) {
			old.mu.Lock()
			oldHits := old.controlCount
			old.mu.Unlock()
			next.mu.Lock()
			nHits, nHost := next.controlCount, next.lastHost
			next.mu.Unlock()
			t.Fatalf("new upstream not used: new control=%d host=%q, old control=%d", nHits, nHost, oldHits)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestUDPProxyRelaySetUpstreamDropsAssociation 验证热更新会作废已建立的
// ASSOCIATE：旧控制连接被关闭，assocIsUp 归零，下一个包重新握手。
func TestUDPProxyRelaySetUpstreamDropsAssociation(t *testing.T) {
	mock := startMockSocks5UDP(t)
	defer mock.stop()

	r := newUDPProxyRelay(mock.addr(), "", "", func(string, int, []byte) {})
	r.stats = newStats()
	defer r.close()

	if err := r.ensureAssoc(); err != nil {
		t.Fatal(err)
	}
	if r.assocIsUp() != 1 {
		t.Fatal("association should be up")
	}
	mock.mu.Lock()
	before := len(mock.controls)
	mock.mu.Unlock()
	if before != 1 {
		t.Fatalf("expected 1 control connection, got %d", before)
	}

	r.setUpstream("127.0.0.1:1", "", "")
	if r.assocIsUp() != 0 {
		t.Fatal("association must be dropped after upstream swap")
	}
	// 凭证与代次都已换掉
	addr, _, _, gen := r.creds()
	if addr != "127.0.0.1:1" || gen == 0 {
		t.Fatalf("creds not swapped: addr=%q gen=%d", addr, gen)
	}
	// 失败冷却一并清除：换上游后应立刻允许重拨
	r.mu.Lock()
	cd := r.cooldownUntil
	r.mu.Unlock()
	if !cd.IsZero() {
		t.Fatal("cooldown must reset on upstream swap")
	}
	// 切回可用上游后必须重新握手（旧 ASSOCIATE 已作废，不能复用）
	r.setUpstream(mock.addr(), "", "")
	if err := r.ensureAssoc(); err != nil {
		t.Fatalf("re-associate after swap: %v", err)
	}
	mock.mu.Lock()
	after := mock.controlCount
	mock.mu.Unlock()
	if after != 2 {
		t.Fatalf("expected a fresh handshake, control connections=%d", after)
	}
}
