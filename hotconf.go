package main

import (
	"fmt"
	"os"
	"strconv"
	"sync/atomic"
)

// runtimeOptions 是"当前生效配置"的不可变快照：SIGHUP 重读配置文件后
// 整体替换，读侧永远拿到一个自洽的集合（不会出现"新上游 + 旧认证"）。
//
// 字段按能否在线生效分两类：
//   - 热项：每次连接/查询都读取，改了立即生效（上游地址与认证、访问
//     日志开关、AAAA 过滤开关、域名表与 GeoIP 文件路径）
//   - cold：只能启动时确定（监听地址、日志轮转参数等），这里只存其
//     字符串形式的当前值，用于变更检测 —— 改了只能提示重启。
type runtimeOptions struct {
	socks             string
	socksUser         string
	socksPass         string
	accessLog         bool
	aaaaOn            bool
	directDomainsFile string
	proxyDomainsFile  string
	geoipFile         string

	cold map[string]string
}

// coldOptions 是必须重启才能生效的选项，顺序固定用于日志稳定输出。
var coldOptions = []string{
	"dns", "listen", "tproxy", "udplisten", "udp-tproxy",
	"stats-addr", "log-file", "log-max-mb", "log-backups",
	"pprof", "direct-dns",
}

func newRuntimeOptions(o *options) *runtimeOptions {
	return &runtimeOptions{
		socks:             o.socks,
		socksUser:         o.socksUser,
		socksPass:         o.socksPass,
		accessLog:         o.accessLog,
		aaaaOn:            o.disableAAAA,
		directDomainsFile: o.directDomainsFile,
		proxyDomainsFile:  o.proxyDomainsFile,
		geoipFile:         o.geoipFile,
		cold:              coldValues(o),
	}
}

// coldValues 把冷选项拍平成字符串，供 SIGHUP 做"是否被动过"的比对。
func coldValues(o *options) map[string]string {
	return map[string]string{
		"dns":         o.dns,
		"listen":      o.listen,
		"tproxy":      o.tproxyListen,
		"udplisten":   o.udpListen,
		"udp-tproxy":  o.udpTProxy,
		"stats-addr":  o.statsAddr,
		"log-file":    o.logFile,
		"log-max-mb":  strconv.Itoa(o.logMaxMB),
		"log-backups": strconv.Itoa(o.logBackups),
		"pprof":       strconv.FormatBool(o.pprofEnable),
		"direct-dns":  o.directDNS,
	}
}

// runtimeConf 用 atomic.Value 整体换快照：SIGHUP 写一次，业务 goroutine
// 读多次，无锁、无撕裂、无读写竞争。
type runtimeConf struct {
	v atomic.Value // *runtimeOptions
}

func newRuntimeConf(o *runtimeOptions) *runtimeConf {
	c := &runtimeConf{}
	c.v.Store(o)
	return c
}

func (c *runtimeConf) get() *runtimeOptions {
	if o, ok := c.v.Load().(*runtimeOptions); ok {
		return o
	}
	return nil
}

func (c *runtimeConf) set(o *runtimeOptions) { c.v.Store(o) }

// aaaaEnabled 供 DNS 过滤层每次查询调用。
func (c *runtimeConf) aaaaEnabled() bool {
	if o := c.get(); o != nil {
		return o.aaaaOn
	}
	return false
}

// pick 决定一个选项的新值：命令行显式给过 -> 死守当前值（文件永远顶不
// 掉命令行）；否则取按类型解析好的文件值；文件里没写 -> 回落内置默认。
// def 由调用方用 config.String/Bool/Int(name, builtinX) 算好，类型非法
// 时 config 已记录到 errs，随后 validate 统一报错。
func pick(cmdline map[string]bool, name, cur, def string) string {
	if cmdline[name] {
		return cur
	}
	return def
}

// pickBool 是 pick 的布尔版本（避免字符串往返）。
func pickBool(cmdline map[string]bool, name string, cur, def bool) bool {
	if cmdline[name] {
		return cur
	}
	return def
}

// upstreamSetter / proxyAddrUpdater 是热更新上游时需要同步的下游：前者
// 是 UDP relay（换上游即作废旧 ASSOCIATE），后者是 resolver 的远程 DoH
// 代理地址。抽成接口以便单测编排。
type upstreamSetter interface {
	setUpstream(addr, user, pass string)
}

type proxyAddrUpdater interface {
	UpdateProxyAddress(proxyAddr string) error
}

// socksProxyURL 把 -socks 的 host:port 转成 gohome DoH 上游能识别的
// socks5 URL。注意 gohome 内部用 proxy.SOCKS5("tcp", host, nil, ...) 构造
// 拨号器 —— **忽略 URL 里的 userinfo**，也就是说 DoH over socks5 无法带
// 用户名密码。因此只在 -socks 无认证时返回可用 URL：宁可不用远端 DNS，
// 也不能让需要远端解析的查询明文直连（既不可达又泄漏查询内容）。
func socksProxyURL(addr, user, pass string) string {
	if addr == "" || user != "" || pass != "" {
		return ""
	}
	return "socks5://" + addr
}

// applyUpstream 把新上游同步给所有持有它的组件。带认证的上游走不了 DoH
// 代理，此时 resolver 保持现状（调用方负责提示重启），绝不回落成明文直连。
func applyUpstream(gw upstreamSetter, rl proxyAddrUpdater, addr, user, pass string) error {
	gw.setUpstream(addr, user, pass)
	url := socksProxyURL(addr, user, pass)
	if url == "" || rl == nil {
		return nil
	}
	return rl.UpdateProxyAddress(url)
}

// reloadRuntimeOptions 重读配置文件，按"命令行 > 配置文件 > 内置默认"
// 重新计算生效值。返回新快照、本次热生效的键、以及改了但必须重启的键。
// 任何解析/校验错误都原样返回旧快照：一次写坏的 SIGHUP 不能让正在跑的
// 代理失去上游。
func reloadRuntimeOptions(path string, cmdline map[string]bool, builtin *options, cur *runtimeOptions) (*runtimeOptions, []string, []string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return cur, nil, nil, fmt.Errorf("read config %s: %w", path, err)
	}
	vals, err := parseConfigFile(data)
	if err != nil {
		return cur, nil, nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	c := &config{path: path, vals: vals}

	next := *cur // 值拷贝；cold 下面整体替换，不与旧快照共享 map
	next.socks = pick(cmdline, "socks", cur.socks, c.String("socks", builtin.socks))
	next.socksUser = pick(cmdline, "socks-user", cur.socksUser, c.String("socks-user", builtin.socksUser))
	next.socksPass = pick(cmdline, "socks-pass", cur.socksPass, c.String("socks-pass", builtin.socksPass))
	next.accessLog = pickBool(cmdline, "access-log", cur.accessLog, c.Bool("access-log", builtin.accessLog))
	next.aaaaOn = pickBool(cmdline, "disable-aaaa", cur.aaaaOn, c.Bool("disable-aaaa", builtin.disableAAAA))
	next.directDomainsFile = pick(cmdline, "direct-domains-file", cur.directDomainsFile,
		c.String("direct-domains-file", builtin.directDomainsFile))
	next.proxyDomainsFile = pick(cmdline, "proxy-domains-file", cur.proxyDomainsFile,
		c.String("proxy-domains-file", builtin.proxyDomainsFile))
	next.geoipFile = pick(cmdline, "geoip", cur.geoipFile, c.String("geoip", builtin.geoipFile))

	// 冷项只做检测：算出"若此刻重启会生效的值"，与当前值比对。
	// log-max-mb/log-backups/pprof 走 c.Int/c.Bool 仍是为了让类型非法的
	// 值进入 errs，validate 阶段一并报出来。
	nextCold := map[string]string{
		"dns":         pick(cmdline, "dns", cur.cold["dns"], c.String("dns", builtin.dns)),
		"listen":      pick(cmdline, "listen", cur.cold["listen"], c.String("listen", builtin.listen)),
		"tproxy":      pick(cmdline, "tproxy", cur.cold["tproxy"], c.String("tproxy", builtin.tproxyListen)),
		"udplisten":   pick(cmdline, "udplisten", cur.cold["udplisten"], c.String("udplisten", builtin.udpListen)),
		"udp-tproxy":  pick(cmdline, "udp-tproxy", cur.cold["udp-tproxy"], c.String("udp-tproxy", builtin.udpTProxy)),
		"stats-addr":  pick(cmdline, "stats-addr", cur.cold["stats-addr"], c.String("stats-addr", builtin.statsAddr)),
		"log-file":    pick(cmdline, "log-file", cur.cold["log-file"], c.String("log-file", builtin.logFile)),
		"log-max-mb":  pick(cmdline, "log-max-mb", cur.cold["log-max-mb"], strconv.Itoa(c.Int("log-max-mb", builtin.logMaxMB))),
		"log-backups": pick(cmdline, "log-backups", cur.cold["log-backups"], strconv.Itoa(c.Int("log-backups", builtin.logBackups))),
		"pprof":       pick(cmdline, "pprof", cur.cold["pprof"], strconv.FormatBool(c.Bool("pprof", builtin.pprofEnable))),
		"direct-dns":  pick(cmdline, "direct-dns", cur.cold["direct-dns"], c.String("direct-dns", builtin.directDNS)),
	}
	next.cold = nextCold

	// 键名必须真实存在、值必须类型正确：与启动时同一套严格校验，
	// 防止改文件时一个拼写错误让上游静默回落。
	if err := c.validate(); err != nil {
		return cur, nil, nil, err
	}

	var changed []string
	if next.socks != cur.socks {
		changed = append(changed, "socks")
	}
	if next.socksUser != cur.socksUser {
		changed = append(changed, "socks-user")
	}
	if next.socksPass != cur.socksPass {
		changed = append(changed, "socks-pass")
	}
	if next.accessLog != cur.accessLog {
		changed = append(changed, "access-log")
	}
	if next.aaaaOn != cur.aaaaOn {
		changed = append(changed, "disable-aaaa")
	}
	if next.directDomainsFile != cur.directDomainsFile {
		changed = append(changed, "direct-domains-file")
	}
	if next.proxyDomainsFile != cur.proxyDomainsFile {
		changed = append(changed, "proxy-domains-file")
	}
	if next.geoipFile != cur.geoipFile {
		changed = append(changed, "geoip")
	}
	var cold []string
	for _, name := range coldOptions {
		if nextCold[name] != cur.cold[name] {
			cold = append(cold, name)
		}
	}
	return &next, changed, cold, nil
}
