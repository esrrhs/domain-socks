package main

import (
	"errors"
	"strings"
	"testing"
)

// fakeReloader 记录 reloadConfig 对 resolver 的调用序列，
// 可按文件路径注入加载错误。
type fakeReloader struct {
	calls       []string
	directN     int
	proxyN      int
	failLoad    map[string]error
	failGeoIP   bool
	cleared     bool
	resetDirect [][]string
	resetProxy  [][]string
}

func (f *fakeReloader) UpdateDirectDomains(domains []string) {
	f.calls = append(f.calls, "reset-direct")
	f.resetDirect = append(f.resetDirect, domains)
}

func (f *fakeReloader) UpdateProxyDomains(domains []string) {
	f.calls = append(f.calls, "reset-proxy")
	f.resetProxy = append(f.resetProxy, domains)
}

func (f *fakeReloader) LoadDirectDomainFile(p string) (int, error) {
	f.calls = append(f.calls, "load-direct:"+p)
	if err := f.failLoad[p]; err != nil {
		return 0, err
	}
	return f.directN, nil
}

func (f *fakeReloader) LoadProxyDomainFile(p string) (int, error) {
	f.calls = append(f.calls, "load-proxy:"+p)
	if err := f.failLoad[p]; err != nil {
		return 0, err
	}
	return f.proxyN, nil
}

func (f *fakeReloader) ReloadGeoIPDatabase(p string) error {
	f.calls = append(f.calls, "geoip:"+p)
	if f.failGeoIP {
		return errors.New("mmdb corrupt")
	}
	return nil
}

func (f *fakeReloader) ClearCache() {
	f.calls = append(f.calls, "clear-cache")
	f.cleared = true
}

func TestReloadConfigSuccess(t *testing.T) {
	dir := t.TempDir()
	dFile := dir + "/direct.conf"
	pFile := dir + "/proxy.conf"
	gFile := dir + "/country.mmdb"

	fr := &fakeReloader{directN: 42, proxyN: 7}
	summary, err := reloadConfig(nil, fr, dFile, pFile, gFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 顺序必须是：每张表先 Reset（删除的规则才能失效）再加载文件，
	// GeoIP 其后，最后清缓存（保证新规则对后续查询生效）。
	wantCalls := []string{
		"reset-direct", "load-direct:" + dFile,
		"reset-proxy", "load-proxy:" + pFile,
		"geoip:" + gFile, "clear-cache",
	}
	if strings.Join(fr.calls, "|") != strings.Join(wantCalls, "|") {
		t.Fatalf("call order=%v\nwant %v", fr.calls, wantCalls)
	}
	// Reset 传 nil：保留 gohome 内置直连默认，只清用户自定义
	if len(fr.resetDirect[0]) != 0 || len(fr.resetProxy[0]) != 0 {
		t.Fatal("reset must pass nil/empty user domains")
	}
	for _, want := range []string{"direct domains=42", "proxy domains=7", "geoip reloaded"} {
		if !strings.Contains(summary, want) {
			t.Fatalf("summary=%q missing %q", summary, want)
		}
	}
}

// 错误隔离：direct 文件坏掉不能阻止 proxy/geoip/cache 继续执行，
// 错误聚合返回；没有 geoip 文件时摘要不应声称已重载。
func TestReloadConfigErrorAggregation(t *testing.T) {
	dir := t.TempDir()
	dFile := dir + "/direct.conf"
	pFile := dir + "/proxy.conf"

	fr := &fakeReloader{
		proxyN:   3,
		failLoad: map[string]error{dFile: errors.New("no such file")},
	}
	summary, err := reloadConfig(nil, fr, dFile, pFile, "")
	if err == nil {
		t.Fatal("expected aggregated error")
	}
	if !strings.Contains(err.Error(), "load direct domains") {
		t.Fatalf("error=%v must mention direct domains", err)
	}
	if !fr.cleared {
		t.Fatal("ClearCache must still run after a file load failure")
	}
	joined := strings.Join(fr.calls, "|")
	if !strings.Contains(joined, "load-proxy:"+pFile) {
		t.Fatalf("proxy load must not be skipped:\n%v", fr.calls)
	}
	if strings.Contains(summary, "geoip reloaded") {
		t.Fatalf("summary must not claim geoip when no file configured: %q", summary)
	}
	if !strings.Contains(summary, "proxy domains=3") {
		t.Fatalf("summary=%q should still report proxy count", summary)
	}

	// geoip 坏也只作为聚合错误的一项
	fr2 := &fakeReloader{failGeoIP: true}
	_, err = reloadConfig(nil, fr2, "", "", dir+"/x.mmdb")
	if err == nil || !strings.Contains(err.Error(), "reload geoip") {
		t.Fatalf("geoip error expected, got %v", err)
	}
	if !fr2.cleared {
		t.Fatal("cache must be cleared even when geoip reload fails")
	}
}

func TestReloadConfigNoOptions(t *testing.T) {
	// 未配置任何文件：不触碰 resolver，也不应报错（纯 SIGHUP 仅 reopen 日志）
	fr := &fakeReloader{}
	summary, err := reloadConfig(nil, fr, "", "", "")
	if err != nil || fr.cleared || len(fr.calls) != 0 {
		t.Fatalf("empty reload touched resolver: summary=%q err=%v calls=%v", summary, err, fr.calls)
	}
	if !strings.Contains(summary, "direct domains=0") || !strings.Contains(summary, "proxy domains=0") {
		t.Fatalf("summary=%q", summary)
	}
}

func TestReloadConfigNilSafe(t *testing.T) {
	// lw=nil（文件日志未开）且 rl=nil 也不能 panic
	summary, err := reloadConfig(nil, nil, "/x/direct.conf", "", "")
	if err != nil {
		t.Fatalf("nil reload err=%v", err)
	}
	if !strings.Contains(summary, "reload complete") {
		t.Fatalf("summary=%q", summary)
	}
}
