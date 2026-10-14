package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanConfigPath(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		want    string
		wantErr bool
	}{
		{"absent", []string{"-socks", "1.2.3.4"}, "", false},
		{"no args", nil, "", false},
		{"space form", []string{"-config", "/etc/domain-socks.conf"}, "/etc/domain-socks.conf", false},
		{"long space form", []string{"--config", "/etc/x"}, "/etc/x", false},
		{"eq form", []string{"-config=/etc/x"}, "/etc/x", false},
		{"long eq form", []string{"--config=/etc/x"}, "/etc/x", false},
		{"after other flags", []string{"-socks", "a:1", "-config", "/etc/x", "-version"}, "/etc/x", false},
		{"empty value ok", []string{"-config="}, "", false},
		{"missing value", []string{"-socks", "a", "-config"}, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := scanConfigPath(tc.args)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %q err %v want %q", got, err, tc.want)
			}
		})
	}
}

func TestParseConfigFile(t *testing.T) {
	in := `
# 整行注释
   # 缩进注释也是注释

socks = 10.0.0.1:1080
 -dns=0.0.0.0:53
--log-backups=5
access-log=false
socks-pass=a=b=c
direct-domains-file=
proxy-domains-file=
`
	got, err := parseConfigFile([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"socks":               "10.0.0.1:1080",
		"dns":                 "0.0.0.0:53",
		"log-backups":         "5",
		"access-log":          "false",
		"socks-pass":          "a=b=c", // 只按第一个 = 切分，密码里的 = 原样保留
		"direct-domains-file": "",
		"proxy-domains-file":  "",
	}
	if len(got) != len(want) {
		t.Fatalf("keys=%v want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("%s=%q want %q", k, got[k], v)
		}
	}

	bad := []struct {
		in   string
		want string
	}{
		{"socks 1.2.3.4", "expected key=value"},
		{"=value", "empty key"},
		{"a=1\n  bad line", "line 2"},
	}
	for _, tc := range bad {
		if _, err := parseConfigFile([]byte(tc.in)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("parse %q err=%v want %q", tc.in, err, tc.want)
		}
	}

	// 重复键：后写覆盖前写
	dup, err := parseConfigFile([]byte("socks=a\nsocks=b\n"))
	if err != nil || dup["socks"] != "b" {
		t.Fatalf("dup=%v err=%v", dup, err)
	}
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ds.conf")
	if err := os.WriteFile(path, []byte("socks=9.9.9.9:1080\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := loadConfig([]string{"-config", path})
	if err != nil {
		t.Fatal(err)
	}
	if c.path != path || c.String("socks", "") != "9.9.9.9:1080" {
		t.Fatalf("cfg=%+v", c)
	}

	// 没有 -config：一切走默认，不报错
	c, err = loadConfig([]string{"-socks", "1.2.3.4"})
	if err != nil || c.path != "" || len(c.vals) != 0 {
		t.Fatalf("no-config cfg=%+v err=%v", c, err)
	}
	if got := c.String("socks", "fallback"); got != "fallback" {
		t.Fatalf("got %q", got)
	}

	// 文件不存在必须显式失败，不能静默用默认值起代理
	if _, err := loadConfig([]string{"-config", filepath.Join(dir, "nope.conf")}); err == nil ||
		!strings.Contains(err.Error(), "read config") {
		t.Fatalf("err=%v", err)
	}
}

func TestConfigTypedDefaults(t *testing.T) {
	c, err := parseConfigFileTest(t, "b1=true\nb2=0\nb3=nope\ni1=7\ni2=1\ni3=x\n")
	if err != nil {
		t.Fatal(err)
	}
	if !c.Bool("b1", false) || c.Bool("b2", true) {
		t.Fatal("bool parsing broken")
	}
	if c.Bool("b3", true) != true || len(c.errs) != 1 || !strings.Contains(c.errs[0], "b3: invalid bool") {
		t.Fatalf("bad bool must keep default and record error: %v", c.errs)
	}
	if c.Int("i1", 0) != 7 || c.Int("i2", 0) != 1 {
		t.Fatal("int parsing broken")
	}
	if c.Int("i3", 5) != 5 || len(c.errs) != 2 || !strings.Contains(c.errs[1], "i3: invalid int") {
		t.Fatalf("bad int must keep default and record error: %v", c.errs)
	}
	if !c.Has("i1") || !c.Has("b3") {
		t.Fatal("Has must be true for present keys")
	}
	if c.Has("missing") {
		t.Fatal("Has(missing)")
	}
}

func parseConfigFileTest(t *testing.T, in string) (*config, error) {
	t.Helper()
	vals, err := parseConfigFile([]byte(in))
	if err != nil {
		return nil, err
	}
	return &config{path: "test.conf", vals: vals}, nil
}

// TestConfigValidate 验证两件事：未知键（拼写错误）与非法值都必须
// 让 validate 报错；已知键、合法值返回 nil。
func TestConfigValidate(t *testing.T) {
	// 借用全局 flag.CommandLine 注册一个已知键（main 里同理定义所有选项）
	if flag.Lookup("cfgvalidate-known") == nil {
		flag.String("cfgvalidate-known", "", "test flag")
	}

	c, err := parseConfigFileTest(t, "cfgvalidate-known=ok\nsock=typo\n")
	if err != nil {
		t.Fatal(err)
	}
	verr := c.validate()
	if verr == nil || !strings.Contains(verr.Error(), "unknown option") ||
		!strings.Contains(verr.Error(), "sock") {
		t.Fatalf("unknown key err=%v", verr)
	}

	c, err = parseConfigFileTest(t, "cfgvalidate-known=ok\n")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.validate(); err != nil {
		t.Fatalf("known key err=%v", err)
	}

	c, err = parseConfigFileTest(t, "cfgvalidate-known=ok\n")
	if err != nil {
		t.Fatal(err)
	}
	c.errs = append(c.errs, `b3: invalid bool "nope"`)
	if verr := c.validate(); verr == nil || !strings.Contains(verr.Error(), "invalid bool") {
		t.Fatalf("typed err=%v", verr)
	}
}

// TestConfigPriorityChain 复刻 main 的注入方式验证三级优先：
// 内置默认 < 配置文件 < 命令行。
func TestConfigPriorityChain(t *testing.T) {
	for _, tc := range []struct {
		file string
		cli  []string
		want string
	}{
		{"", nil, "builtin"},
		{"opt=fromfile", nil, "fromfile"},
		{"opt=fromfile", []string{"-opt", "fromcli"}, "fromcli"},
		{"opt=", nil, ""}, // 文件显式给空值：尊重文件
	} {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		c := &config{path: "t.conf", vals: map[string]string{}}
		if tc.file != "" {
			vals, err := parseConfigFile([]byte(tc.file))
			if err != nil {
				t.Fatal(err)
			}
			c.vals = vals
		}
		got := fs.String("opt", c.String("opt", "builtin"), "")
		if err := fs.Parse(tc.cli); err != nil {
			t.Fatal(err)
		}
		if *got != tc.want {
			t.Fatalf("file=%q cli=%v got %q want %q", tc.file, tc.cli, *got, tc.want)
		}
	}
}
