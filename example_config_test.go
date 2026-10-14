package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestExampleConfigFileValid 防止文档漂移：示例配置是用户直接复制的
// 模板，路由器上一个拼写漂移就是 exit 2。这里从 main.go 源码提取全部
// flag 定义名，要求 ①示例中实际生效（未注释）的键都是真实选项；
// ②每个真实选项（config 本身除外）至少出现在示例中一次（注释形式也算），
// 保证模板随新选项一起长大。
func TestExampleConfigFileValid(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	// 选项定义在 defineFlags 里注册到传入的 FlagSet（flag.CommandLine
	// 或取内置默认用的临时集），故这里按方法名匹配而不绑定接收者名。
	re := regexp.MustCompile(`\.(?:String|Bool|Int)\("([^"]+)"`)
	defined := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		defined[m[1]] = true
	}
	if len(defined) < 15 {
		t.Fatalf("flag extraction looks wrong: %d names", len(defined))
	}

	data, err := os.ReadFile("domain-socks.conf.example")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	vals, err := parseConfigFile(data)
	if err != nil {
		t.Fatalf("example config unparseable: %v", err)
	}

	for key := range vals {
		if !defined[key] {
			t.Fatalf("example sets unknown option %q", key)
		}
	}

	for name := range defined {
		if name == "config" {
			continue // command-line only by design
		}
		if !strings.Contains(text, name) {
			t.Fatalf("example does not mention option %q (add a live or commented line)", name)
		}
	}
	// 注意：不能在这里调 c.validate()——go test 不会执行 main()，
	// flag.CommandLine 里没有注册任何选项，validate 的未知键检查
	// 会全部误报；键合法性由上面的 main.go 源码比对承担。
}
