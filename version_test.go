package main

import (
	"strings"
	"testing"
)

func TestBuildInfoVersionString(t *testing.T) {
	// 无 VCS 信息（如 go build 时不在 git 工作区）：明确回退，不能 panic
	empty := buildInfo{}
	if got := empty.versionString(); got != "unknown (built without VCS info)" {
		t.Fatalf("empty buildInfo=%q", got)
	}

	// 正常嵌入：短 SHA + UTC 时间 + dirty 标记
	b := buildInfo{
		commit:   "abcdef1",
		fullSHA:  "abcdef1234567890",
		commitAt: "2026-10-11T15:04:05Z",
		modified: true,
	}
	got := b.versionString()
	for _, want := range []string{"abcdef1", "2026-10-11T15:04:05Z", "[dirty]"} {
		if !strings.Contains(got, want) {
			t.Fatalf("versionString=%q missing %q", got, want)
		}
	}

	// 非 dirty 不带标记，非法时间戳回退原样输出不丢信息
	clean := buildInfo{commit: "1234567", commitAt: "garbage"}
	got = clean.versionString()
	if strings.Contains(got, "[dirty]") || !strings.Contains(got, "garbage") {
		t.Fatalf("clean/bad-time versionString=%q", got)
	}
}

func TestReadBuildInfoShape(t *testing.T) {
	// go test 在 git 工作区内构建测试二进制，通常带 VCS stamping；
	// 没有也合法（断言宽松）。非空时必须是 7 位十六进制短 SHA。
	b := readBuildInfo()
	if b.commit != "" {
		if len(b.commit) != 7 {
			t.Fatalf("short commit=%q want 7 chars", b.commit)
		}
		for _, r := range b.commit {
			if !strings.ContainsRune("0123456789abcdef", r) {
				t.Fatalf("short commit %q contains non-hex %q", b.commit, r)
			}
		}
		if len(b.fullSHA) < 7 {
			t.Fatalf("full SHA suspiciously short: %q", b.fullSHA)
		}
	}
}

func TestDescribeAuthNeverLeaksPassword(t *testing.T) {
	if describeAuth("") != "none" {
		t.Fatal("empty user must report none")
	}
	got := describeAuth("alice")
	if !strings.Contains(got, "user=alice") {
		t.Fatalf("auth=%q", got)
	}
	// 该函数只接收用户名，签名层面就拿不到密码
	if s := nonEmpty("", "fallback"); s != "fallback" || nonEmpty("x", "f") != "x" {
		t.Fatal("nonEmpty fallback broken")
	}
}
