package main

import (
	"runtime/debug"
	"time"
)

// buildInfo 描述编译进二进制的源码版本。Go 1.18+ 在 git 工作区内
// 执行 go build 会自动嵌入 VCS stamping（无需改构建脚本/传 -ldflags），
// 路由器上排查时就能从日志或 -version 确认实际跑的是哪个提交。
type buildInfo struct {
	commit    string // vcs.revision 的短 SHA（7 位）
	fullSHA   string
	commitAt  string // vcs.time 原始 RFC3339 时间
	modified  bool   // vcs.modified=true：构建时工作区有未提交改动
	goVersion string
}

func readBuildInfo() buildInfo {
	var b buildInfo
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return b
	}
	b.goVersion = bi.GoVersion
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			b.fullSHA = s.Value
			if len(s.Value) >= 7 {
				b.commit = s.Value[:7]
			} else {
				b.commit = s.Value
			}
		case "vcs.time":
			b.commitAt = s.Value
		case "vcs.modified":
			b.modified = s.Value == "true"
		}
	}
	return b
}

// versionString 是 -version 与启动横幅用的单行版本描述。
func (b buildInfo) versionString() string {
	if b.commit == "" {
		return "unknown (built without VCS info)"
	}
	s := b.commit
	if t, err := time.Parse(time.RFC3339, b.commitAt); err == nil {
		s += " built " + t.UTC().Format("2006-01-02T15:04:05Z")
	} else if b.commitAt != "" {
		s += " built " + b.commitAt
	}
	if b.modified {
		s += " [dirty]"
	}
	return s
}

// describeAuth 只回显认证是否开启与用户名，永不输出密码。
func describeAuth(user string) string {
	if user == "" {
		return "none"
	}
	return "user=" + user
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
