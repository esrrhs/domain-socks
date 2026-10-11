//go:build windows

package main

import "os"

// Windows 没有 SIGHUP：热重载通道永不触发（分流规则变更需重启服务）。
// 保留同一组函数让 main.go 无需平台分支。
func notifyReload() chan os.Signal {
	return make(chan os.Signal)
}

func stopReload(ch chan os.Signal) {}
