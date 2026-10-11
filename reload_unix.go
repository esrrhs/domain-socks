//go:build !windows

package main

import (
	"os"
	"os/signal"
	"syscall"
)

// notifyReload 在 Unix 上把 SIGHUP（守护进程约定的"重读配置"信号）
// 投递到返回的带缓冲 channel：外部 logrotate 或管理员
// `kill -HUP $(pidof domain-socks)` 即触发热重载。
func notifyReload() chan os.Signal {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	return ch
}

func stopReload(ch chan os.Signal) {
	signal.Stop(ch)
}
