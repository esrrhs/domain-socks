//go:build !windows

package main

import (
	"syscall"
	"testing"
	"time"
)

// TestReloadSignalDelivery 验证 SIGHUP 信号管线本身（reload_unix.go）：
// 向自身发送的 SIGHUP 必须送达 notifyReload 返回的通道；stopReload
// 之后旧通道不再接收，重新注册的新通道接管。测试刻意保留一个新
// 注册的通道到信号发送之后——没有注册者时 SIGHUP 的默认动作会
// 直接终止测试进程。
func TestReloadSignalDelivery(t *testing.T) {
	ch := notifyReload()
	defer stopReload(ch)

	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatalf("kill self: %v", err)
	}
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("SIGHUP not delivered to reload channel")
	}

	// stopReload 同步生效：其后的 SIGHUP 不可能再进旧通道
	stopReload(ch)
	ch2 := notifyReload()
	defer stopReload(ch2)

	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatalf("kill self: %v", err)
	}
	select {
	case <-ch2:
	case <-time.After(2 * time.Second):
		t.Fatal("SIGHUP not delivered after re-register")
	}
	select {
	case <-ch:
		t.Fatal("stopped channel must not receive SIGHUP")
	default:
	}
}
