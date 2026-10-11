package main

import (
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestConnRegistryAddRemoveCloseAll(t *testing.T) {
	r := newConnRegistry()
	if r.len() != 0 {
		t.Fatal("fresh registry must be empty")
	}

	a1, b1 := net.Pipe()
	a2, b2 := net.Pipe()
	defer b1.Close()
	defer b2.Close()
	r.add(a1)
	r.add(a2)
	if r.len() != 2 {
		t.Fatalf("len=%d want 2", r.len())
	}
	r.remove(a1)
	if r.len() != 1 {
		t.Fatalf("after remove len=%d want 1", r.len())
	}
	r.add(a1) // 重新加入

	if n := r.closeAll(); n != 2 {
		t.Fatalf("closeAll=%d want 2", n)
	}
	if r.len() != 0 {
		t.Fatalf("registry must be empty after closeAll, got %d", r.len())
	}

	// 对端读必须立即解锁（closeAll 的核心目的：打断阻塞的 io.Copy）
	done := make(chan error, 2)
	for _, c := range []net.Conn{b1, b2} {
		go func(c net.Conn) {
			_, err := c.Read(make([]byte, 1))
			done <- err
		}(c)
	}
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("read on force-closed conn must error")
			}
		case <-time.After(time.Second):
			t.Fatal("read on force-closed conn did not unblock within 1s")
		}
	}

	// handleConn 的 defer c.Close() 会再关一次：必须幂等不 panic
	_ = a1.Close()
	_ = a2.Close()
	// 已摘除连接的 remove 也应安全
	r.remove(a1)
	// 空集合 closeAll 返回 0
	if n := r.closeAll(); n != 0 {
		t.Fatalf("closeAll on empty=%d want 0", n)
	}
}

// withShortDrain 在测试期间缩短两阶段排空预算。
func withShortDrain(t *testing.T, grace, total time.Duration) {
	t.Helper()
	oldGrace, oldTotal := shutdownGrace, shutdownDrainTimeout
	shutdownGrace, shutdownDrainTimeout = grace, total
	t.Cleanup(func() {
		shutdownGrace, shutdownDrainTimeout = oldGrace, oldTotal
	})
}

func TestWaitForShutdownNatural(t *testing.T) {
	withShortDrain(t, time.Second, 2*time.Second)
	var wg sync.WaitGroup
	r := newConnRegistry()
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(20 * time.Millisecond)
	}()
	start := time.Now()
	drained, hard := waitForShutdown(&wg, r, nil)
	if !drained || hard {
		t.Fatalf("natural drain=(%v,%v)", drained, hard)
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("natural completion took %v, should not wait the grace", d)
	}
}

// 核心场景：连接阻塞在读上（典型 keepalive 长连），宽限后被强关，
// 收尾 defer 执行，wg 正常归零——统计/日志不丢。
func TestWaitForShutdownForceClosesStuckConns(t *testing.T) {
	withShortDrain(t, 60*time.Millisecond, 2*time.Second)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = c.Read(make([]byte, 1))
			}()
		}
	}()

	var wg sync.WaitGroup
	r := newConnRegistry()
	finished := make(chan struct{}, 2)
	for i := 0; i < 2; i++ {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		r.add(c)
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer r.remove(c) // 模拟 handleConn 的 defer 链
			defer c.Close()
			_, _ = c.Read(make([]byte, 1))
			finished <- struct{}{}
		}(c)
	}
	if r.len() != 2 {
		t.Fatalf("active=%d want 2", r.len())
	}

	drained, hard := waitForShutdown(&wg, r, nil)
	if !drained || hard {
		t.Fatalf("force drain=(%v,%v), want (true,false)", drained, hard)
	}
	for i := 0; i < 2; i++ {
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Fatal("handler defer did not run after force close")
		}
	}
	if r.len() != 0 {
		t.Fatalf("registry=%d want empty", r.len())
	}
}

func TestWaitForShutdownSecondSignal(t *testing.T) {
	withShortDrain(t, 5*time.Second, 10*time.Second) // 预算很长，靠信号打断
	var wg sync.WaitGroup
	r := newConnRegistry()
	wg.Add(1) // 永不完成
	block := make(chan struct{})
	go func() {
		defer wg.Done()
		<-block
	}()
	t.Cleanup(func() { close(block) })

	hardExit := make(chan os.Signal, 1)
	go func() {
		time.Sleep(30 * time.Millisecond)
		hardExit <- syscall.SIGTERM
	}()
	start := time.Now()
	drained, hard := waitForShutdown(&wg, r, hardExit)
	if drained || !hard {
		t.Fatalf("second signal=(%v,%v), want (false,true)", drained, hard)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("second signal took %v to take effect", d)
	}
}

func TestWaitForShutdownBudgetExhausted(t *testing.T) {
	withShortDrain(t, 30*time.Millisecond, 80*time.Millisecond)
	var wg sync.WaitGroup
	r := newConnRegistry()
	wg.Add(1)
	block := make(chan struct{})
	go func() {
		defer wg.Done()
		<-block // 模拟连 close 都救不回的卡死（如无 context 的拨号）
	}()
	t.Cleanup(func() { close(block) })

	start := time.Now()
	drained, hard := waitForShutdown(&wg, r, nil)
	if drained || hard {
		t.Fatalf("budget exhausted=(%v,%v), want (false,false)", drained, hard)
	}
	if d := time.Since(start); d < 70*time.Millisecond || d > 500*time.Millisecond {
		t.Fatalf("timeout took %v, want ~80ms total budget", d)
	}
}
