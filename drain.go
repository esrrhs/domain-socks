package main

import (
	"log"
	"net"
	"os"
	"sync"
	"time"
)

// 优雅退出预算（设为变量便于测试缩短）：先给在途连接 shutdownGrace
// 自然收尾（短请求多半自行结束）；超时后强制关闭仍存活的客户端连接，
// 让 handleConn 的双向 io.Copy 解锁、统计 defer 执行落账；再等
// shutdownDrainTimeout 总预算的剩余部分，之后放弃卡死的连接直接退出。
var (
	shutdownGrace        = 1 * time.Second
	shutdownDrainTimeout = 3 * time.Second
)

// connRegistry 是 accept 出来的在途客户端连接集合。关闭集合中的连接会
// 同时打断 handleConn 内阻塞的双向 io.Copy（另一方向经 closeWrite 级联），
// 使访问日志、字节计数、/top 聚合与时长直方图的 defer 及时执行，
// 而不是随进程退出被丢弃。
type connRegistry struct {
	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

func newConnRegistry() *connRegistry {
	return &connRegistry{conns: make(map[net.Conn]struct{})}
}

// add 必须在 go handleConn 之前同步调用：确保 closeAll 扫描时不会漏掉
// "已 Accept 但还没来得及登记"的连接。
func (r *connRegistry) add(c net.Conn) {
	r.mu.Lock()
	r.conns[c] = struct{}{}
	r.mu.Unlock()
}

func (r *connRegistry) remove(c net.Conn) {
	r.mu.Lock()
	delete(r.conns, c)
	r.mu.Unlock()
}

func (r *connRegistry) len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.conns)
}

// closeAll 关闭并摘除全部在途连接，返回关闭的连接数。
// 连接随后还会被 handleConn 的 defer c.Close() 再关一次——
// net.Conn.Close 幂等，重复关闭的错误被忽略即可。
func (r *connRegistry) closeAll() int {
	r.mu.Lock()
	conns := make([]net.Conn, 0, len(r.conns))
	for c := range r.conns {
		conns = append(conns, c)
	}
	r.conns = make(map[net.Conn]struct{})
	r.mu.Unlock()

	for _, c := range conns {
		_ = c.Close()
	}
	return len(conns)
}

// waitForShutdown 执行两阶段排空，返回 drained 表示是否全部连接正常收尾，
// hard 表示是否由第二个 SIGINT/SIGTERM 触发立即放弃（调用方应以非零码退出）。
//   - 第一阶段等在途连接自然结束（宽限期内不打扰任何连接）；
//   - 宽限后仍在的，强关其客户端连接以触发统计 defer；
//   - 总预算耗尽仍未退出的（如卡在无 context 的拨号中）放弃；
//   - hardExit 收到第二个信号时立即返回 (false, true)，不再等待。
func waitForShutdown(wg *sync.WaitGroup, active *connRegistry, hardExit <-chan os.Signal) (drained, hard bool) {
	wgDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(wgDone)
	}()

	// 第一阶段：自然宽限
	select {
	case <-wgDone:
		return true, false
	case <-hardExit:
		return false, true
	case <-time.After(shutdownGrace):
	}

	// 第二阶段：强关仍存活的连接，逼出 handleConn 的收尾 defer
	if n := active.closeAll(); n > 0 {
		log.Printf("grace period (%v) elapsed, force-closing %d active connection(s)", shutdownGrace, n)
	}

	select {
	case <-wgDone:
		return true, false
	case <-hardExit:
		return false, true
	case <-time.After(shutdownDrainTimeout - shutdownGrace):
		log.Printf("drain timeout: abandoning %d stuck connection(s) after %v total budget",
			active.len(), shutdownDrainTimeout)
		return false, false
	}
}
