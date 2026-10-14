package main

import (
	"fmt"
	"runtime"
	"testing"
	"time"
)

// TestBoundedGrowthUnderMassiveChurn 是小内存路由器长期运行的回归护栏：
// 制造 30000 条不同目标的 UDP flow（5000 个不同客户端）并让它们全部
// 空闲过期，断言 ①flow/client 表被 sweep 清空；②/top 聚合表停在
// cap+1（超限键折叠进 __other__，不再增长）；③GC 后堆增量有硬上限，
// 防止未来改动引入随域名数线性累积的常驻内存。
func TestBoundedGrowthUnderMassiveChurn(t *testing.T) {
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	gw, st := newTestUDPGateway(t)

	const nFlows = 30000
	aged := time.Now().Add(-udpFlowIdle - time.Second)
	gw.mu.Lock()
	for i := 0; i < nFlows; i++ {
		target := fmt.Sprintf("h%05d.example.com", i)
		fkey := "P|" + target + ":443"
		ci := i % 5000
		ckey := fmt.Sprintf("10.0.%d.%d:40000", ci/250, ci%250)
		gw.flows[fkey] = &udpFlow{
			clientKey: ckey,
			target:    target + ":443",
			host:      target,
			via:       "socks",
			created:   aged,
			lastSeen:  aged,
			up:        100,
			down:      1000,
		}
		if _, ok := gw.clients[ckey]; !ok {
			gw.clients[ckey] = &udpClient{addr: ckey, lastSeen: time.Now().Add(-udpClientIdle - time.Second)}
		}
	}
	gw.mu.Unlock()

	gw.sweep()

	gw.mu.Lock()
	liveFlows, liveClients := len(gw.flows), len(gw.clients)
	gw.mu.Unlock()
	if liveFlows != 0 || liveClients != 0 {
		t.Fatalf("sweep left flows=%d clients=%d", liveFlows, liveClients)
	}

	st.domains.mu.Lock()
	domRows := len(st.domains.m)
	_, domOverflow := st.domains.m[aggOverflow]
	st.domains.mu.Unlock()
	if domRows != aggCapDomains+1 || !domOverflow {
		t.Fatalf("domains table=%d overflow=%v want %d with __other__", domRows, domOverflow, aggCapDomains+1)
	}

	st.clients.mu.Lock()
	cliRows := len(st.clients.m)
	_, cliOverflow := st.clients.m[aggOverflow]
	st.clients.mu.Unlock()
	if cliRows != aggCapClients+1 || !cliOverflow {
		t.Fatalf("clients table=%d overflow=%v want %d with __other__", cliRows, cliOverflow, aggCapClients+1)
	}

	// 5 万次孤儿回包：只允许动计数器，不允许再造任何表项
	for i := 0; i < 50000; i++ {
		gw.deliverBack(fmt.Sprintf("P|h%d.example.com:443", i+i%nFlows), []byte("x"))
	}
	gw.mu.Lock()
	missFlows := len(gw.flows)
	gw.mu.Unlock()
	if missFlows != 0 {
		t.Fatalf("deliverBack miss re-created flows: %d", missFlows)
	}

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	// 30000 flow + 聚合表的净驻留应当只有 MB 级；16MiB 的宽上限
	// 足以抓住"每域名常驻分配"级别的回归而不误报 GC 噪声。
	growth := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	if growth > 16*1024*1024 {
		t.Fatalf("heap grew %.1fMiB after churn+sweep; something retains per-domain memory", float64(growth)/(1024*1024))
	}
	t.Logf("churn %d flows -> sweep clean, heap growth %.2fMiB", nFlows, float64(growth)/(1024*1024))
}
