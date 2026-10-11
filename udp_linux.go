//go:build linux

package main

import (
	"context"
	"log"
	"net"
	"sync"
	"syscall"
)

// udpProbe 是绑定在重定向端口、并 connect 到某个 LAN 客户端的 UDP socket：
//   - 借助 conntrack 用 SO_ORIGINAL_DST 还原该客户端报文的原始目标
//   - 回包从该 socket 发出（源端口=重定向端口），conntrack 自动反 DNAT，
//     客户端看到的源地址就是它原本访问的目标
type udpProbe struct {
	conn    *net.UDPConn
	dstIP   net.IP
	dstPort int
}

type udpFrontend struct {
	conn   *net.UDPConn
	gw     *udpGateway
	bindTo string // 与主监听相同的本地 bind 地址（probe 复用）

	probesMu sync.Mutex
	probes   map[string]*udpProbe
}

// startUDPFrontend 监听被 iptables nat REDIRECT 过来的 UDP 流量。
// 需要与防火墙配套：nat PREROUTING -p udp ... -j REDIRECT --to-ports <port>。
// 返回的 stop 关闭主监听（probe socket 由 gateway 的空闲回收/Close 释放）。
func startUDPFrontend(listenAddr string, gw *udpGateway) (func(), error) {
	lc := net.ListenConfig{Control: setUDPReuseAddr}
	pc, err := lc.ListenPacket(context.Background(), "udp4", listenAddr)
	if err != nil {
		return nil, err
	}
	f := &udpFrontend{
		conn:   pc.(*net.UDPConn),
		gw:     gw,
		bindTo: listenAddr,
		probes: make(map[string]*udpProbe),
	}
	go f.loop()
	log.Printf("udp transparent redirect listening on %s", listenAddr)
	return func() { _ = f.conn.Close() }, nil
}

// setUDPReuseAddr 允许 probe socket 与主监听绑定同一地址。
// 不能用 SO_REUSEPORT：内核会在多个 socket 间负载分担报文，
// 导致客户端数据被随机分到 probe 或主监听上。
func setUDPReuseAddr(network, address string, rc syscall.RawConn) error {
	var serr error
	err := rc.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	})
	if err != nil {
		return err
	}
	return serr
}

func (f *udpFrontend) loop() {
	buf := make([]byte, udpMaxPacket)
	for {
		n, client, err := f.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		f.dispatch(data, client)
	}
}

func (f *udpFrontend) dispatch(data []byte, client *net.UDPAddr) {
	key := client.String()
	probe := f.getProbe(key, client)
	if probe == nil {
		return
	}
	p := probe // 捕获给闭包
	f.gw.handle(data, key, probe.dstIP, probe.dstPort,
		func(b []byte) error {
			_, err := p.conn.Write(b)
			return err
		},
		func() { f.removeProbe(key, p) },
	)
}

// getProbe 返回（或惰性创建）客户端对应的 probe。原始目标在 conntrack
// 元组生命周期内保持不变，因此只在建连时查询一次 SO_ORIGINAL_DST。
func (f *udpFrontend) getProbe(key string, client *net.UDPAddr) *udpProbe {
	f.probesMu.Lock()
	defer f.probesMu.Unlock()
	if p, ok := f.probes[key]; ok {
		return p
	}

	// UDPConn 没有 Connect：用带 LocalAddr 的 Dialer 创建"已连接"的
	// UDP socket，Control 里置 SO_REUSEADDR 以复用重定向端口。
	localAddr, err := net.ResolveUDPAddr("udp4", f.bindTo)
	if err != nil {
		log.Printf("udp probe resolve %s: %v", f.bindTo, err)
		return nil
	}
	d := net.Dialer{LocalAddr: localAddr, Control: setUDPReuseAddr}
	cc, err := d.DialContext(context.Background(), "udp4", client.String())
	if err != nil {
		log.Printf("udp probe dial %s: %v", key, err)
		return nil
	}
	uc := cc.(*net.UDPConn)

	var dstIP net.IP
	var dstPort int
	var opErr error
	raw, err := uc.SyscallConn()
	if err == nil {
		err = raw.Control(func(fd uintptr) {
			dstIP, dstPort, opErr = sockOrigDst(fd)
		})
	}
	if err != nil || opErr != nil {
		_ = uc.Close()
		// conntrack 项不存在（过期/未被 REDIRECT 的流量）时直接丢弃，
		// 避免把无法还原目标的报文送入代理
		log.Printf("udp original dst for %s: %v %v", key, err, opErr)
		return nil
	}

	p := &udpProbe{conn: uc, dstIP: dstIP, dstPort: dstPort}
	f.probes[key] = p
	return p
}

func (f *udpFrontend) removeProbe(key string, probe *udpProbe) {
	f.probesMu.Lock()
	if cur, ok := f.probes[key]; ok && cur == probe {
		delete(f.probes, key)
	}
	f.probesMu.Unlock()
	_ = probe.conn.Close()
}
