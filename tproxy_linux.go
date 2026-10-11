//go:build linux

package main

import (
	"context"
	"errors"
	"log"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// TPROXY (透明代理) 与 REDIRECT 的区别：
//   - REDIRECT 改写目标地址，需 SO_ORIGINAL_DST 从 conntrack 反查（仅 IPv4）；
//   - TPROXY 不做 NAT，报文按原始目标被送到本地透明 socket：
//     TCP accept 后 LocalAddr 即原始目标；
//     UDP 通过 IP(V6)_RECVORIGDSTADDR 控制消息拿到完整原始地址（含端口），
//     回包必须从"绑定到原始目标地址:端口"的透明 socket 发出，客户端才会接受
//     （没有 conntrack 帮忙做反向 NAT）。
//     配合 fwmark 策略路由，可同时截获 IPv4 与 IPv6。
const (
	linuxIPTransparent   = 19 // SOL_IP
	linuxIPRecvOrigDst   = 20 // SOL_IP
	linuxIPPROTOIPV6     = 41
	linuxIPV6V6Only      = 26
	linuxIPV6Transparent = 75
	linuxIPV6OrigDst     = 74 // IPPROTO_IPV6（RECV 与数据消息同值）
)

// setTCPTransparent 在监听 socket 上同时开启 v4/v6 透明绑定，
// 绑到 :port 的双栈 listener 可同时截获 IPv4 与 IPv6 入向 TCP。
func setTCPTransparent(network, address string, rc syscall.RawConn) error {
	var serr error
	if err := rc.Control(func(fd uintptr) {
		// 显式要求双栈（部分发行版 net.ipv6.bindv6only=1）
		if err := syscall.SetsockoptInt(int(fd), linuxIPPROTOIPV6, linuxIPV6V6Only, 0); err != nil {
			serr = err
			return
		}
		if err := syscall.SetsockoptInt(int(fd), syscall.SOL_IP, linuxIPTransparent, 1); err != nil {
			serr = err
			return
		}
		if err := syscall.SetsockoptInt(int(fd), linuxIPPROTOIPV6, linuxIPV6Transparent, 1); err != nil {
			serr = err
		}
	}); err != nil {
		return err
	}
	return serr
}

// startTCPTProxy 创建双栈 TPROXY TCP 监听器。需要 CAP_NET_ADMIN（或 root）
// 以及 mangle 表 TPROXY 规则 + fwmark 策略路由，普通环境会绑定失败。
func startTCPTProxy(addr string) (net.Listener, error) {
	lc := net.ListenConfig{Control: setTCPTransparent}
	ln, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		return nil, err
	}
	log.Printf("tcp tproxy dual-stack listening on %s", addr)
	return ln, nil
}

// ---------------- UDP TPROXY ----------------

// udpTProxySender 是绑定在"某个原始目标 ip:port"上的透明发送 socket：
// 从该 socket 发给客户端的回包，源地址正是客户端最初访问的地址。
// 同一原始目标的回包被所有客户端共用，由 lastSeen 驱动空闲回收。
type udpTProxySender struct {
	conn     *net.UDPConn
	lastSeen time.Time
}

type udpTProxyFrontend struct {
	gw *udpGateway

	mu      sync.Mutex
	senders map[string]*udpTProxySender // 原始目标 host:port -> sender
	fds     []int
	closed  bool
}

// startUDPTProxy 创建 v4/v6 两个 TPROXY UDP socket 并开始读取。
// addr 必须是通配地址（:port / [::]:port），原始目标来自每包的
// ORIGDSTADDR 控制消息，而不是 socket 绑定地址。
func startUDPTProxy(addr string, gw *udpGateway) (func(), error) {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	p, err := net.LookupPort("udp", port)
	if err != nil || p <= 0 {
		return nil, errors.New("invalid udp tproxy port")
	}

	f := &udpTProxyFrontend{gw: gw, senders: make(map[string]*udpTProxySender)}

	fd4, err := newTProxyFD(unix.AF_INET, p)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.fds = []int{fd4}
	f.mu.Unlock()
	go f.readLoop(fd4, false)

	// 无 IPv6 栈（EAFNOSUPPORT/EADDRNOTAVAIL）时降级为仅 v4，不影响主流程
	stack := "v4+v6"
	if fd6, err6 := newTProxyFD(unix.AF_INET6, p); err6 == nil {
		f.mu.Lock()
		f.fds = append(f.fds, fd6)
		f.mu.Unlock()
		go f.readLoop(fd6, true)
	} else {
		stack = "v4-only"
		log.Printf("udp tproxy: ipv6 socket unavailable, ipv4-only mode: %v", err6)
	}
	go f.sweepLoop()
	log.Printf("udp tproxy listening on %s (%s)", addr, stack)

	return f.close, nil
}

func newTProxyFD(family, port int) (int, error) {
	fd, err := unix.Socket(family, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	switch family {
	case unix.AF_INET:
		if err = unix.SetsockoptInt(fd, unix.SOL_IP, linuxIPTransparent, 1); err != nil {
			_ = unix.Close(fd)
			return -1, err
		}
		if err = unix.SetsockoptInt(fd, unix.SOL_IP, linuxIPRecvOrigDst, 1); err != nil {
			_ = unix.Close(fd)
			return -1, err
		}
		err = unix.Bind(fd, &unix.SockaddrInet4{Port: port})
	case unix.AF_INET6:
		if err = unix.SetsockoptInt(fd, linuxIPPROTOIPV6, linuxIPV6V6Only, 1); err != nil {
			_ = unix.Close(fd)
			return -1, err
		}
		if err = unix.SetsockoptInt(fd, linuxIPPROTOIPV6, linuxIPV6Transparent, 1); err != nil {
			_ = unix.Close(fd)
			return -1, err
		}
		if err = unix.SetsockoptInt(fd, linuxIPPROTOIPV6, linuxIPV6OrigDst, 1); err != nil {
			_ = unix.Close(fd)
			return -1, err
		}
		err = unix.Bind(fd, &unix.SockaddrInet6{Port: port})
	}
	if err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func (f *udpTProxyFrontend) readLoop(fd int, v6 bool) {
	buf := make([]byte, udpMaxPacket)
	oob := make([]byte, 1024)
	for {
		n, oobn, _, from, err := unix.Recvmsg(fd, buf, oob, 0)
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}
		dstIP, dstPort, ok := parseOrigDst(oob[:oobn], v6)
		if !ok {
			continue
		}
		client, ok := sockaddrToUDP(from)
		if !ok {
			continue
		}
		data := append([]byte(nil), buf[:n]...)
		key := client.String()
		f.touch(dstIP, dstPort)
		f.gw.handle(data, key, dstIP, dstPort,
			func(b []byte) error { return f.reply(dstIP, dstPort, client, b) },
			func() {},
		)
	}
}

// parseOrigDst 从控制消息解析原始目标地址（IP_ORIGDSTADDR=20 /
// IPV6_ORIGDSTADDR=74），消息体即 sockaddr_in / sockaddr_in6。
func parseOrigDst(oob []byte, v6 bool) (net.IP, int, bool) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, 0, false
	}
	for _, m := range msgs {
		if v6 {
			if m.Header.Level != linuxIPPROTOIPV6 || m.Header.Type != linuxIPV6OrigDst {
				continue
			}
			// sockaddr_in6: family(2) port(2) flowinfo(4) addr(16) ...
			if len(m.Data) < 24 {
				return nil, 0, false
			}
			port := int(m.Data[2])<<8 | int(m.Data[3])
			ip := make(net.IP, net.IPv6len)
			copy(ip, m.Data[8:24])
			return canonicalIP(ip), port, true
		}
		if m.Header.Level != unix.SOL_IP || m.Header.Type != linuxIPRecvOrigDst {
			continue
		}
		// sockaddr_in: family(2) port(2) addr(4)
		if len(m.Data) < 8 {
			return nil, 0, false
		}
		port := int(m.Data[2])<<8 | int(m.Data[3])
		return net.IPv4(m.Data[4], m.Data[5], m.Data[6], m.Data[7]).To4(), port, true
	}
	return nil, 0, false
}

func sockaddrToUDP(sa unix.Sockaddr) (*net.UDPAddr, bool) {
	switch a := sa.(type) {
	case *unix.SockaddrInet4:
		return &net.UDPAddr{IP: net.IPv4(a.Addr[0], a.Addr[1], a.Addr[2], a.Addr[3]).To4(), Port: a.Port}, true
	case *unix.SockaddrInet6:
		ip := make(net.IP, net.IPv6len)
		copy(ip, a.Addr[:])
		return &net.UDPAddr{IP: canonicalIP(ip), Port: a.Port, Zone: zoneFromID(a.ZoneId)}, true
	}
	return nil, false
}

func zoneFromID(id uint32) string {
	if id == 0 {
		return ""
	}
	if iface, err := net.InterfaceByIndex(int(id)); err == nil {
		return iface.Name
	}
	return ""
}

// sender 返回（惰性创建）绑定到原始目标的透明发送 socket。
func (f *udpTProxyFrontend) sender(ip net.IP, port int) (*net.UDPConn, error) {
	key := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	f.mu.Lock()
	if s, ok := f.senders[key]; ok {
		s.lastSeen = time.Now()
		f.mu.Unlock()
		return s.conn, nil
	}
	f.mu.Unlock()

	network := "udp4"
	v6only := 0
	if ip.To4() == nil {
		network = "udp6"
		v6only = 1
	}
	lc := net.ListenConfig{Control: func(network, address string, rc syscall.RawConn) error {
		var serr error
		err := rc.Control(func(fd uintptr) {
			if v6only == 1 {
				if e := syscall.SetsockoptInt(int(fd), linuxIPPROTOIPV6, linuxIPV6V6Only, 1); e != nil {
					serr = e
					return
				}
				if e := syscall.SetsockoptInt(int(fd), linuxIPPROTOIPV6, linuxIPV6Transparent, 1); e != nil {
					serr = e
				}
			} else {
				serr = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, linuxIPTransparent, 1)
			}
		})
		if err != nil {
			return err
		}
		return serr
	}}
	pc, err := lc.ListenPacket(context.Background(), network, key)
	if err != nil {
		return nil, err
	}
	uc := pc.(*net.UDPConn)

	f.mu.Lock()
	if s, ok := f.senders[key]; ok { // 并发时已有建连者，丢弃重复 socket
		f.mu.Unlock()
		_ = uc.Close()
		return s.conn, nil
	}
	f.senders[key] = &udpTProxySender{conn: uc, lastSeen: time.Now()}
	f.mu.Unlock()

	go func() { // 排空该 socket 上的意外入包，防接收缓冲占满
		b := make([]byte, 512)
		for {
			if _, _, err := uc.ReadFrom(b); err != nil {
				return
			}
		}
	}()
	return uc, nil
}

func (f *udpTProxyFrontend) touch(ip net.IP, port int) {
	key := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	f.mu.Lock()
	if s, ok := f.senders[key]; ok {
		s.lastSeen = time.Now()
	}
	f.mu.Unlock()
}

func (f *udpTProxyFrontend) reply(ip net.IP, port int, client *net.UDPAddr, b []byte) error {
	uc, err := f.sender(ip, port)
	if err != nil {
		return err
	}
	_, err = uc.WriteToUDP(b, client)
	return err
}

func (f *udpTProxyFrontend) sweepLoop() {
	ticker := time.NewTicker(udpSweep)
	defer ticker.Stop()
	for range ticker.C {
		var stale []*net.UDPConn
		f.mu.Lock()
		if f.closed {
			f.mu.Unlock()
			return
		}
		for key, s := range f.senders {
			if time.Since(s.lastSeen) > udpFlowIdle {
				delete(f.senders, key)
				stale = append(stale, s.conn)
			}
		}
		f.mu.Unlock()
		for _, c := range stale {
			_ = c.Close()
		}
	}
}

func (f *udpTProxyFrontend) close() {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	f.closed = true
	fds := f.fds
	senders := f.senders
	f.senders = make(map[string]*udpTProxySender)
	f.mu.Unlock()

	for _, fd := range fds {
		_ = unix.Close(fd)
	}
	for _, s := range senders {
		_ = s.conn.Close()
	}
}
