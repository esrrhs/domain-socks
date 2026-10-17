//go:build linux

package main

import (
	"context"
	"log"
	"net"
	"syscall"
)

type udpFrontend struct {
	conn *net.UDPConn
	gw   *udpGateway
}

// startUDPFrontend 监听被 iptables nat REDIRECT 过来的 UDP 流量。
// 需要与防火墙配套：nat PREROUTING -p udp ... -j REDIRECT --to-ports <port>。
// 通过 IP_RECVORIGDSTADDR 控制消息直接获取被 REDIRECT 前的原始目标地址（IP 和端口），
// 回包由主 socket 直接发往客户端，由 Linux 内核 conntrack 自动完成反向 NAT。
func startUDPFrontend(listenAddr string, gw *udpGateway) (func(), error) {
	lc := net.ListenConfig{Control: setUDPRecvOrigDst}
	pc, err := lc.ListenPacket(context.Background(), "udp4", listenAddr)
	if err != nil {
		return nil, err
	}
	f := &udpFrontend{
		conn: pc.(*net.UDPConn),
		gw:   gw,
	}
	go f.loop()
	log.Printf("udp transparent redirect listening on %s (IP_RECVORIGDSTADDR)", listenAddr)
	return func() { _ = f.conn.Close() }, nil
}

// setUDPRecvOrigDst 开启 SO_REUSEADDR 与 IP_RECVORIGDSTADDR (20)。
func setUDPRecvOrigDst(network, address string, rc syscall.RawConn) error {
	var serr error
	err := rc.Control(func(fd uintptr) {
		if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
			serr = err
			return
		}
		if err := syscall.SetsockoptInt(int(fd), syscall.SOL_IP, linuxIPRecvOrigDst, 1); err != nil {
			serr = err
			return
		}
	})
	if err != nil {
		return err
	}
	return serr
}

func (f *udpFrontend) loop() {
	buf := make([]byte, udpMaxPacket)
	oob := make([]byte, 1024)
	for {
		n, oobn, _, client, err := f.conn.ReadMsgUDP(buf, oob)
		if err != nil {
			return
		}
		if n == 0 || client == nil {
			continue
		}
		dstIP, dstPort, ok := parseOrigDst(oob[:oobn], false)
		if !ok {
			log.Printf("udp original dst missing for %s", client)
			continue
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		key := client.String()
		f.gw.handle(data, key, dstIP, dstPort,
			func(b []byte) error {
				_, err := f.conn.WriteToUDP(b, client)
				return err
			},
			func() {},
		)
	}
}
