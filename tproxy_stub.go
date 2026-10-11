//go:build !linux

package main

import (
	"errors"
	"net"
)

// TPROXY 依赖 Linux mangle/TPROXY、IP_TRANSPARENT 与策略路由，
// 非 Linux 平台显式拒绝启动。
func startTCPTProxy(addr string) (net.Listener, error) {
	return nil, errors.New("tcp tproxy only supported on linux")
}

func startUDPTProxy(addr string, gw *udpGateway) (func(), error) {
	return nil, errors.New("udp tproxy only supported on linux")
}
