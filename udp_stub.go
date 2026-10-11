//go:build !linux

package main

import "errors"

// UDP 透明重定向依赖 Linux conntrack 的 SO_ORIGINAL_DST（nat REDIRECT），
// 非 Linux 平台显式拒绝启动，避免静默吞掉流量。
func startUDPFrontend(listenAddr string, gw *udpGateway) (func(), error) {
	return nil, errors.New("udp transparent redirect only supported on linux")
}
