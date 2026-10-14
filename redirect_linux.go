//go:build linux

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func originalDst(conn net.Conn) (net.IP, int, error) {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, 0, fmt.Errorf("not tcp")
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		return nil, 0, err
	}
	var ip net.IP
	var port int
	var opErr error
	err = raw.Control(func(fd uintptr) {
		ip, port, opErr = sockOrigDst(fd)
	})
	if err != nil {
		return nil, 0, err
	}
	if opErr != nil {
		return nil, 0, opErr
	}
	return ip, port, nil
}

// sockOrigDst 通过 SO_ORIGINAL_DST 从 conntrack 读取 REDIRECT/DNAT 前的
// 原始目标地址。TCP 监听 socket 与 UDP "connect 到客户端"的 probe socket
// 共用本实现。
// 注意：SO_ORIGINAL_DST 的数值各 Linux 架构一致（asm-generic 0x50），
// 但经 unix.SO_ORIGINAL_DST 引用而非硬编码魔数——OpenWrt 目标含
// mipsel（Newifi3/MT7621），常量引用让架构分歧在编译期暴露。
func sockOrigDst(fd uintptr) (net.IP, int, error) {
	var buf [128]byte
	size := uint32(len(buf))
	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		fd,
		uintptr(syscall.IPPROTO_IP),
		uintptr(unix.SO_ORIGINAL_DST),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if errno != 0 {
		return nil, 0, errno
	}
	if size < 8 {
		return nil, 0, fmt.Errorf("short sockaddr %d", size)
	}
	port := int(binary.BigEndian.Uint16(buf[2:4]))
	ip := net.IPv4(buf[4], buf[5], buf[6], buf[7]).To4()
	return ip, port, nil
}
