//go:build linux

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"
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
		var buf [128]byte
		size := uint32(len(buf))
		_, _, errno := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			uintptr(syscall.IPPROTO_IP),
			80, // SO_ORIGINAL_DST
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			0,
		)
		if errno != 0 {
			opErr = errno
			return
		}
		if size < 8 {
			opErr = fmt.Errorf("short sockaddr %d", size)
			return
		}
		port = int(binary.BigEndian.Uint16(buf[2:4]))
		ip = net.IPv4(buf[4], buf[5], buf[6], buf[7]).To4()
	})
	if err != nil {
		return nil, 0, err
	}
	if opErr != nil {
		return nil, 0, opErr
	}
	return ip, port, nil
}
