//go:build !linux

package main

import (
	"fmt"
	"net"
)

func originalDst(conn net.Conn) (net.IP, int, error) {
	return nil, 0, fmt.Errorf("original destination only supported on linux")
}
