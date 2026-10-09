package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// The router is one client of the SOCKS server. A phone opening many
// connections at once used to time out the handshake even though a single
// manual test succeeded.
var handshakeSlots = make(chan struct{}, 12)

func socksConnect(proxy string, host string, ip net.IP, port int) (net.Conn, error) {
	handshakeSlots <- struct{}{}
	defer func() { <-handshakeSlots }()
	conn, err := socksConnectOnce(proxy, host, ip, port)
	if err == nil || !isTimeout(err) {
		return conn, err
	}
	time.Sleep(300 * time.Millisecond)
	return socksConnectOnce(proxy, host, ip, port)
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

func socksConnectOnce(proxy string, host string, ip net.IP, port int) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxy, 8*time.Second)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(12 * time.Second))
	if _, err = conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, err
	}
	greet := make([]byte, 2)
	if _, err = io.ReadFull(conn, greet); err != nil {
		conn.Close()
		return nil, err
	}
	if greet[0] != 0x05 || greet[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks auth %v", greet)
	}
	var req []byte
	req = append(req, 0x05, 0x01, 0x00)
	if host != "" {
		if len(host) > 255 {
			conn.Close()
			return nil, fmt.Errorf("host too long")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	} else {
		ip4 := ip.To4()
		if ip4 == nil {
			conn.Close()
			return nil, fmt.Errorf("no ipv4")
		}
		req = append(req, 0x01)
		req = append(req, ip4...)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(port))
	req = append(req, pb[:]...)
	if _, err = conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}
	hdr := make([]byte, 4)
	if _, err = io.ReadFull(conn, hdr); err != nil {
		conn.Close()
		return nil, err
	}
	if hdr[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks connect refused code %d", hdr[1])
	}
	var skip int
	switch hdr[3] {
	case 0x01:
		skip = 4
	case 0x03:
		lb := make([]byte, 1)
		if _, err = io.ReadFull(conn, lb); err != nil {
			conn.Close()
			return nil, err
		}
		skip = int(lb[0])
	case 0x04:
		skip = 16
	default:
		conn.Close()
		return nil, fmt.Errorf("socks atyp %d", hdr[3])
	}
	if _, err = io.CopyN(io.Discard, conn, int64(skip+2)); err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}
