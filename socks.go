package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// The router is one client of the SOCKS server. A phone opening many
// connections at once used to time out the handshake even though a single
// manual test succeeded.
var handshakeSlots = make(chan struct{}, 12)

func socksConnect(proxy string, host string, ip net.IP, port int, user string, pass string) (net.Conn, error) {
	handshakeSlots <- struct{}{}
	defer func() { <-handshakeSlots }()
	conn, err := socksConnectOnce(proxy, host, ip, port, user, pass)
	if err == nil || !isTimeout(err) {
		return conn, err
	}
	time.Sleep(300 * time.Millisecond)
	return socksConnectOnce(proxy, host, ip, port, user, pass)
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

func socksConnectOnce(proxy string, host string, ip net.IP, port int, user string, pass string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxy, 8*time.Second)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(12 * time.Second))

	if err = socksNegotiate(conn, user, pass); err != nil {
		conn.Close()
		return nil, err
	}
	if err = socksWriteRequest(conn, socksCmdConnect, host, ip, port); err != nil {
		conn.Close()
		return nil, err
	}
	if _, _, _, err = socksReadReply(conn); err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

const (
	socksCmdConnect      = 0x01
	socksCmdUDPAssociate = 0x03
)

// socksNegotiate 完成 SOCKS5 方法协商与可选的 RFC 1929 用户名/密码认证。
// TCP CONNECT 与 UDP ASSOCIATE 共用，两条路径不得各自实现以免行为漂移。
func socksNegotiate(conn net.Conn, user string, pass string) error {
	// 协商认证方式
	if user != "" || pass != "" {
		// 支持免密(0x00)与用户名/密码认证(0x02)
		if _, err := conn.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
			return err
		}
	} else {
		if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			return err
		}
	}

	greet := make([]byte, 2)
	if _, err := io.ReadFull(conn, greet); err != nil {
		return err
	}
	if greet[0] != 0x05 {
		return fmt.Errorf("socks version %d", greet[0])
	}

	if greet[1] == 0x02 { // 需要用户名/密码认证 (RFC 1929)
		if len(user) > 255 || len(pass) > 255 {
			return errors.New("socks credentials too long")
		}
		authReq := make([]byte, 0, 3+len(user)+len(pass))
		authReq = append(authReq, 0x01, byte(len(user)))
		authReq = append(authReq, user...)
		authReq = append(authReq, byte(len(pass)))
		authReq = append(authReq, pass...)
		if _, err := conn.Write(authReq); err != nil {
			return err
		}
		authResp := make([]byte, 2)
		if _, err := io.ReadFull(conn, authResp); err != nil {
			return err
		}
		if authResp[1] != 0x00 {
			return fmt.Errorf("socks auth failed: %v", authResp)
		}
	} else if greet[1] != 0x00 {
		return fmt.Errorf("socks auth method refused: %v", greet)
	}
	return nil
}

// socksWriteRequest 发送 CONNECT/UDP ASSOCIATE 请求。
// host 非空时按域名(ATYP=0x03)发送；ip 非空时按 IPv4(ATYP=0x01)发送；
// 两者皆空时发送 0.0.0.0:0（UDP ASSOCIATE 客户端无特定绑定时使用）。
func socksWriteRequest(conn net.Conn, cmd byte, host string, ip net.IP, port int) error {
	req := make([]byte, 0, 262)
	req = append(req, 0x05, cmd, 0x00)
	switch {
	case host != "":
		if len(host) > 255 {
			return errors.New("host too long")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	case ip != nil:
		// IPv4-mapped IPv6 统一按 IPv4 发送
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 0x01)
			req = append(req, ip4...)
		} else {
			ip6 := ip.To16()
			if ip6 == nil {
				return errors.New("invalid ip")
			}
			req = append(req, 0x04)
			req = append(req, ip6...)
		}
	default:
		req = append(req, 0x01, 0, 0, 0, 0)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(port))
	req = append(req, pb[:]...)
	_, err := conn.Write(req)
	return err
}

// socksReadReply 读取 SOCKS5 应答，返回 BND.ADDR/BND.PORT。
// 域名型(ATYP=0x03)应答会返回 host；IPv4/IPv6 返回解析后的 ip。
func socksReadReply(conn net.Conn) (host string, ip net.IP, port int, err error) {
	hdr := make([]byte, 4)
	if _, err = io.ReadFull(conn, hdr); err != nil {
		return "", nil, 0, err
	}
	if hdr[1] != 0x00 {
		return "", nil, 0, fmt.Errorf("socks refused code %d", hdr[1])
	}
	var addr []byte
	switch hdr[3] {
	case 0x01:
		addr = make([]byte, 4)
	case 0x04:
		addr = make([]byte, 16)
	case 0x03:
		lb := make([]byte, 1)
		if _, err = io.ReadFull(conn, lb); err != nil {
			return "", nil, 0, err
		}
		addr = make([]byte, int(lb[0]))
	default:
		return "", nil, 0, fmt.Errorf("socks atyp %d", hdr[3])
	}
	if _, err = io.ReadFull(conn, addr); err != nil {
		return "", nil, 0, err
	}
	var pb [2]byte
	if _, err = io.ReadFull(conn, pb[:]); err != nil {
		return "", nil, 0, err
	}
	port = int(binary.BigEndian.Uint16(pb[:]))
	switch hdr[3] {
	case 0x01:
		ip = net.IPv4(addr[0], addr[1], addr[2], addr[3]).To4()
	case 0x04:
		ip = make(net.IP, net.IPv6len)
		copy(ip, addr)
	case 0x03:
		host = string(addr)
	}
	return host, ip, port, nil
}
