package main

import (
	"errors"
	"net"
)

// SOCKS5 UDP 数据报（RFC 1928 §7）：
//
//	+----+------+------+----------+----------+----------+
//	|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//	+----+------+------+----------+----------+----------+
//	 2     1      1     可变       2         可变
//
// 我们不支持重组分片，FRAG 必须为 0。

const (
	socks5AtypIPv4   = 0x01
	socks5AtypDomain = 0x03
	socks5AtypIPv6   = 0x04
)

// packSocks5UDP 构造发往 SOCKS5 UDP relay 的报文。
// host 为 IP 字面量时按 A 记录/AAAA 编码，否则按域名(ATYP=0x03)编码；
// IPv4-mapped IPv6（::ffff:x.x.x.x）统一按 IPv4 发送。
func packSocks5UDP(host string, port int, data []byte) ([]byte, error) {
	if port < 1 || port > 65535 {
		return nil, errors.New("socks5 udp: invalid destination port")
	}
	pkt := make([]byte, 0, 3+1+255+2+len(data))
	pkt = append(pkt, 0, 0, 0) // RSV + FRAG

	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			pkt = append(pkt, socks5AtypIPv4)
			pkt = append(pkt, ip4...)
		} else {
			pkt = append(pkt, socks5AtypIPv6)
			pkt = append(pkt, ip.To16()...)
		}
	} else {
		if len(host) == 0 {
			return nil, errors.New("socks5 udp: empty destination host")
		}
		if len(host) > 255 {
			return nil, errors.New("socks5 udp: destination hostname too long")
		}
		pkt = append(pkt, socks5AtypDomain, byte(len(host)))
		pkt = append(pkt, host...)
	}
	pkt = append(pkt, byte(port>>8), byte(port))
	pkt = append(pkt, data...)
	return pkt, nil
}

// unpackSocks5UDP 解析 relay 回来的报文，返回源地址 host（IP 字面量或域名）、
// 端口与负载（不含 UDP 头）。分片报文与非法地址一律拒绝。
func unpackSocks5UDP(pkt []byte) (host string, port int, data []byte, err error) {
	if len(pkt) < 4 {
		return "", 0, nil, errors.New("socks5 udp: packet too short")
	}
	if pkt[2] != 0 {
		return "", 0, nil, errors.New("socks5 udp: fragmented datagrams are not supported")
	}
	b := pkt[3:]
	var addr []byte
	switch b[0] {
	case socks5AtypIPv4:
		if len(b) < 1+net.IPv4len+2 {
			return "", 0, nil, errors.New("socks5 udp: truncated ipv4 address")
		}
		addr = b[1 : 1+net.IPv4len]
		host = net.IPv4(addr[0], addr[1], addr[2], addr[3]).String()
		b = b[1+net.IPv4len:]
	case socks5AtypIPv6:
		if len(b) < 1+net.IPv6len+2 {
			return "", 0, nil, errors.New("socks5 udp: truncated ipv6 address")
		}
		addr = b[1 : 1+net.IPv6len]
		ip6 := make(net.IP, net.IPv6len)
		copy(ip6, addr)
		if ip4 := ip6.To4(); ip4 != nil {
			host = ip4.String()
		} else {
			host = ip6.String()
		}
		b = b[1+net.IPv6len:]
	case socks5AtypDomain:
		if len(b) < 2 {
			return "", 0, nil, errors.New("socks5 udp: truncated domain length")
		}
		n := int(b[1])
		if n == 0 || len(b) < 2+n+2 {
			return "", 0, nil, errors.New("socks5 udp: truncated domain address")
		}
		host = string(b[2 : 2+n])
		b = b[2+n:]
	default:
		return "", 0, nil, errors.New("socks5 udp: unknown atyp")
	}
	port = int(b[0])<<8 | int(b[1])
	if port < 1 {
		return "", 0, nil, errors.New("socks5 udp: invalid source port")
	}
	return host, port, b[2:], nil
}
