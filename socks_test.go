package main

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
)

// TestSocksWriteRequestIPv6 验证 TPROXY 截获真实 IPv6 目标时，
// SOCKS5 请求按 ATYP=0x04 编码 16 字节地址；IPv4-mapped 仍发 ATYP=0x01。
func TestSocksWriteRequestIPv6(t *testing.T) {
	cases := []struct {
		name     string
		ip       net.IP
		wantAtyp byte
		wantLen  int
	}{
		{"ipv6", net.ParseIP("2001:db8::1"), socks5AtypIPv6, 22},
		{"mapped v4", net.ParseIP("::ffff:1.2.3.4"), socks5AtypIPv4, 10},
		{"ipv4", net.IPv4(5, 6, 7, 8), socks5AtypIPv4, 10},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, cli := net.Pipe()
			go func() {
				_ = socksWriteRequest(cli, socksCmdConnect, "", tc.ip, 0x1234)
				_ = cli.Close()
			}()
			buf := make([]byte, tc.wantLen)
			if _, err := io.ReadFull(srv, buf); err != nil {
				t.Fatal(err)
			}
			srv.Close()
			if buf[0] != 0x05 || buf[1] != socksCmdConnect || buf[2] != 0x00 {
				t.Fatalf("bad header: %x", buf[:4])
			}
			if buf[3] != tc.wantAtyp {
				t.Fatalf("atyp=%d want %d", buf[3], tc.wantAtyp)
			}
			if port := binary.BigEndian.Uint16(buf[len(buf)-2:]); port != 0x1234 {
				t.Fatalf("port=%d", port)
			}
			if tc.wantAtyp == socks5AtypIPv6 {
				if got := net.IP(buf[4:20]); !got.Equal(net.ParseIP("2001:db8::1")) {
					t.Fatalf("addr=%s", got)
				}
			} else {
				want := net.IPv4(5, 6, 7, 8)
				if tc.name == "mapped v4" {
					want = net.IPv4(1, 2, 3, 4)
				}
				if got := net.IPv4(buf[4], buf[5], buf[6], buf[7]); !got.Equal(want) {
					t.Fatalf("addr=%s want %s", got, want)
				}
			}
		})
	}
}
