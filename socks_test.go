package main

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
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

// fakeNetErr 实现 net.Error，用于 isTimeout 的分类判定。
type fakeNetErr struct{ timeout bool }

func (e fakeNetErr) Error() string   { return "fake net error" }
func (e fakeNetErr) Timeout() bool   { return e.timeout }
func (e fakeNetErr) Temporary() bool { return false }

// TestIsTimeout 验证重试只针对超时类错误：nil、普通错误、
// 非超时 net.Error 都不重试，避免对拒绝类故障做无谓二次拨号。
func TestIsTimeout(t *testing.T) {
	if isTimeout(nil) {
		t.Fatal("nil error must not be classified as timeout")
	}
	if isTimeout(errors.New("connection refused")) {
		t.Fatal("plain error is not a net.Error")
	}
	if isTimeout(fakeNetErr{timeout: false}) {
		t.Fatal("non-timeout net.Error must not be classified as timeout")
	}
	if !isTimeout(fakeNetErr{timeout: true}) {
		t.Fatal("timeout net.Error must be classified as timeout")
	}
}

// TestSocksReadReply 逐分支验证 SOCKS5 应答解析。应答字节全部由测试
// 构造，覆盖三种 ATYP 与所有错误路径：拒绝码、非法 ATYP、截断的
// 头部/地址——上游返回损坏或恶意数据时必须报错而不是 panic 或
// 返回半解析结果。
func TestSocksReadReply(t *testing.T) {
	buildReply := func(code, atyp byte, addr []byte, port uint16) []byte {
		b := []byte{0x05, code, 0x00, atyp}
		if atyp == 0x03 {
			b = append(b, byte(len(addr)))
		}
		b = append(b, addr...)
		var pb [2]byte
		binary.BigEndian.PutUint16(pb[:], port)
		return append(b, pb[:]...)
	}
	cases := []struct {
		name     string
		reply    []byte
		wantHost string
		wantIP   string
		wantPort int
		wantErr  string
	}{
		{"ipv4", buildReply(0, 0x01, []byte{1, 2, 3, 4}, 0x0050), "", "1.2.3.4", 80, ""},
		{"ipv6", buildReply(0, 0x04, net.ParseIP("2001:db8::1").To16(), 0x1f90), "", "2001:db8::1", 8080, ""},
		{"domain", buildReply(0, 0x03, []byte("bnd.example.com"), 0x01bb), "bnd.example.com", "", 443, ""},
		{"empty domain", buildReply(0, 0x03, nil, 0x01bb), "", "", 443, ""},
		{"refused", buildReply(0x05, 0x01, []byte{0, 0, 0, 0}, 0), "", "", 0, "code 5"},
		{"bad atyp", buildReply(0, 0x02, []byte{0, 0, 0, 0}, 0), "", "", 0, "atyp 2"},
		{"short header", []byte{0x05, 0x00}, "", "", 0, "unexpected EOF"},
		{"short addr", []byte{0x05, 0x00, 0x00, 0x01, 1, 2}, "", "", 0, "unexpected EOF"},
		{"short port", []byte{0x05, 0x00, 0x00, 0x01, 1, 2, 3, 4, 0x01}, "", "", 0, "unexpected EOF"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, cli := net.Pipe()
			go func() {
				_, _ = srv.Write(tc.reply)
				_ = srv.Close()
			}()
			host, ip, port, err := socksReadReply(cli)
			_ = cli.Close()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err=%v want contains %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if host != tc.wantHost {
				t.Fatalf("host=%q want %q", host, tc.wantHost)
			}
			if tc.wantIP == "" {
				if ip != nil {
					t.Fatalf("ip=%v want nil for non-IP atyp", ip)
				}
			} else if ip == nil || !ip.Equal(net.ParseIP(tc.wantIP)) {
				t.Fatalf("ip=%v want %s", ip, tc.wantIP)
			}
			if port != tc.wantPort {
				t.Fatalf("port=%d want %d", port, tc.wantPort)
			}
		})
	}
}
