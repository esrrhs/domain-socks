package main

import (
	"net"
	"testing"
)

// TestLocalDst 验证 TPROXY 模式取原始目标的方式：accept 连接的 LocalAddr。
// （REDIRECT 模式取址依赖内核 SO_ORIGINAL_DST，无法在普通环境模拟。）
func TestLocalDst(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	want := ln.Addr().(*net.TCPAddr)

	connCh := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		connCh <- c
	}()
	cli, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	srv := <-connCh
	defer srv.Close()

	ip, port, err := localDst(srv)
	if err != nil {
		t.Fatal(err)
	}
	if !ip.Equal(want.IP) || port != want.Port {
		t.Fatalf("localDst=%s:%d want %s", ip, port, want)
	}
}

func TestCanonicalIP(t *testing.T) {
	cases := []struct {
		in   string
		want string
		v4   bool
	}{
		{"1.2.3.4", "1.2.3.4", true},
		{"::ffff:5.6.7.8", "5.6.7.8", true},
		{"2001:db8::1", "2001:db8::1", false},
		{"::1", "::1", false},
	}
	for _, tc := range cases {
		got := canonicalIP(net.ParseIP(tc.in))
		if got == nil {
			t.Fatalf("canonicalIP(%s) nil", tc.in)
		}
		if got.String() != tc.want {
			t.Fatalf("canonicalIP(%s)=%s want %s", tc.in, got, tc.want)
		}
		if is4 := got.To4() != nil; is4 != tc.v4 {
			t.Fatalf("canonicalIP(%s) family v4=%v want %v (len=%d)", tc.in, is4, tc.v4, len(got))
		}
	}
	if canonicalIP(nil) != nil {
		t.Fatal("canonicalIP(nil) must be nil")
	}
}
