//go:build linux

package main

import (
	"encoding/binary"
	"net"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

// cmsgMarshal 手工拼出 recvmsg 控制消息：64 位 cmsghdr = Len(size_t,8) +
// Level(int32) + Type(int32)，之后对齐到 SizeofCmsghdr 放数据。
// parseOrigDst 生产代码走 unix.ParseSocketControlMessage，与架构无关，
// 这里只在 64 位（CI 的 amd64/arm64）验证。
func cmsgMarshal(t *testing.T, level, typ int, data []byte) []byte {
	t.Helper()
	if strconv.IntSize != 64 || unix.SizeofCmsghdr != 16 {
		t.Skip("cmsg layout test only covers 64-bit linux")
	}
	buf := make([]byte, unix.CmsgSpace(len(data)))
	binary.NativeEndian.PutUint64(buf[0:8], uint64(unix.CmsgLen(len(data))))
	binary.LittleEndian.PutUint32(buf[8:12], uint32(level))
	binary.LittleEndian.PutUint32(buf[12:16], uint32(typ))
	copy(buf[unix.SizeofCmsghdr:], data)
	return buf
}

func TestParseOrigDstV4(t *testing.T) {
	sa := make([]byte, 8) // sockaddr_in
	sa[0], sa[1] = unix.AF_INET, 0
	sa[2], sa[3] = 0x1f, 0x90 // 8080
	copy(sa[4:8], []byte{8, 8, 4, 4})
	oob := cmsgMarshal(t, unix.SOL_IP, linuxIPRecvOrigDst, sa)

	ip, port, ok := parseOrigDst(oob, false)
	if !ok {
		t.Fatal("parse failed")
	}
	if port != 8080 || !ip.Equal(net.IPv4(8, 8, 4, 4)) || ip.To4() == nil {
		t.Fatalf("got %s:%d", ip, port)
	}
}

func TestParseOrigDstV6(t *testing.T) {
	sa := make([]byte, 24) // sockaddr_in6
	sa[0], sa[1] = unix.AF_INET6, 0
	sa[2], sa[3] = 0x1f, 0x90 // 8080
	want := net.ParseIP("2001:db8::2")
	copy(sa[8:24], want.To16())
	oob := cmsgMarshal(t, linuxIPPROTOIPV6, linuxIPV6OrigDst, sa)

	ip, port, ok := parseOrigDst(oob, true)
	if !ok {
		t.Fatal("parse failed")
	}
	if port != 8080 || !ip.Equal(want) || ip.To4() != nil {
		t.Fatalf("got %s:%d", ip, port)
	}
}

func TestParseOrigDstReject(t *testing.T) {
	// level/type 不匹配
	sa := make([]byte, 8)
	oob := cmsgMarshal(t, unix.SOL_SOCKET, linuxIPRecvOrigDst, sa)
	if _, _, ok := parseOrigDst(oob, false); ok {
		t.Fatal("wrong level must be rejected")
	}
	// 截断的 sockaddr_in
	oob2 := cmsgMarshal(t, unix.SOL_IP, linuxIPRecvOrigDst, make([]byte, 4))
	if _, _, ok := parseOrigDst(oob2, false); ok {
		t.Fatal("truncated addr must be rejected")
	}
	// 完全无控制消息
	if _, _, ok := parseOrigDst(nil, false); ok {
		t.Fatal("empty oob must be rejected")
	}
}
