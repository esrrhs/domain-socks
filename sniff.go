package main

import (
	"bytes"
	"time"
)

const (
	// sniffTimeout 是嗅探应用层前缀的总等待预算
	sniffTimeout = 250 * time.Millisecond
	// sniffMaxBytes 限制嗅探读取的最大字节数，ClientHello 通常在一个 MTU 内，
	// 携带大量扩展时可能到数 KB，8KB 足以覆盖，超过即放弃嗅探
	sniffMaxBytes = 8192
)

func sniffHost(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	// 仅在 TLS record 接收完整时才解析 SNI，截断的 ClientHello 可能产生误报
	if b[0] == 0x16 && len(b) >= 5 && b[1] == 0x03 {
		recLen := int(b[3])<<8 | int(b[4])
		if recLen > 0 && 5+recLen <= sniffMaxBytes && len(b) >= 5+recLen {
			if host := sniffSNI(b); host != "" {
				return host
			}
		}
	}
	if isHTTP(b) {
		return sniffHTTPHost(b)
	}
	return ""
}

// sniffConclusive 判断已读取的前缀是否足以对"能否嗅探出域名"下结论，
// 结论为真时调用方不必继续等待后续 TCP 分段：
//   - 首字节既非 TLS 握手也不可能是 HTTP 方法：非目标协议，立即放弃
//   - TLS record 已完整（此时 SNI 有无已经确定），或 record 声明长度异常
//   - HTTP 请求头已结束（Host 头有无已经确定）
//
// 前缀尚不完整（TLS record 头/体被分段、HTTP 方法名跨段等）时返回 false。
func sniffConclusive(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	if b[0] == 0x16 {
		// 第二字节已表明不是 SSL 3.0+ 的 TLS record，不可能是 ClientHello
		if len(b) >= 2 && b[1] != 0x03 {
			return true
		}
		// record 头尚未收齐（可能被 TCP 分段），继续等待
		if len(b) < 5 {
			return false
		}
		recLen := int(b[3])<<8 | int(b[4])
		// record 声称超过嗅探上限，不继续缓存
		if 5+recLen > sniffMaxBytes {
			return true
		}
		return len(b) >= 5+recLen
	}
	if httpMethodPrefix(b) {
		return bytes.Contains(b, []byte("\r\n\r\n"))
	}
	return true
}

func isHTTP(b []byte) bool {
	return httpMethodPrefix(b) && bytes.Contains(b, []byte("\r\n"))
}

// httpMethodPrefix 判断 b 是否是某个 HTTP 方法的前缀（容忍方法名跨 TCP 段），
// 或已经以完整方法开头。
func httpMethodPrefix(b []byte) bool {
	methods := []string{"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT "}
	for _, m := range methods {
		mb := []byte(m)
		if bytes.HasPrefix(b, mb) || bytes.HasPrefix(mb, b) {
			return true
		}
	}
	return false
}

func sniffHTTPHost(b []byte) string {
	lower := bytes.ToLower(b)
	key := []byte("\nhost:")
	i := bytes.Index(lower, key)
	if i < 0 {
		return ""
	}
	rest := b[i+len(key):]
	rest = bytes.TrimLeft(rest, " \t")
	end := bytes.IndexByte(rest, '\n')
	if end < 0 {
		return ""
	}
	host := string(bytes.TrimSpace(rest[:end]))
	if c := bytes.IndexByte([]byte(host), ':'); c >= 0 {
		host = host[:c]
	}
	return host
}

func sniffSNI(b []byte) string {
	// TLS record + handshake, enough to walk to the server_name extension.
	if len(b) < 5 || b[0] != 0x16 {
		return ""
	}
	recLen := int(b[3])<<8 | int(b[4])
	if 5+recLen > len(b) {
		b = b[:len(b)]
	} else {
		b = b[:5+recLen]
	}
	if len(b) < 5+4+2+32+1 {
		return ""
	}
	hs := b[5:]
	if hs[0] != 0x01 {
		return ""
	}
	off := 4 + 2 + 32
	if off >= len(hs) {
		return ""
	}
	sidLen := int(hs[off])
	off++
	off += sidLen
	if off+2 > len(hs) {
		return ""
	}
	csLen := int(hs[off])<<8 | int(hs[off+1])
	off += 2 + csLen
	if off+1 > len(hs) {
		return ""
	}
	compLen := int(hs[off])
	off++
	off += compLen
	if off+2 > len(hs) {
		return ""
	}
	extLen := int(hs[off])<<8 | int(hs[off+1])
	off += 2
	extEnd := off + extLen
	if extEnd > len(hs) {
		extEnd = len(hs)
	}
	for off+4 <= extEnd {
		typ := int(hs[off])<<8 | int(hs[off+1])
		l := int(hs[off+2])<<8 | int(hs[off+3])
		off += 4
		if off+l > extEnd {
			return ""
		}
		if typ == 0 && l >= 5 {
			data := hs[off : off+l]
			// list length(2) + name type(1) + name length(2) + name
			if len(data) >= 5 && data[2] == 0 {
				nlen := int(data[3])<<8 | int(data[4])
				if 5+nlen <= len(data) {
					return string(data[5 : 5+nlen])
				}
			}
		}
		off += l
	}
	return ""
}
