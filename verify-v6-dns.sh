#!/bin/sh
# verify-v6-dns.sh - 验证 domain-socks 的 IPv6 DNS 劫持闭环
#
# 默认执行【只读】检查，不插入/修改任何防火墙规则，不改动系统配置：
#   1. ip6tables 与 ip6table_nat 模块是否就绪
#   2. PREROUTING 中 tcp/udp 53 的 REDIRECT 规则是否指向本地 DNS 端口
#   3. domain-socks 是否以单个双栈 IPv6 socket 监听（v4/v6 同一 socket）
#   4. 经 ::1 直查本地 DNS：代理域名应返回 198.18/15 Fake-IP
#
# 可选模式（仍然不碰现有防火墙规则）：
#   --watch SECONDS   快照规则计数，等待 SECONDS 秒后对比；期间请从 LAN 的
#                     IPv6 客户端执行: dig @2400:3200::1 <proxy-domain>
#                     （计数 +1 即证明真实流量被 REDIRECT 命中）
#   --netns           创建【临时】veth + network namespace 模拟 LAN v6 客户端，
#                     从 netns 内查询外部 v6 DNS（报文过 PREROUTING 被劫持），
#                     断言收到 Fake-IP，结束自动清理（trap 保证）。
#                     需要 ip-full 的 netns/veth 支持与 v6 转发能力。
#
# 用法:
#   ./verify-v6-dns.sh [--port 1053] [--proxy-domain google.com]
#                     [--watch SECONDS] [--netns]
#
# 退出码: 0=全部通过(WARN 不影响); 1=存在 FAIL 项; 2=参数/环境错误

set -u

PORT=1053
PROXY_DOMAIN="google.com"
WATCH=0
USE_NETNS=0

# ---- 参数解析（POSIX getopts 不支持长选项，手工解析）----
while [ $# -gt 0 ]; do
	case "$1" in
	--port)
		shift
		[ $# -gt 0 ] || { echo "error: --port requires a value" >&2; exit 2; }
		PORT="$1"
		;;
	--proxy-domain)
		shift
		[ $# -gt 0 ] || { echo "error: --proxy-domain requires a value" >&2; exit 2; }
		PROXY_DOMAIN="$1"
		;;
	--watch)
		shift
		[ $# -gt 0 ] || { echo "error: --watch requires seconds" >&2; exit 2; }
		WATCH="$1"
		;;
	--netns)
		USE_NETNS=1
		;;
	-h|--help)
		sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'
		exit 0
		;;
	*)
		echo "error: unknown option: $1" >&2
		exit 2
		;;
	esac
	shift
done

case "$WATCH" in
''|*[!0-9]*)
	echo "error: --watch must be a non-negative integer (seconds)" >&2
	exit 2
	;;
esac
case "$PORT" in
''|*[!0-9]*)
	echo "error: --port must be a port number" >&2
	exit 2
	;;
esac

FAIL_COUNT=0
WARN_COUNT=0

pass() { printf '[ PASS ] %s\n' "$1"; }
warn() { WARN_COUNT=$((WARN_COUNT + 1)); printf '[ WARN ] %s\n' "$1"; }
fail() { FAIL_COUNT=$((FAIL_COUNT + 1)); printf '[ FAIL ] %s\n' "$1"; }
info() { printf '[ INFO ] %s\n' "$1"; }

section() { printf '\n== %s ==\n' "$1"; }

# ---- 0. 运行环境 ----
section "0. environment"

if [ "$(id -u)" = "0" ]; then
	pass "running as root"
else
	warn "not root; socket/process details and rule counters may be invisible"
fi

if command -v ip6tables >/dev/null 2>&1; then
	pass "ip6tables available: $(ip6tables --version 2>/dev/null | head -n1)"
else
	fail "ip6tables not found; install the ip6tables userspace package"
fi

if command -v ip >/dev/null 2>&1; then
	pass "ip available: $(ip -V 2>/dev/null)"
else
	warn "ip command not found (needed for --netns)"
fi

# ---- 1. ip6table_nat 模块与 REDIRECT 规则（只读）----
section "1. IPv6 nat REDIRECT rules"

NAT_OK=0
if command -v ip6tables >/dev/null 2>&1 && \
	ip6tables -t nat -L PREROUTING -n >/dev/null 2>&1; then
	NAT_OK=1
	pass "ip6tables nat table is usable (ip6table_nat loaded)"
else
	fail "ip6tables nat table unavailable: install 'kmod-ipt-nat6' (opkg install kmod-ipt-nat6)"
fi

rule_present() {
	# $1 = tcp|udp
	ip6tables -t nat -S PREROUTING 2>/dev/null | \
		grep -E -- "-[AD] .*-p $1( .*)?--dport 53( .*)?-j REDIRECT( .*)?--to-ports? $PORT([ ]|$)" >/dev/null 2>&1
}

rule_count() {
	# $1 = tcp|udp ; 输出该规则当前命中包数（-x 精确值）
	ip6tables -t nat -L PREROUTING -v -n -x 2>/dev/null | \
		awk -v proto="$1" -v port="$PORT" '
			$0 ~ proto " dpt:53 " && $0 ~ "redir ports " port {
				print $1
			}'
}

if [ "$NAT_OK" = "1" ]; then
	if rule_present udp; then
		pass "udp/53 REDIRECT -> port $PORT present in nat6 PREROUTING"
	else
		fail "udp/53 REDIRECT -> port $PORT missing (start domain-socks via the init script, or install kmod-ipt-nat6)"
	fi
	if rule_present tcp; then
		pass "tcp/53 REDIRECT -> port $PORT present in nat6 PREROUTING"
	else
		fail "tcp/53 REDIRECT -> port $PORT missing"
	fi
fi

# ---- 2. 双栈监听检查 ----
section "2. dual-stack DNS listener"

# 输出监听 socket 行（ss 优先，netstat 兜底）
listen_dump() {
	if command -v ss >/dev/null 2>&1; then
		ss -lntu 2>/dev/null
	elif command -v netstat >/dev/null 2>&1; then
		netstat -lntu 2>/dev/null
	else
		return 1
	fi
}

DUMP=""
if DUMP="$(listen_dump)"; then
	# 单个 AF_INET6 dual socket 的显示形式：
	#   netstat/busybox :::PORT   iproute2 ss : [::]:PORT 或 UDP 的 *:PORT
	# v4 连接以 v4-mapped 进入同一 socket，不会另有 0.0.0.0:PORT 行。
	if printf '%s\n' "$DUMP" | \
		grep -E ":::$PORT([ ]|$)|\*:$PORT([ ]|$)|\[::\]:$PORT([ ]|$)" >/dev/null 2>&1; then
		pass "wildcard IPv6 socket on port $PORT (dual-stack v4+v6)"
		if printf '%s\n' "$DUMP" | grep -i "domain-socks" >/dev/null 2>&1; then
			pass "listener process is domain-socks"
		else
			warn "cannot confirm listener owner is domain-socks (need root / proc visibility)"
		fi
	else
		fail "no dual-stack listener on :::$PORT (daemon uses -dns [::]:$PORT ?)"
	fi
else
	warn "neither ss nor netstat available; listener check skipped"
fi

# ---- 3. 查询工具探测 ----
# dig/kdig/drill -> python3(内置迷你客户端) -> 放弃功能查询
DIG_TOOL=""
for t in dig kdig drill; do
	if command -v "$t" >/dev/null 2>&1; then
		DIG_TOOL="$t"
		break
	fi
done

# dns_query SERVER PORT NAME [tcp]
# 成功时把应答中的 A 记录逐行打印到 stdout，失败返回非 0
dns_query() {
	_server=$1; _port=$2; _name=$3; _proto=${4:-udp}
	if [ -n "$DIG_TOOL" ]; then
		# +short 对 CNAME 会输出别名行，过滤只留地址；drill 参数风格不同
		case "$DIG_TOOL" in
		drill)
			_tcp=""
			[ "$_proto" = "tcp" ] && _tcp="-T"
			$RUNNER drill $_tcp "@$_server" -p "$_port" "$_name" A 2>/dev/null | \
				grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
			;;
		*)
			_tcp=""
			[ "$_proto" = "tcp" ] && _tcp="+tcp"
			$RUNNER "$DIG_TOOL" "@$_server" -p "$_port" "$_name" A \
				+time=2 +tries=1 +short $_tcp 2>/dev/null | \
				grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
			;;
		esac
		return 0
	elif command -v python3 >/dev/null 2>&1; then
		exec $RUNNER python3 - "$_server" "$_port" "$_name" "$_proto" <<'PYEOF'
import socket, struct, sys

server, port, name, proto = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]

qname = b"".join(bytes([len(p)]) + p.encode() for p in name.rstrip(".").split(".")) + b"\0"
# header: id=0x1357 RD=1 ; question: type A(1) class IN(1)
msg = struct.pack(">HHHHHH", 0x1357, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", 1, 1)

s = socket.socket(socket.AF_INET6 if ":" in server else socket.AF_INET,
                  socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM)
s.settimeout(2)
try:
    if proto == "tcp":
        s.connect((server, port))
        s.sendall(struct.pack(">H", len(msg)) + msg)
        ln = struct.unpack(">H", s.recv(2))[0]
        data = b""
        while len(data) < ln:
            chunk = s.recv(ln - len(data))
            if not chunk:
                break
            data += chunk
    else:
        s.sendto(msg, (server, port))
        data = s.recv(4096)
finally:
    s.close()

# 极简解析：跳过 header(12) + question，再遍历资源记录取 A RDATA
def skip_name(buf, i):
    while True:
        b = buf[i]
        if b & 0xC0 == 0xC0:
            return i + 2
        if b == 0:
            return i + 1
        i += b + 1

pos = skip_name(data, 12) + 4  # question name + qtype/qclass
ancount = struct.unpack(">H", data[6:8])[0]
rcode = data[3] & 0x0F
if rcode != 0:
    sys.exit(1)
for _ in range(ancount):
    pos = skip_name(data, pos)
    rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
    pos += 10
    if rtype == 1 and rdlen == 4:
        print(".".join(str(b) for b in data[pos:pos + 4]))
    pos += rdlen
PYEOF
	else
		return 3
	fi
}

# RUNNER 非空时作为 dns_query 的执行前缀（netns 验证用）
RUNNER=""

is_fakeip() {
	# 198.18.0.0/15 -> 198.18.x.x 或 198.19.x.x
	echo "$1" | grep -E '^198\.(18|19)\.[0-9]+\.[0-9]+$' >/dev/null 2>&1
}

# ---- 3/4. 本地双栈查询（直查本机监听，验证应答内容，不经过 NAT）----
section "3. local DNS queries via dual-stack socket"

if [ -z "$DIG_TOOL" ] && ! command -v python3 >/dev/null 2>&1; then
	warn "no dig/kdig/drill/python3 found; functional queries skipped (opkg install bind-dig)"
else
	if answers="$(dns_query "::1" "$PORT" "$PROXY_DOMAIN" 2>/dev/null)" && [ -n "$answers" ]; then
		pass "query over IPv6 ::1 -> [$DIG_TOOL/python3] answered"
		fake="$(echo "$answers" | grep -E '^198\.(18|19)\.' | head -n1)"
		if [ -n "$fake" ]; then
			pass "$PROXY_DOMAIN returns Fake-IP $fake (198.18.0.0/15) over IPv6"
		else
			fail "$PROXY_DOMAIN answer is not a Fake-IP: $answers"
		fi
	else
		fail "no answer querying [::1]:$PORT (daemon not listening on the v6 socket?)"
	fi

	if answers4="$(dns_query "127.0.0.1" "$PORT" "$PROXY_DOMAIN" 2>/dev/null)" && [ -n "$answers4" ]; then
		pass "v4-mapped query 127.0.0.1 -> same dual socket works"
	else
		fail "127.0.0.1:$PORT unreachable (dual-stack fallback not working)"
	fi
fi

# ---- 5. 真实 LAN 客户端流量：规则计数对比（只读）----
if [ "$WATCH" -gt 0 ] 2>/dev/null; then
	section "4. counter watch (${WATCH}s)"
	if [ "$NAT_OK" != "1" ]; then
		fail "nat table unusable, cannot watch counters"
	else
		udp_before="$(rule_count udp)"
		tcp_before="$(rule_count tcp)"
		udp_before=${udp_before:-0}
		tcp_before=${tcp_before:-0}
		info "current hits: udp=$udp_before tcp=$tcp_before"
		echo
		echo "  >>> On a LAN IPv6 client, run BOTH:"
		echo "        dig @2400:3200::1 $PROXY_DOMAIN A"
		echo "        dig +tcp @2400:3200::1 $PROXY_DOMAIN A"
		echo "      (or re-run a failing app that uses IPv6 DNS)"
		echo "  >>> waiting ${WATCH}s ..."
		sleep "$WATCH"
		udp_after="$(rule_count udp)"; udp_after=${udp_after:-0}
		tcp_after="$(rule_count tcp)"; tcp_after=${tcp_after:-0}
		info "hits after wait: udp=$udp_after tcp=$tcp_after"
		if [ "$udp_after" -gt "$udp_before" ] || [ "$tcp_after" -gt "$tcp_before" ]; then
			pass "REDIRECT counters increased: real IPv6 client traffic is being hijacked"
		else
			warn "no hits during the window: no client queried, or its DNS is not routed via this router"
		fi
	fi
fi

# ---- 6. opt-in: 临时 netns 端到端（veth 报文真实经过 PREROUTING）----
if [ "$USE_NETNS" = "1" ]; then
	section "5. end-to-end via temporary netns"

	if ! command -v ip >/dev/null 2>&1; then
		fail "--netns requires ip-full"
	elif ! ip netns list >/dev/null 2>&1; then
		fail "network namespace support unavailable (need ip-full + kernel netns)"
	elif [ -z "$DIG_TOOL" ] && ! command -v python3 >/dev/null 2>&1; then
		fail "--netns needs dig/kdig/drill or python3 inside the test path"
	else
		NS="dsv6dns$$"
		VHOST="veth-ds6a$$"
		VCLI="veth-ds6b$$"
		# 唯一本地地址段（RFC4193），避开真实 LAN；PID 取模后转 4 位 hex hextet
		PID_HEX="$(printf '%04x' "$(( $$ % 65536 ))")"
		NET="fd64:736f:636b:$PID_HEX"
		HOST_IP="$NET::1"
		CLI_IP="$NET::2"
		# OpenWrt netns 在 /var/run 下建 bind mount，确保目录存在
		mkdir -p /var/run/netns 2>/dev/null

		FWD_OLD=""
		cleanup_netns() {
			[ -n "$FWD_OLD" ] && \
				sysctl -w "net.ipv6.conf.$VHOST.forwarding=$FWD_OLD" >/dev/null 2>&1
			ip netns del "$NS" 2>/dev/null
			ip link del "$VHOST" 2>/dev/null
		}
		trap cleanup_netns EXIT INT TERM

		info "creating veth pair $VHOST/$VCLI and netns $NS (temporary)"
		if ip netns add "$NS" && \
			ip link add "$VHOST" type veth peer name "$VCLI" && \
			ip link set "$VCLI" netns "$NS"; then
			pass "netns + veth created"
		else
			fail "failed to create netns/veth (kernel veth support?)"
		fi

		if [ "$FAIL_COUNT" = "0" ]; then
			# lo up；并在地址分配前关掉 client 端 DAD，省去 1s 乐观地址等待
			ip netns exec "$NS" ip link set lo up 2>/dev/null
			ip netns exec "$NS" sysctl -w "net.ipv6.conf.$VCLI.accept_dad=0" >/dev/null 2>&1

			# IPv6 转发仅在该临时 veth 上临时开启（不动 all/全局），结束恢复
			FWD_OLD="$(sysctl -n "net.ipv6.conf.$VHOST.forwarding" 2>/dev/null)"
			sysctl -w "net.ipv6.conf.$VHOST.forwarding=1" >/dev/null 2>&1

			ip addr add "$HOST_IP/64" dev "$VHOST" 2>/dev/null
			ip link set "$VHOST" up 2>/dev/null
			ip netns exec "$NS" ip addr add "$CLI_IP/64" dev "$VCLI" 2>/dev/null
			ip netns exec "$NS" ip link set "$VCLI" up 2>/dev/null
			ip netns exec "$NS" ip -6 route add default via "$HOST_IP" dev "$VCLI" 2>/dev/null
			pass "veth addressing, v6 forwarding and default route configured"

			# 从 netns 向"外部 v6 DNS"查询：报文经 veth 进入 root ns 的
			# PREROUTING，被 nat6 REDIRECT 改写成本机 DNS 端口，由
			# domain-socks 应答。报文不会离开路由器，无需真实互联网连通。
			EXTERNAL_V6_DNS="2400:3200::1"
			info "UDP query @$EXTERNAL_V6_DNS from netns (must be redirected to local :$PORT)"
			ans_udp="$(RUNNER="ip netns exec $NS" \
				dns_query "$EXTERNAL_V6_DNS" 53 "$PROXY_DOMAIN" udp 2>/dev/null)"
			ans_addr="$(echo "$ans_udp" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -n1)"
			if [ -n "$ans_addr" ]; then
				pass "netns UDP/53 got an answer via the REDIRECT path: $ans_addr"
				if is_fakeip "$ans_addr"; then
					pass "UDP answer is Fake-IP -> IPv6 DNS hijack verified end-to-end"
				else
					fail "UDP answer $ans_addr is not in 198.18/15; packet bypassed the redirect?"
				fi
			else
				fail "no UDP answer from netns query (v6 forwarding / REDIRECT rule / resolver chain)"
			fi

			info "TCP query @$EXTERNAL_V6_DNS from netns (tcp/53 REDIRECT path)"
			ans_tcp="$(RUNNER="ip netns exec $NS" \
				dns_query "$EXTERNAL_V6_DNS" 53 "$PROXY_DOMAIN" tcp 2>/dev/null)"
			ans_addr_tcp="$(echo "$ans_tcp" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -n1)"
			if [ -n "$ans_addr_tcp" ]; then
				pass "netns TCP/53 got an answer via the REDIRECT path: $ans_addr_tcp"
			else
				fail "no TCP answer from netns query (tcp/53 REDIRECT rule or resolver chain)"
			fi
			# 函数调用前缀的临时赋值在 POSIX shell 中会留存，显式复位
			RUNNER=""
		fi

		cleanup_netns
		trap - EXIT INT TERM
		info "temporary netns and veth removed"
	fi
fi

# ---- 汇总 ----
section "summary"
echo "PASS items reported above; warnings: $WARN_COUNT; failures: $FAIL_COUNT"
if [ "$FAIL_COUNT" -gt 0 ]; then
	echo
	echo "next steps for common failures:"
	echo "  - kmod-ipt-nat6 missing : opkg update && opkg install kmod-ipt-nat6 ip6tables"
	echo "  - no v6 listener       : start with '-dns [::]:$PORT' (default in the init script)"
	echo "  - no client hits       : ensure LAN clients route IPv6 via this router (RA/DHCPv6),"
	echo "                           or re-run with --netns for a self-contained end-to-end test"
	exit 1
fi
exit 0
