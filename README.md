# domain-socks

[![Test](https://github.com/esrrhs/domain-socks/actions/workflows/test.yml/badge.svg)](https://github.com/esrrhs/domain-socks/actions/workflows/test.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/esrrhs/domain-socks)](https://goreportcard.com/report/github.com/esrrhs/domain-socks)

A lightweight Fake-IP transparent proxy client designed for OpenWrt and Linux routers. It intercepts DNS queries, assigns RFC 2544 Fake-IPs (`198.18.0.0/15`), intercepts redirected TCP traffic, and forwards it to an upstream SOCKS5 proxy using domain-based requests (`ATYP=0x03`).


## Features

- **Smart CN & Direct Split Routing**: Powered by [`gohome/dns`](https://github.com/esrrhs/gohome). Built-in `.cn` TLDs and major Chinese domestic domains resolve directly to real IPs; traffic connects directly without touching the proxy. Non-CN/proxy domains receive Fake-IPs and are routed via SOCKS5.
- **Fake-IP DNS Server**: Responds immediately with Fake-IP addresses (`198.18.0.0/15`) for proxy domains to avoid DNS pollution and speed up connection establishment.
- **Transparent Redirect**: Works with Linux iptables/nftables `REDIRECT` (`SO_ORIGINAL_DST`, IPv4) or `TPROXY` (dual-stack, IPv4 + IPv6).
- **Domain Restoration & Sniffing**:
  - Restores original domains from the in-memory Fake-IP map.
  - Sniffs SNI (TLS Client Hello) or HTTP `Host` header as a fallback, tolerating TCP segmentation of the handshake/request headers.
- **IPv6 Leak Protection**: Proxy-domain `AAAA` queries get an empty `NOERROR` answer so clients fall back to IPv4 Fake-IPs instead of bypassing the IPv4-only transparent redirect over native IPv6.
- **QUIC / HTTP3 Fallback**: Pair it with a `REJECT` rule on forwarded UDP/443 so browsers fall back to TLS over TCP immediately.
- **Captive Portal Bypass**: Responds HTTP 204 directly for `/generate_204` connectivity check probes.
- **SOCKS5 Upstream**: Forwards TCP connections with domain names (`ATYP=0x03`), letting the remote SOCKS5 server handle external resolution and routing.
- **Optional UDP Relay** (`-udplisten` / `-udp-tproxy`): Transparently intercepted UDP is relayed via RFC 1928 UDP ASSOCIATE (one shared association, domain-mode `ATYP=0x03` for Fake-IP targets, `ATYP=0x04` for literal IPv6 proxy targets) or sent direct (separate v4/v6 sockets); control-channel loss triggers automatic re-association. `REDIRECT` mode is IPv4-only; `TPROXY` mode is dual-stack. Disabled by default.
- **Graceful Shutdown**: Drains in-flight connections (up to 3s) on SIGINT/SIGTERM.

## Usage

```bash
domain-socks -socks <proxy_ip:port> -dns <dns_listen> -listen <redirect_listen>
```

### Options

- `-socks`: Upstream SOCKS5 proxy address (default: `192.168.1.101:1081`)
- `-socks-user`: Upstream SOCKS5 username (optional, RFC 1929)
- `-socks-pass`: Upstream SOCKS5 password (optional, RFC 1929)
- `-dns`: DNS listen address (UDP/TCP, default: `[::]:1053`). A wildcard host (`[::]` / `0.0.0.0` / empty) binds one dual-stack socket serving both IPv4 and IPv6 traffic, automatically falling back to IPv4-only wildcard if the kernel lacks an IPv6 stack. An explicit address such as `127.0.0.1:1053` binds exactly as given. The wildcard relies on the firewall's default WAN `input` reject (standard on OpenWrt) to avoid exposure upstream
- `-listen`: Transparent redirect TCP listen address (default: `0.0.0.0:12345`)
- `-direct-dns`: Upstream DNS servers for domestic queries (comma-separated, default: `223.5.5.5:53,119.29.29.29:53`)
- `-direct-domains-file`: Optional file path containing extra direct domains (supports line list and dnsmasq format)
- `-proxy-domains-file`: Optional file path containing extra proxy domains (supports line list and dnsmasq format)
- `-geoip`: Optional `GeoLite2-Country.mmdb` path used for IP-based CN split routing
- `-disable-aaaa`: Return empty `NOERROR` for proxy-domain AAAA queries to prevent IPv6 bypass leak (default: `true`; pass `-disable-aaaa=false` to forward AAAA normally)
- `-udplisten`: Transparent UDP REDIRECT listen address for SOCKS5 UDP ASSOCIATE relay (IPv4 only; default: disabled; e.g. `0.0.0.0:12346`). Requires a matching `nat ... -p udp -j REDIRECT` rule — set `ENABLE_UDP=1` in the init script to install it
- `-tproxy`: TCP TPROXY dual-stack listen address (default: disabled; e.g. `:12345`). Mutually exclusive with `-listen`; enables interception of native IPv6 traffic. Requires `mangle ... -j TPROXY` rules plus `fwmark` policy routing (see below)
- `-udp-tproxy`: UDP TPROXY dual-stack listen address (default: disabled; e.g. `:12346`). Mutually exclusive with `-udplisten`; use together with `-tproxy` and `ENABLE_UDP=1` for IPv6 UDP relay
- `-stats-addr`: Read-only runtime metrics endpoint (default: `127.0.0.1:18080`). `GET /` returns a human-readable snapshot, `GET /json` machine-readable JSON — TCP proxy/direct/failure counts with per-route up/down byte totals and active-connection gauge, UDP packets in/out with payload byte totals, ASSOCIATE establish/teardown/cooldown counts, active UDP clients/flows gauges, DNS total/AAAA queries, filtered AAAA, Fake-IP answer and upstream-error counts, plus uptime and goroutine count. Also four fixed-bucket latency histograms (cumulative counts with sum): `tcp_proxy_dial_seconds` for the full SOCKS5 dial+negotiate+CONNECT attempt, `tcp_direct_dial_seconds` for direct net.Dial, and `udp_assoc_dial_seconds` for UDP ASSOCIATE dial+handshake (real attempts only — cooldown fast-fails are excluded), each with 13 le-buckets from 1ms to 10s; plus `dns_upstream_seconds` with finer 0.5ms–10s buckets measuring real upstream DNS round trips (local AAAA short-circuits excluded; failures included) — all record successes and failures, so a slow-but-not-yet-failing upstream or resolver shows up as a distribution shift before errors accumulate. `GET /healthz` answers `200 ok` as long as the process/event loop is alive (liveness); `GET /readyz` probes the configured upstream SOCKS5 with a read-only greeting+auth handshake (no CONNECT, no proxied traffic) and answers `200 ready` or `503 not ready: <error>`, with results cached for 2s so concurrent scrapers cannot hammer the upstream. `GET /conns` shows the live table of intercepted TCP connections currently dialing or forwarding (age, via socks/direct, state dial/forward, client, target, live up/down bytes, sorted by age) — use it to spot a stuck dial or a long-lived connection without waiting for the access-log line at close. `GET /top` answers "who is using the bandwidth": two cumulative leaderboards (top 20 by total bytes since start) per destination domain/IP and per LAN client IP, with flow counts split proxy/direct and up/down byte totals. It merges both planes: TCP contributes when a connection closes; UDP contributes when a per-target flow is swept idle (2 min) or the daemon shuts down, using the Fake-IP-restored domain for proxied targets. Tables are bounded (8192 domains / 1024 clients, further keys fold into `__other__`) so long-running routers cannot grow memory without limit. `GET /metrics` serves the same counters/gauges/histograms in Prometheus text exposition format 0.0.4 (`text/plain; version=0.0.4`): counters as `domain_socks_*_total`, the dial histograms as `*_bucket{le=...}`/`*_sum`/`*_count`, plus `domain_socks_up` — point a Prometheus `scrape_config` or VictoriaMetrics at `http://<router>:18080/metrics` for Grafana dashboards/alerts, still zero-dependency and read-only. Loopback-only by default; set empty to disable, or `0.0.0.0:18080` to expose to the LAN (no control surface, counters only)
- `-access-log`: Log one summary line per intercepted TCP connection when it closes (default enabled; `-access-log=false` silences). Example: `tcp 192.168.1.5:54321 -> www.google.com:443 via socks up 2.0KiB down 5.00MiB in 2.35s`; dial failures append ` fail: <error>` and use `via socks`/`direct`/`dst-fail`/`captive204` labels.

Quick check on the router:

```bash
curl -s http://127.0.0.1:18080/ | grep -E 'socks_fail|assoc_|forward_fail|dns_|bytes'
# dns_fakeip_answers growing       => DNS hijack + fake-ip split routing works
# dns_aaaa_filtered growing        => clients are forced back to IPv4 (no v6 leak)
# sustained udp_assoc_teardown + socks_fail/forward_fail growth => upstream proxy unhealthy
# tcp_proxy_bytes_* vs tcp_direct_bytes_* => how traffic actually splits
curl -s http://127.0.0.1:18080/json | python3 -c 'import json,sys; print(json.load(sys.stdin)["histograms"]["tcp_proxy_dial_seconds"])'
# cumulative_counts shifting toward le=0.5/1/2 before socks_fail grows => upstream degrading
curl -s http://127.0.0.1:18080/conns
# rows stuck in state=dial with growing age => upstream dial hanging (not yet timed out)
curl -s http://127.0.0.1:18080/top
# per-domain / per-client leaderboards => which site or LAN device consumes bandwidth
curl -s http://127.0.0.1:18080/metrics
# Prometheus exposition; scrape_config job: metrics_path /metrics on :18080
```

## Firewall Rules

The daemon only accepts redirected TCP connections and serves DNS; the router must
steer LAN traffic into it. The rules below only touch `PREROUTING` (forwarded LAN
traffic). Do **not** redirect `OUTPUT` traffic as well: the daemon's own direct
and SOCKS dial-outs originate locally and redirecting them would loop back into
the daemon.

Fake-IP traffic (`198.18.0.0/15`) must be redirected, so it is intentionally not
in the reserved-CIDR bypass list. UDP/443 is rejected with ICMP port-unreachable
so QUIC clients (Chrome/YouTube) fall back to TLS over TCP within one RTT.

### iptables (the init script installs these automatically)

```bash
DNS_PORT=1053
REDIR_PORT=12345

# 1. DNS hijack: TCP/UDP 53 -> local DNS (must precede the catch-all TCP rule)
iptables -t nat -I PREROUTING 1 -p udp --dport 53 -j REDIRECT --to-ports $DNS_PORT
iptables -t nat -I PREROUTING 1 -p tcp --dport 53 -j REDIRECT --to-ports $DNS_PORT

# 1b. Same hijack for IPv6 (needs ip6table_nat / OpenWrt kmod-ipt-nat6);
#     the daemon's single dual-stack DNS socket receives both families
ip6tables -t nat -I PREROUTING 1 -p udp --dport 53 -j REDIRECT --to-ports $DNS_PORT
ip6tables -t nat -I PREROUTING 1 -p tcp --dport 53 -j REDIRECT --to-ports $DNS_PORT

# 2. Transparent TCP redirect, bypassing reserved/private ranges
iptables -t nat -N DOMAIN_SOCKS 2>/dev/null
iptables -t nat -F DOMAIN_SOCKS
iptables -t nat -A DOMAIN_SOCKS -p tcp --dport 53 -j RETURN
for cidr in 0.0.0.0/8 10.0.0.0/8 127.0.0.0/8 169.254.0.0/16 \
            172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 224.0.0.0/4 240.0.0.0/4; do
    iptables -t nat -A DOMAIN_SOCKS -d $cidr -j RETURN
done
iptables -t nat -A DOMAIN_SOCKS -p tcp -j REDIRECT --to-ports $REDIR_PORT
iptables -t nat -A PREROUTING -p tcp -j DOMAIN_SOCKS

# 3. Block QUIC so HTTP/3 falls back to TCP
iptables -N DOMAIN_SOCKS_R 2>/dev/null
iptables -F DOMAIN_SOCKS_R
iptables -A DOMAIN_SOCKS_R -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable
iptables -I FORWARD 1 -j DOMAIN_SOCKS_R
```

### nftables (OpenWrt 22+ default)

```nft
table ip domain_socks {
    set reserved_v4 {
        type ipv4_addr
        elements = { 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16,
                       172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10,
                       224.0.0.0/4, 240.0.0.0/4 }
    }
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        meta l4proto { tcp, udp } th dport 53 redirect to :1053
        ip daddr != @reserved_v4 meta l4proto tcp redirect to :12345
    }
    chain forward {
        type filter hook forward priority filter; policy accept;
        meta l4proto udp th dport 443 reject with icmp type port-unreachable
    }
}
```

To proxy traffic generated by the router itself, add an `OUTPUT` redirect and
exclude the daemon user with `-m owner ! --uid-owner <domain-socks uid>`.

## UDP Relay (SOCKS5 UDP ASSOCIATE)

UDP relay is **off by default**. Enable it with `-udplisten 0.0.0.0:12346`
(or `ENABLE_UDP=1` in the init script, which also installs the matching nat
rule). Requirements:

- Linux kernel `nf_conntrack` (part of the default OpenWrt firewall); the
  original destination is recovered via `SO_ORIGINAL_DST` on a per-client
  connected probe socket.
- An upstream SOCKS5 server supporting UDP ASSOCIATE.

Behavior:

- Fake-IP targets restore the domain and leave remote resolution to the proxy
  (`ATYP=0x03`), exactly like the TCP path; CN/direct targets are sent direct.
- A single UDP ASSOCIATE (TCP control connection + one relay socket) is shared
  by all LAN clients; it is established lazily on the first UDP packet, never
  per packet. If the control connection dies, the next packet transparently
  re-establishes it.
- Idle per-target NAT entries expire after 2 min and idle client probes after
  3 min. Fragmented UDP datagrams (`FRAG != 0`) are dropped.
- The idle control connection uses TCP keepalive (30s) so WAN/NAT half-open
  timeouts tear down and rebuild the association instead of blackholing
  packets; failed handshakes back off for 3s (server-initiated disconnects
  reconnect immediately), and forwarding-failure logs are rate-limited.
- Port 53 stays handled by the local DNS hijack. Port 443 deliberately bypasses
  the UDP redirect so the QUIC `REJECT` rule keeps forcing HTTP/3 browsers onto
  TLS/TCP; remove that `RETURN` line if your upstream supports UDP and you want
  proxied QUIC.

Limitations:

- SOCKS5 UDP replies only identify the remote target, not the LAN sender, so
  when two clients exchange UDP with the same `host:port` simultaneously the
  newer flow owns the reverse mapping. DNS and typical game traffic (unique
  remote ports) are unaffected.
- REDIRECT mode additionally inherits a conntrack constraint: one connected
  probe socket pins one conntrack entry (whose reply tuple is
  `router:redirect-port ↔ client:source-port`), so packets from the **same
  client source port to several destinations** are attributed to the first
  destination. UDP clients normally pick a fresh source port per destination
  (`connect()` semantics), so this is rare in practice; TPROXY mode has no
  such constraint — every packet carries its own original destination and
  per-flow reply sockets keep concurrent destinations independent.

## TPROXY Mode (IPv4 + IPv6)

`REDIRECT` is NAT-based and can only recover the original destination via
`SO_ORIGINAL_DST` (IPv4). **TPROXY** does not NAT: packets are delivered to a
local transparent socket (`IP_TRANSPARENT`) preserving the original
destination — `LocalAddr` on accepted TCP, the `IP_ORIGDSTADDR` /
`IPV6_ORIGDSTADDR` control message on UDP — so one dual-stack listener handles
both families. Enable it with `-tproxy :12345` (and `-udp-tproxy :12346` for
UDP), or set `ENABLE_TPROXY=1` in the init script.

Prerequisites:

- Kernel modules: `xt_TPROXY`, `xt_socket` (`kmod-ipt-tproxy`), and the IPv6
  variants (`nf_tproxy_ipv6`, `ip6table_mangle`).
- `ip-full` (`ip rule` / `ip route`) for policy routing; the daemon must run as
  root / with `CAP_NET_ADMIN`.
- Policy routing that sends fwmarked packets to the local loopback:

```bash
MARK=0x3f; TABLE=100
ip  rule add fwmark $MARK table $TABLE
ip  route add local 0.0.0.0/0 dev lo table $TABLE
ip -6 rule add fwmark $MARK table $TABLE
ip -6 route add local ::/0       dev lo table $TABLE
```

- `mangle/PREROUTING` rules (the init script installs these; `DIVERT` handles
  packets already owned by a local transparent socket):

```bash
iptables -t mangle -N DOMAIN_SOCKS_DIV
iptables -t mangle -A DOMAIN_SOCKS_DIV -j MARK --set-mark $MARK
iptables -t mangle -A DOMAIN_SOCKS_DIV -j ACCEPT
iptables -t mangle -A PREROUTING -p tcp -m socket -j DOMAIN_SOCKS_DIV

iptables -t mangle -N DOMAIN_SOCKS_TP
iptables -t mangle -A DOMAIN_SOCKS_TP -p tcp --dport 53 -j RETURN
iptables -t mangle -A DOMAIN_SOCKS_TP -p udp --dport 53 -j RETURN
iptables -t mangle -A DOMAIN_SOCKS_TP -p udp --dport 443 -j RETURN  # keep QUIC fallback
for cidr in 0.0.0.0/8 10.0.0.0/8 127.0.0.0/8 169.254.0.0/16 \
            172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 224.0.0.0/4 240.0.0.0/4; do
    iptables -t mangle -A DOMAIN_SOCKS_TP -d $cidr -j RETURN
done
iptables -t mangle -A DOMAIN_SOCKS_TP -p tcp -j TPROXY --on-port 12345 --tproxy-mark $MARK
iptables -t mangle -A DOMAIN_SOCKS_TP -p udp -j TPROXY --on-port 12346 --tproxy-mark $MARK
iptables -t mangle -A PREROUTING -p tcp -j DOMAIN_SOCKS_TP
iptables -t mangle -A PREROUTING -p udp -j DOMAIN_SOCKS_TP
```

The IPv6 rules are identical with `ip6tables`, bypassing `::1/128`,
`fc00::/7`, `fe80::/10`, `ff00::/8`.

### Native nftables (dual-stack, no iptables compat)

A single `inet` table covers both families. Requires `kmod-nft-tproxy`,
`kmod-nft-socket`, `kmod-nft-nat` (for the DNS redirect) and `nft` >= 0.9
(kernel >= 5.x recommended). The `ip rule` policy routing above is still
required — nftables only sets the fwmark; it does not program routes.

```nft
define TPROXY_MARK = 0x3f

table inet domain_socks_tproxy {
    set reserved_v4 {
        type ipv4_addr
        flags interval
        elements = {
            0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16,
            172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10,
            224.0.0.0/4, 240.0.0.0/4
        }
    }
    set reserved_v6 {
        type ipv6_addr
        flags interval
        elements = { ::1/128, fc00::/7, fe80::/10, ff00::/8 }
    }

    chain prerouting {
        type filter hook prerouting priority mangle; policy accept;

        # DIVERT: deliver flows already owned by a local transparent
        # listener directly (needed for established TPROXY TCP sockets)
        meta l4proto tcp socket transparent 1 \
            meta mark set $TPROXY_MARK accept

        # port 53: handled by the DNS hijack in the nat table below
        meta l4proto { tcp, udp } th dport 53 return
        # UDP/443: keep falling through to the QUIC REJECT chain
        meta l4proto udp th dport 443 return

        ip  daddr @reserved_v4 return
        ip6 daddr @reserved_v6 return

        meta l4proto tcp tproxy to :12345 meta mark set $TPROXY_MARK accept
        meta l4proto udp tproxy to :12346 meta mark set $TPROXY_MARK accept
    }
}

# Dual-stack DNS hijack (nat redirect works for both families in an inet table)
table inet domain_socks_dns {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        meta l4proto { tcp, udp } th dport 53 redirect to :1053
    }
}

# QUIC rejection: family-correct ICMP/ICMPv6 is chosen automatically in inet
table inet domain_socks_filter {
    chain forward {
        type filter hook forward priority filter; policy accept;
        meta l4proto udp th dport 443 reject
    }
}
```

Apply / remove atomically (the named table is the identity — re-running the
file replaces it wholesale, never rely on fuzzy "rule exists" checks):

```bash
nft -f /etc/nftables.d/99-domain-socks-tproxy.nft
nft delete table inet domain_socks_tproxy
nft delete table inet domain_socks_dns
nft delete table inet domain_socks_filter
```

Notes:

- The mangle chain (`priority mangle`, -150) runs before the nat chain
  (`priority dstnat`, -100), so port-53 packets `return` from TPROXY and are
  then redirected by the DNS rule; the same ordering dependency as iptables.
- On older nft builds that do not auto-select the ICMP family in `inet`
  tables, split the reject into two family tables:
  `ip ... reject with icmp type port-unreachable` and
  `ip6 ... reject with icmpv6 type port-unreachable`.
- Do not mix this table with the init-script iptables rules for the same
  traffic — pick one management plane (`ENABLE_TPROXY` or native nft).

#### IPv6-only variant (`ip6` family)

Use an `ip6` table when IPv4 is handled by the init script's iptables
REDIRECT (or another manager) and only native IPv6 needs TPROXY — the two
families never collide. The daemon still listens dual-stack (`-tproxy
:12345 -udp-tproxy :12346`); only the ruleset is family-scoped.

Only the v6 half of the policy routing is required:

```bash
MARK=0x3f; TABLE=100
ip -6 rule add fwmark $MARK table $TABLE
ip -6 route add local ::/0 dev lo table $TABLE
```

```nft
define TPROXY_MARK = 0x3f

table ip6 domain_socks_tproxy6 {
    set reserved6 {
        type ipv6_addr
        flags interval
        elements = { ::1/128, fc00::/7, fe80::/10, ff00::/8 }
    }

    chain prerouting {
        type filter hook prerouting priority mangle; policy accept;

        # ICMPv6 must bypass TPROXY: NDP (types 133-136), MLD and
        # Packet-Too-Big (type 2, PMTUD) are part of the IPv6 fabric.
        # The reserved6 fe80::/10 match below also covers link-local,
        # but this keeps globally-scoped PTB alive explicitly.
        meta l4proto icmpv6 accept

        # DHCPv6 (client 546 / server 547) stays local
        udp dport { 546, 547 } accept
        udp sport { 546, 547 } accept

        # DIVERT: deliver flows already owned by a local transparent socket
        meta l4proto tcp socket transparent 1 \
            meta mark set $TPROXY_MARK accept

        # port 53 -> v6 nat redirect below; udp/443 -> QUIC reject below
        meta l4proto { tcp, udp } th dport 53 return
        meta l4proto udp th dport 443 return

        ip6 daddr @reserved6 return

        meta l4proto tcp tproxy to :12345 meta mark set $TPROXY_MARK accept
        meta l4proto udp tproxy to :12346 meta mark set $TPROXY_MARK accept
    }
}

table ip6 domain_socks_dns6 {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        meta l4proto { tcp, udp } th dport 53 redirect to :1053
    }
}

table ip6 domain_socks_filter6 {
    chain forward {
        type filter hook forward priority filter; policy accept;
        meta l4proto icmpv6 accept
        meta l4proto udp th dport 443 reject with icmpv6 type port-unreachable
    }
}
```

Apply / remove:

```bash
nft -f /etc/nftables.d/99-domain-socks-tproxy6.nft
nft delete table ip6 domain_socks_tproxy6
nft delete table ip6 domain_socks_dns6
nft delete table ip6 domain_socks_filter6
```

Verify the loop with `./verify-v6-dns.sh --netns` (temporary veth/netns
client, asserts a Fake-IP answer through the v6 PREROUTING path).

IPv6-specific notes:

- Never drop or TPROXY ICMPv6 — unlike IPv4 (where ICMP is optional), NDP
  replaces ARP and Packet-Too-Big drives mandatory PMTUD; blackholing it
  causes silent, delayed breakage days later.
- Match transport with `meta l4proto`, not `ip6 nexthdr`: the latter only
  sees the first Next-Header, so packets carrying extension headers
  (Fragment, AH, Hop-by-Hop) would miss the port rules. `meta l4proto`
  walks the extension chain to the real transport protocol.
- Port matches only see the first fragment; non-first IPv6 fragments hit
  the default `accept` policy (same behaviour as the inet example).
- The daemon's `-dns [::]:1053` dual-stack socket receives the v6
  `redirect`. If the init script also installed its `ip6tables` nat6
  DNS redirect, delete one copy — two managers rewriting the same v6/53
  traffic are redundant (the first match wins) and confusing to debug.

UDP TPROXY semantics differ from REDIRECT: there is no conntrack reverse-NAT,
so replies are sent from per-destination transparent sockets bound to the
exact original `ip:port` (shared across clients, idle-reaped after 2 min).
The reverse mapping is tracked per flow (`client → target`), so one client
exchanging UDP with several destinations concurrently gets each reply from
the matching source address — unlike the REDIRECT conntrack limitation above.

Notes:

- SOCKS5 requests to literal IPv6 targets use `ATYP=0x04`; `::ffff:`-mapped
  addresses are normalized to IPv4 throughout.
- AAAA filtering still applies to proxy domains: clients use IPv4 Fake-IPs for
  proxied sites, while native IPv6 connections to CN/direct targets pass
  through directly.
- DNS hijack covers both families: the init script installs `nat REDIRECT` for
  IPv4 and IPv6 (the latter needs `ip6table_nat` / `kmod-ipt-nat6`) into the
  dual-stack DNS socket, and mangle rules `RETURN` port 53 so TPROXY never
  grabs DNS. Clients may keep any resolver address configured — IPv6 DNS queries
  are redirected regardless of RA/DHCPv6-advertised resolver settings.

## OpenWrt Integration

See [`domain-socks.init`](domain-socks.init) for the procd service configuration.
The init script installs the iptables rules above on start and removes them on
stop; override `PROXY_SERVER`, `DNS_PORT`, `REDIR_PORT` at the top of the file.
Set `ENABLE_UDP=1` to enable UDP relay, and `ENABLE_TPROXY=1` to switch from
IPv4-only `REDIRECT` to dual-stack `TPROXY` (install `kmod-ipt-tproxy`,
`ip6tables-mod-nat`/mangle and `ip-full` first). IPv6 DNS hijack installs in
both modes when `kmod-ipt-nat6` is present. Policy-routing `ip rule`
entries are left in place on stop because they may be shared with other
services; the stop function's comments document the manual cleanup commands.
