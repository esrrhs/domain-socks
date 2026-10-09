# domain-socks

[![Test](https://github.com/esrrhs/domain-socks/actions/workflows/test.yml/badge.svg)](https://github.com/esrrhs/domain-socks/actions/workflows/test.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/esrrhs/domain-socks)](https://goreportcard.com/report/github.com/esrrhs/domain-socks)

A lightweight Fake-IP transparent proxy client designed for OpenWrt and Linux routers. It intercepts DNS queries, assigns RFC 2544 Fake-IPs (`198.18.0.0/15`), intercepts redirected TCP traffic, and forwards it to an upstream SOCKS5 proxy using domain-based requests (`ATYP=0x03`).


## Features

- **Smart CN & Direct Split Routing**: Powered by [`gohome/dns`](https://github.com/esrrhs/gohome). Built-in `.cn` TLDs and major Chinese domestic domains resolve directly to real IPs; traffic connects directly without touching the proxy. Non-CN/proxy domains receive Fake-IPs and are routed via SOCKS5.
- **Fake-IP DNS Server**: Responds immediately with Fake-IP addresses (`198.18.0.0/15`) for proxy domains to avoid DNS pollution and speed up connection establishment.
- **Transparent Redirect**: Works with Linux iptables/nftables `REDIRECT` (`SO_ORIGINAL_DST`).
- **Domain Restoration & Sniffing**:
  - Restores original domains from the in-memory Fake-IP map.
  - Sniffs SNI (TLS Client Hello) or HTTP `Host` header as a fallback.
- **Captive Portal Bypass**: Responds HTTP 204 directly for `/generate_204` connectivity check probes.
- **SOCKS5 Upstream**: Forwards connections with domain names (`ATYP=0x03`), letting the remote SOCKS5 server handle external resolution and routing.

## Usage

```bash
domain-socks -socks <proxy_ip:port> -dns <dns_listen> -listen <redirect_listen>
```

### Options

- `-socks`: Upstream SOCKS5 proxy address (default: `192.168.1.101:1081`)
- `-dns`: DNS listen address (UDP/TCP, default: `127.0.0.1:1053`)
- `-listen`: Transparent redirect TCP listen address (default: `0.0.0.0:12345`)
- `-direct-dns`: Upstream DNS servers for domestic queries (comma-separated, default: `223.5.5.5:53,119.29.29.29:53`)
- `-direct-domains-file`: Optional file path containing extra direct domains (supports line list and dnsmasq format)

## OpenWrt Integration

See [`domain-socks.init`](domain-socks.init) for the procd service configuration.
