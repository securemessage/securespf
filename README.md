# SecureSPF

High-performance SPF verification milter for Postfix.

## Overview

SecureSPF implements RFC 7208 (Sender Policy Framework) as a milter that integrates with Postfix via the Sendmail milter protocol v6. It evaluates SPF records for incoming mail and adds `Authentication-Results` headers with the SPF verdict.

## Features

- **Thread-per-core architecture** with kqueue I/O multiplexing
- **DNS resolution** with per-worker TTL caching, negative caching, and proactive health monitoring
- **Full RFC 7208 compliance**: all mechanisms (`all`, `include`, `a`, `mx`, `ip4`, `ip6`, `exists`, `ptr`) and qualifiers (`+`, `-`, `~`, `?`)
- **SPF macro expansion** (`%{s}`, `%{l}`, `%{d}`, `%{i}`, etc.)
- **10-lookup limit** enforcement per RFC 7208 §4.6.4
- **Multi-listener** support (TCP and Unix domain sockets)
- **IP whitelist** — bypass SPF checks for trusted senders
- **ZMQ event publishing** for analytics/reporting
- **IPv4 and IPv6** support
- **SIGHUP reload** without dropping connections
- **INI-style configuration** with `[listener:name]` sections

## Quick Start

```sh
# Build
zig build

# Create user and directories
pw useradd _spf -d /nonexistent -s /usr/sbin/nologin
mkdir -p /var/run/securespf /usr/local/etc/securespf
chown _spf:_spf /var/run/securespf

# Write config
cat > /usr/local/etc/securespf/securespf.conf << 'EOF'
[global]
AuthservID      = mail.example.com
User            = _spf
PidFile         = /var/run/securespf/securespf.pid
DnsNameserver   = 127.0.0.1

[listener:inbound]
Socket          = inet:8890@0.0.0.0
EOF

# Install and start
cp zig-out/bin/securespf /usr/local/sbin/
securespf -c /usr/local/etc/securespf/securespf.conf

# Verify it's running
cat /var/run/securespf/securespf.pid
```

## Configuration Reference

### [global]

| Option | Default | Description |
|--------|---------|-------------|
| `AuthservID` | `localhost` | Authentication-Results header identifier |
| `WorkerThreads` | `0` (auto) | Worker thread count (0 = CPU count) |
| `MaxConnections` | `256` | Max simultaneous connections per worker |
| `PidFile` | `/var/run/securespf/securespf.pid` | PID file path |
| `Foreground` | `no` | Run in foreground (no daemonize) |
| `User` | *(none)* | Drop privileges to this user |
| `Syslog` | `yes` | Enable syslog output |
| `SyslogFacility` | `mail` | Syslog facility |
| `LogLevel` | `info` | Log level: err, warn, info, debug |
| `DnsNameserver` | `127.0.0.1` | Comma-separated nameserver IPs |
| `DnsTimeout` | `5` | DNS timeout in seconds |
| `DnsRetries` | `2` | DNS retry count |
| `DnsCacheSize` | `1000` | Per-worker DNS cache max entries |
| `DnsNegativeTTL` | `60` | Negative cache TTL in seconds |
| `WhitelistFile` | *(none)* | IP whitelist file (one per line) |
| `ZmqEndpoint` | *(disabled)* | ZMQ PUB endpoint |
| `ZmqTopic` | `spf.result` | ZMQ topic prefix |

### [listener:name]

| Option | Default | Description |
|--------|---------|-------------|
| `Socket` | — | `inet:port@host` or `unix:/path` |

## Postfix Integration

Add to `/usr/local/etc/postfix/main.cf`:

```ini
smtpd_milters = inet:127.0.0.1:8890
milter_connect_macros = j {daemon_name} v {client_addr}
milter_default_action = accept
```

> **Important**: `{client_addr}` in `milter_connect_macros` is required for SecureSPF to see the SMTP client IP.

### Milter Chain Ordering

When using the full SecureMilter suite:

```ini
smtpd_milters = inet:127.0.0.1:8890,
                inet:127.0.0.1:8891,
                inet:127.0.0.1:8894,
                inet:127.0.0.1:8895
```

Order: **SPF (8890) → DKIM (8891) → DMARC (8894) → ARC (8895)**

## CLI Tool

`securespf-check` performs standalone SPF evaluation:

```sh
securespf-check -i 192.168.1.233 -s user@bambania.com
securespf-check -i 2001:db8::1 -s user@example.org -n 8.8.8.8
```

## Signals

- **SIGHUP** — Reload configuration (active connections unaffected)
- **SIGTERM** — Graceful shutdown (30s drain timeout)

## Part of the SecureMilter Suite

- [securemilter-lib](https://pacyworld.dev/securemessage/securemilter-lib) — Shared infrastructure library
- **SecureSPF** — SPF verification (this project)
- [SecureDKIM](https://pacyworld.dev/securemessage/securedkim) — DKIM signing and verification
- [SecureDMARC](https://pacyworld.dev/securemessage/securedmarc) — DMARC policy evaluation
- [SecureARC](https://pacyworld.dev/securemessage/securearc) — ARC chain validation and sealing

## Requirements

- Zig 0.15.x
- FreeBSD (kqueue/kevent)
- Postfix with milter support (`milter_protocol = 6`)

## License

BSD-2-Clause — Copyright (c) 2026, Daniel Morante
