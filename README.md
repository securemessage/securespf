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
- **IP whitelist** -- bypass SPF checks for trusted senders
- **Trusted relays** -- skip evaluation for your own relay infrastructure (stamps `none`, never `pass`)
- **ZMQ event publishing** for analytics/reporting
- **IPv4 and IPv6** support
- **SIGHUP reload** without dropping connections
- **INI-style configuration** with `[listener:name]` sections

## Quick Start

```sh
# Build
zig build

# Create directories (mailnull is the shared FreeBSD milter account other
# milters already run as -- no dedicated user needed)
mkdir -p /var/run/securespf /usr/local/etc/securespf

# Write config
cat > /usr/local/etc/securespf/securespf.conf << 'EOF'
[global]
AuthservID      = mail.example.com
User            = mailnull
PidFile         = /var/run/securespf/securespf.pid
DnsNameserver   = 127.0.0.1

[listener:inbound]
Socket          = inet:8890@127.0.0.1
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
| `StripAuthResults` | `no` | Remove pre-existing Authentication-Results headers claiming our `AuthservID`; enable only on the first milter in the chain (RFC 8601 §5) |
| `WorkerThreads` | `0` (auto) | Worker thread count (0 = CPU count) |
| `MaxConnections` | `256` | Max simultaneous connections per worker |
| `PidFile` | `/var/run/securespf/securespf.pid` | PID file path |
| `Foreground` | `no` | Run in foreground (no daemonize) |
| `User` | *(none)* | Drop privileges to this user |
| `UMask` | *(inherited)* | File-creation mask (octal) for the PID file and any unix-domain listener |
| `Syslog` | `yes` | Enable syslog output |
| `SyslogFacility` | `mail` | Syslog facility |
| `LogLevel` | `info` | Log level: err, warn, info, debug |
| `DnsNameserver` | `127.0.0.1` | Comma-separated nameserver IPs |
| `DnsTimeout` | `5` | DNS timeout in seconds |
| `DnsRetries` | `2` | DNS retry count |
| `DnsCacheSize` | `1000` | Per-worker DNS cache max entries |
| `DnsNegativeTTL` | `60` | Negative cache TTL in seconds |
| `WhitelistFile` | *(none)* | IP whitelist file (one per line); stamps `pass` |
| `TrustedRelaysFile` | *(none)* | Own-relay list (one per line); skips evaluation, stamps `none` |
| `MaxHeaders` | `500` | Largest number of headers accumulated per message; 0 disables the limit |
| `MaxHeaderBytes` | `1M` | Largest total header size per message; 0 disables the limit |
| `MaxVoidLookups` | `2` | Largest number of terms per SPF record whose DNS lookup finds nothing (RFC 7208 §4.6.4); 0 disables the limit |
| `MaxEvaluationMs` | `20000` | Wall-clock ceiling for evaluating one message; 0 disables it |
| `ZmqEndpoint` | *(disabled)* | ZMQ PUB endpoint |
| `ZmqTopic` | `spf.result` | ZMQ topic prefix |

### [listener:name]

| Option | Default | Description |
|--------|---------|-------------|
| `Socket` | -- | `inet:port@ip` or `unix:/path`. The IP must be numeric (no DNS). An unparseable value is a fatal startup error, never ignored. |

## Postfix Integration

Add to `/usr/local/etc/postfix/main.cf`:

```ini
smtpd_milters = inet:127.0.0.1:8890
milter_connect_macros = j {daemon_name} v {client_addr}
milter_default_action = accept
```

> **Note**: `{client_addr}` in `milter_connect_macros` is not strictly required
> on a stock single-`smtpd` Postfix install; SecureSPF falls back to the
> milter protocol's own `SMFIC_CONNECT` payload when the macro is absent. It
> **is** required if your mail passes through more than one `smtpd` process
> (e.g. a `content_filter` re-injecting via `XCLIENT`), because only the macro
> still carries the original client address at that point. Setting it is
> always safe, so the example above sets it unconditionally.

### Milter Chain Ordering

When using the full SecureMilter suite with SecureDMARC in its default
stamp-only mode:

```ini
smtpd_milters = inet:127.0.0.1:8890,
                inet:127.0.0.1:8891,
                inet:127.0.0.1:8894,
                inet:127.0.0.1:8895
```

Order: **SPF (8890) → DKIM (8891) → DMARC (8894) → ARC (8895)**

If you enable SecureDMARC's `Enforcement` with a `TrustedSealersFile`
override, SecureARC's *verify* step must run **before** SecureDMARC instead;
see [securedmarc's README](https://pacyworld.dev/securemessage/securedmarc#milter-chain-ordering)
for that ordering and why it differs.

## CLI Tool

`securespf-check` performs standalone SPF evaluation:

```sh
securespf-check -i 192.168.1.233 -s user@bambania.com
securespf-check -i 2001:db8::1 -s user@example.org -n 8.8.8.8
```

## Signals

- **SIGHUP** -- Reload configuration (active connections unaffected)
- **SIGTERM** -- Graceful shutdown (30s drain timeout)

## Part of the SecureMilter Suite

- [securemilter-lib](https://pacyworld.dev/securemessage/securemilter-lib) -- Shared infrastructure library
- **SecureSPF** -- SPF verification (this project)
- [SecureDKIM](https://pacyworld.dev/securemessage/securedkim) -- DKIM signing and verification
- [SecureDMARC](https://pacyworld.dev/securemessage/securedmarc) -- DMARC policy evaluation
- [SecureARC](https://pacyworld.dev/securemessage/securearc) -- ARC chain validation and sealing

## Requirements

- Zig 0.15.x
- FreeBSD (kqueue/kevent)
- Postfix with milter support (`milter_protocol = 6`)

## License

BSD-2-Clause -- Copyright (c) 2026, Daniel Morante
