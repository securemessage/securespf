# SecureSPF

High-performance SPF verification milter for Postfix.

## Overview

SecureSPF implements RFC 7208 (Sender Policy Framework) as a milter that integrates with Postfix via the Sendmail milter protocol v6. It evaluates SPF records for incoming mail and adds `Authentication-Results` headers with the SPF verdict.

## Features

- **Thread-per-core architecture** with kqueue I/O multiplexing
- **Async DNS** resolution with per-worker TTL caching
- **Full RFC 7208 compliance**: all mechanisms (`all`, `include`, `a`, `mx`, `ip4`, `ip6`, `exists`, `ptr`) and qualifiers (`+`, `-`, `~`, `?`)
- **SPF macro expansion** (`%{s}`, `%{l}`, `%{d}`, `%{i}`, etc.)
- **10-lookup limit** enforcement per RFC 7208 §4.6.4
- **Multi-listener** support (TCP and Unix domain sockets)
- **ZMQ event publishing** for analytics/reporting
- **IPv4 and IPv6** support
- **INI-style configuration** with `[listener:name]` sections

## Part of the SecureMilter Suite

- [securemilter-lib](https://pacyworld.dev/securemessage/securemilter-lib) — Shared library
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
