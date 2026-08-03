//! The SPF mechanisms that test the connection — RFC 7208 §5 — and the
//! domain-spec expansion every one of them goes through first.
//!
//! `include` is deliberately **not** here. §5.2 defines it as a recursive
//! `check_host()`, not as a test on the connection, so it lives beside the
//! recursive walk in `evaluate.zig` together with the dispatch that reaches it.
//! That asymmetry is the specification's, not an accident of layout, and it is
//! also what keeps this file at the bottom of a DAG: if `include` were here, this
//! file would have to import the evaluator that imports it.

const std = @import("std");
const mem = std.mem;

const securemilter = @import("securemilter");
const dns = securemilter.dns;

const spf = @import("spf.zig");
const macro = @import("macro.zig");
const context = @import("context.zig");
const ptr = @import("ptr.zig");

const Eval = context.Eval;
const EvalContext = context.EvalContext;
const EvalError = context.EvalError;
const Limits = context.Limits;

pub fn matchIp4(ctx: *const EvalContext, directive: spf.Directive) bool {
    if (ctx.is_ipv6) return false;
    const arg = directive.argument orelse return false;
    const parsed = spf.parseIp4Arg(arg) catch return false;
    const client_bytes = spf.parseIp4Bytes(ctx.client_ip) catch return false;
    const prefix = directive.cidr4 orelse parsed.prefix;
    return spf.matchIp4Cidr(client_bytes, parsed.addr, prefix);
}

pub fn matchIp6(ctx: *const EvalContext, directive: spf.Directive) bool {
    if (!ctx.is_ipv6) return false;
    const arg = directive.argument orelse return false;
    const prefix_len = directive.cidr6 orelse 128;
    // Both addresses go through the same RFC 4291 parser the record was validated
    // with, so a literal accepted at parse time cannot be read differently here.
    const client = spf.parseIp6Bytes(ctx.client_ip) catch return false;
    const network = spf.parseIp6Bytes(arg) catch return false;
    return matchIp6Cidr(client, network, prefix_len);
}

fn matchIp6Cidr(client: [16]u8, network: [16]u8, prefix_len: u8) bool {
    if (prefix_len > 128) return false;
    if (prefix_len == 0) return true;

    const full_bytes = prefix_len / 8;
    if (!mem.eql(u8, client[0..full_bytes], network[0..full_bytes])) return false;

    const remaining_bits = @as(u4, @intCast(prefix_len % 8));
    if (remaining_bits > 0) {
        const shift: u3 = @intCast(8 - remaining_bits);
        const mask: u8 = @as(u8, 0xFF) << shift;
        if ((client[full_bytes] & mask) != (network[full_bytes] & mask)) return false;
    }
    return true;
}

/// Expand a domain-spec against the evaluation context.
///
/// **Every** term carrying a domain-spec goes through here: `a`, `mx`, `ptr`,
/// `exists`, `include` and `redirect`. Only `exists` used to expand, so the other
/// five queried the macro's literal characters -- `a:%{H}` looked up the name
/// "%{H}" and `redirect=%{d}.d.spf.example.com` the name "%{d}.d.spf.example.com".
/// The name resolved was never the name the record named.
///
/// This is the fifth rule found implemented in several places and honoured in only
/// some, after D-1, A-5, D-15 and the macro-less mechanisms above, which is why
/// there is one function rather than six call sites. Two of those six callers --
/// `include` and `redirect` -- are in `evaluate.zig`, which is why this is `pub`:
/// the point of the function is that there is exactly one of it.
///
/// Caller owns the returned memory.
pub fn expandDomainSpec(ev: Eval, domain: []const u8, template: []const u8) EvalError![]u8 {
    // `%{p}` costs a reverse lookup and a forward confirmation per candidate, so it
    // is resolved only when a template actually asks for it. Everything else in the
    // macro set is derived from the context we already hold.
    var validated: ?[]u8 = null;
    defer if (validated) |v| ev.allocator.free(v);
    if (ptr.usesValidatedDomain(template)) {
        validated = try ptr.validatedDomain(ev, domain);
    }

    const macro_ctx = macro.Context{
        .sender = ev.ctx.sender,
        .domain = domain,
        .client_ip = ev.ctx.client_ip,
        .is_ipv6 = ev.ctx.is_ipv6,
        .validated_domain = validated orelse "unknown",
        .helo_domain = ev.ctx.helo_domain,
        .receiver_host = ev.ctx.receiver_host,
    };

    // A macro that will not expand is a defect in the record, and §4.6 makes a
    // syntax defect a permerror. Reporting "did not match" instead carries the
    // evaluation on to the record's own `-all` and rejects the mail on the
    // strength of a term that was never evaluated.
    return macro.expand(ev.allocator, template, &macro_ctx) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.RecordSyntax,
    };
}

/// The name a mechanism's domain-spec refers to, defaulting to the current domain
/// for the mechanisms whose argument is optional.
fn expandTarget(ev: Eval, domain: []const u8, directive: spf.Directive) EvalError![]u8 {
    const template = directive.argument orelse return ev.allocator.dupe(u8, domain);
    return expandDomainSpec(ev, domain, template);
}

pub fn matchA(ev: Eval, domain: []const u8, directive: spf.Directive) EvalError!bool {
    try ev.state.chargeTerm();
    const target = try expandTarget(ev, domain, directive);
    defer ev.allocator.free(target);
    const prefix4 = directive.cidr4 orelse 32;
    const prefix6 = directive.cidr6 orelse 128;

    const rtype: dns.RecordType = if (ev.ctx.is_ipv6) .AAAA else .A;
    var result = (try ev.state.query(ev.resolver, target, rtype)) orelse return false;
    defer result.deinit();

    if (!ev.ctx.is_ipv6) {
        const client_bytes = spf.parseIp4Bytes(ev.ctx.client_ip) catch return false;
        for (result.answers) |ans| {
            if (ans.record_type == @intFromEnum(dns.RecordType.A) and ans.data.len >= 4) {
                if (spf.matchIp4Cidr(client_bytes, ans.data[0..4].*, prefix4)) return true;
            }
        }
    } else {
        const client = spf.parseIp6Bytes(ev.ctx.client_ip) catch return false;
        for (result.answers) |ans| {
            if (ans.record_type == @intFromEnum(dns.RecordType.AAAA) and ans.data.len >= 16) {
                if (matchIp6Cidr(client, ans.data[0..16].*, prefix6)) return true;
            }
        }
    }
    return false;
}

pub fn matchMx(ev: Eval, domain: []const u8, directive: spf.Directive) EvalError!bool {
    try ev.state.chargeTerm();
    const target = try expandTarget(ev, domain, directive);
    defer ev.allocator.free(target);
    const prefix4 = directive.cidr4 orelse 32;
    const prefix6 = directive.cidr6 orelse 128;

    var mx_result = (try ev.state.query(ev.resolver, target, .MX)) orelse return false;
    defer mx_result.deinit();

    const rtype: dns.RecordType = if (ev.ctx.is_ipv6) .AAAA else .A;

    // RFC 7208 §4.6.4 caps the records examined *inside* one `mx` at 10, as a
    // separate budget from the 10 terms. The previous code charged each MX host
    // to the term budget instead, so a domain with ten MX hosts spent the whole
    // evaluation allowance on a single valid mechanism.
    var records: usize = 0;

    for (mx_result.answers) |ans| {
        if (ans.record_type != @intFromEnum(dns.RecordType.MX)) continue;
        // MX data contains the exchange hostname
        const mx_host = ans.data;
        if (mx_host.len == 0) continue;

        records += 1;
        if (records > Limits.MAX_RECORDS_PER_MECHANISM) {
            return error.MechanismRecordLimitExceeded;
        }

        var addr_result = (try ev.state.querySub(ev.resolver, mx_host, rtype)) orelse continue;
        defer addr_result.deinit();

        if (!ev.ctx.is_ipv6) {
            const client_bytes = spf.parseIp4Bytes(ev.ctx.client_ip) catch return false;
            for (addr_result.answers) |a_ans| {
                if (a_ans.record_type == @intFromEnum(dns.RecordType.A) and a_ans.data.len >= 4) {
                    if (spf.matchIp4Cidr(client_bytes, a_ans.data[0..4].*, prefix4)) return true;
                }
            }
        } else {
            const client = spf.parseIp6Bytes(ev.ctx.client_ip) catch return false;
            for (addr_result.answers) |a_ans| {
                if (a_ans.record_type == @intFromEnum(dns.RecordType.AAAA) and a_ans.data.len >= 16) {
                    if (matchIp6Cidr(client, a_ans.data[0..16].*, prefix6)) return true;
                }
            }
        }
    }
    return false;
}

pub fn matchExists(ev: Eval, domain: []const u8, directive: spf.Directive) EvalError!bool {
    try ev.state.chargeTerm();

    const expanded = try expandTarget(ev, domain, directive);
    defer ev.allocator.free(expanded);

    // exists: any A record is a match. RFC 7208 §5.7 specifies an A query even
    // when the client is IPv6, which is why this does not branch on is_ipv6.
    var result = (try ev.state.query(ev.resolver, expanded, .A)) orelse return false;
    result.deinit();
    return true;
}

pub fn matchPtr(ev: Eval, domain: []const u8, directive: spf.Directive) EvalError!bool {
    // RFC 7208 §5.5: ptr mechanism is NOT RECOMMENDED but MUST be implemented
    try ev.state.chargeTerm();

    const target_domain = try expandTarget(ev, domain, directive);
    defer ev.allocator.free(target_domain);

    // §5.5: the mechanism matches when any *validated* name for the client address
    // is the target domain or a subdomain of it. The validation itself is shared
    // with the `%{p}` macro, which §7.2 defines in terms of this same procedure.
    var validated = try ptr.validatedNames(ev);
    defer validated.deinit();

    for (validated.names.items) |name| {
        if (ptr.isSubdomainOf(name, target_domain)) return true;
    }
    return false;
}

// =============================================================================
// Tests
// =============================================================================

test "matchIp6Cidr" {
    const addr1 = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    const net1 = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    try std.testing.expect(matchIp6Cidr(addr1, net1, 32));
    try std.testing.expect(!matchIp6Cidr(addr1, net1, 128));
    try std.testing.expect(matchIp6Cidr(addr1, addr1, 128));
}

test "matchIp4 directive" {
    const ctx = EvalContext{
        .client_ip = "192.168.1.42",
        .is_ipv6 = false,
        .sender = "user@example.com",
        .helo_domain = "mail.example.com",
        .receiver_host = "mx.local",
    };
    const directive = spf.Directive{
        .qualifier = .pass,
        .mechanism = .ip4,
        .argument = "192.168.1.0/24",
        .cidr4 = null,
        .cidr6 = null,
    };
    try std.testing.expect(matchIp4(&ctx, directive));
}
