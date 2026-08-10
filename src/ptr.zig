//! RFC 7208 §5.5 validated client names for `ptr` and `%{p}`.
//!
//! Both callers share the same reverse-and-forward DNS confirmation path.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");
const dns = securemilter.dns;

const spf = @import("spf.zig");
const context = @import("context.zig");

const Eval = context.Eval;
const EvalError = context.EvalError;
const Limits = context.Limits;

/// The `ip6.arpa` reverse name for an IPv6 address.
///
/// RFC 3596 §2.5: each of the 32 nibbles as a hex digit, least significant first,
/// dot-separated, under `ip6.arpa`.
fn reverseIp6Name(buf: []u8, octets: [16]u8) ?[]const u8 {
    const hex = "0123456789abcdef";
    const suffix = "ip6.arpa";
    if (buf.len < 32 * 2 + suffix.len) return null;

    var len: usize = 0;
    var i: usize = octets.len;
    while (i > 0) {
        i -= 1;
        buf[len] = hex[octets[i] & 0x0F];
        buf[len + 1] = '.';
        buf[len + 2] = hex[octets[i] >> 4];
        buf[len + 3] = '.';
        len += 4;
    }
    @memcpy(buf[len..][0..suffix.len], suffix);
    return buf[0 .. len + suffix.len];
}

/// The validated domain names of the client address.
pub const ValidatedNames = struct {
    names: std.ArrayListUnmanaged([]u8) = .{},
    allocator: Allocator,

    pub fn deinit(self: *ValidatedNames) void {
        for (self.names.items) |name| self.allocator.free(name);
        self.names.deinit(self.allocator);
    }
};

/// Collect RFC 7208 §5.5-validated client names.
///
/// Each PTR candidate requires a forward confirmation in the connection's address
/// family; the mechanism record limit bounds candidates.
pub fn validatedNames(ev: Eval) EvalError!ValidatedNames {
    var out = ValidatedNames{ .allocator = ev.allocator };
    errdefer out.deinit();

    var client4: [4]u8 = undefined;
    var client6: [16]u8 = undefined;
    var ptr_buf: [80]u8 = undefined;
    const ptr_name = if (ev.ctx.is_ipv6) blk: {
        client6 = spf.parseIp6Bytes(ev.ctx.client_ip) catch return out;
        break :blk reverseIp6Name(&ptr_buf, client6) orelse return out;
    } else blk: {
        client4 = spf.parseIp4Bytes(ev.ctx.client_ip) catch return out;
        break :blk std.fmt.bufPrint(&ptr_buf, "{d}.{d}.{d}.{d}.in-addr.arpa", .{
            client4[3], client4[2], client4[1], client4[0],
        }) catch return out;
    };

    var ptr_result = (try ev.state.query(ev.resolver, ptr_name, .PTR)) orelse return out;
    defer ptr_result.deinit();

    const fwd_type: dns.RecordType = if (ev.ctx.is_ipv6) .AAAA else .A;
    var records: usize = 0;

    for (ptr_result.answers) |ans| {
        if (ans.record_type != @intFromEnum(dns.RecordType.PTR)) continue;
        const candidate = ans.data;

        records += 1;
        if (records > Limits.MAX_RECORDS_PER_MECHANISM) break;

        var fwd_result = (try ev.state.querySub(ev.resolver, candidate, fwd_type)) orelse continue;
        defer fwd_result.deinit();

        for (fwd_result.answers) |fwd_ans| {
            if (fwd_ans.record_type != @intFromEnum(fwd_type)) continue;
            const matches = if (ev.ctx.is_ipv6)
                fwd_ans.data.len >= 16 and mem.eql(u8, fwd_ans.data[0..16], &client6)
            else
                fwd_ans.data.len >= 4 and mem.eql(u8, fwd_ans.data[0..4], &client4);
            if (matches) {
                try out.names.append(ev.allocator, try ev.allocator.dupe(u8, candidate));
                break;
            }
        }
    }
    return out;
}

/// The value of the `%{p}` macro.
///
/// RFC 7208 §7.2 builds it from the §5.5 validated names: prefer `domain` itself if
/// it is among them, then a subdomain of `domain`, then any of them. With none, or
/// on a DNS error, the value is the literal string "unknown".
///
/// §7.2 also says of this macro, in parentheses, "do not use". It costs a reverse
/// lookup plus a forward confirmation per candidate, and the candidate list is
/// chosen by whoever controls the reverse zone. It is implemented because a
/// verifier does not get to ignore a macro a record actually uses.
///
/// Caller owns the returned memory.
pub fn validatedDomain(ev: Eval, domain: []const u8) EvalError![]u8 {
    var validated = validatedNames(ev) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        // "If there are no validated domain names or if a DNS error occurs, the
        // string 'unknown' is used" -- so a lookup failure here must not become the
        // verdict for the whole evaluation.
        else => return ev.allocator.dupe(u8, "unknown"),
    };
    defer validated.deinit();

    if (validated.names.items.len == 0) return ev.allocator.dupe(u8, "unknown");

    for (validated.names.items) |name| {
        if (std.ascii.eqlIgnoreCase(name, domain)) return ev.allocator.dupe(u8, name);
    }
    for (validated.names.items) |name| {
        if (isSubdomainOf(name, domain)) return ev.allocator.dupe(u8, name);
    }
    return ev.allocator.dupe(u8, validated.names.items[0]);
}

/// Whether a domain-spec uses the `%{p}` macro, in either case.
///
/// Lives here rather than beside the expansion that calls it, so every fact about
/// `%{p}` — how to detect it, how to compute it, and what it costs — is in one
/// file. The caller uses this to avoid paying for a reverse lookup a record never
/// asked for.
pub fn usesValidatedDomain(template: []const u8) bool {
    var i: usize = 0;
    while (mem.indexOfScalarPos(u8, template, i, '%')) |at| {
        if (at + 2 < template.len and template[at + 1] == '{' and
            std.ascii.toLower(template[at + 2]) == 'p')
        {
            return true;
        }
        i = at + 1;
    }
    return false;
}

/// Check if name is a subdomain of (or equal to) domain.
pub fn isSubdomainOf(name: []const u8, domain: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(name, domain)) return true;
    if (name.len <= domain.len + 1) return false;
    const suffix_start = name.len - domain.len;
    if (name[suffix_start - 1] != '.') return false;
    return std.ascii.eqlIgnoreCase(name[suffix_start..], domain);
}

// =============================================================================
// Tests
// =============================================================================

test "isSubdomainOf" {
    try std.testing.expect(isSubdomainOf("mail.example.com", "example.com"));
    try std.testing.expect(isSubdomainOf("example.com", "example.com"));
    try std.testing.expect(!isSubdomainOf("notexample.com", "example.com"));
    try std.testing.expect(!isSubdomainOf("evilexample.com", "example.com"));
}

test "reverseIp6Name builds the RFC 3596 nibble name, least significant first" {
    // 2001:db8::1. This had no direct test before the split, and it is the wrong
    // function to leave untested: every way of getting it wrong -- nibble order,
    // high/low order within an octet, a missing separator -- produces a name that
    // is still syntactically a domain and simply resolves to nothing. That
    // reaches `validatedNames` as "no validated names", which is exactly what a
    // client with no PTR record looks like, so `ptr` would answer "did not match"
    // and `%{p}` would expand to "unknown" with nothing logged. Asserted against
    // a literal rather than a round-trip for the same reason: a round-trip
    // through our own builder would agree with itself.
    var buf: [80]u8 = undefined;
    const octets = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 };
    try std.testing.expectEqualStrings(
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
        reverseIp6Name(&buf, octets).?,
    );
}

test "reverseIp6Name refuses a buffer that cannot hold the whole name" {
    // 71 is one short of the 32 nibbles, 32 separators and "ip6.arpa" the name
    // always needs. Returning null rather than writing what fits is the point: a
    // truncated nibble name is a valid name for a *different* address.
    var small: [71]u8 = undefined;
    try std.testing.expect(reverseIp6Name(&small, [_]u8{0} ** 16) == null);
}
