//! Validated domain names for the client address — RFC 7208 §5.5 and §7.2.
//!
//! One procedure with two callers that look unrelated: the `ptr` mechanism (§5.5)
//! and the `%{p}` macro (§7.2), which the RFC defines *in terms of* §5.5 rather
//! than describing separately. Keeping them in one file is what stops the two
//! drifting — a validation rule honoured in one place and not the other is the
//! shape of D-1, A-5, D-15 and the macro-less mechanisms fixed alongside them.
//!
//! Depends only on the shared vocabulary in `context.zig`, so it sits at the
//! bottom of the module graph with nothing importing back into it.

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

/// Collect the client address's validated domain names, per RFC 7208 §5.5.
///
/// A PTR name counts only once its forward lookup, in the address family the
/// connection actually used, contains the connecting address. The reverse zone is
/// controlled by whoever holds the address, so the PTR names are candidates and
/// nothing more until confirmed -- skipping the confirmation would let an address
/// owner claim any name.
///
/// §5.5 caps the names examined at 10, which is a budget separate from the term
/// count: without it a reverse zone returning hundreds of names would buy hundreds
/// of forward confirmations off a single mechanism.
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
