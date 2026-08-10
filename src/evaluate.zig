//! Recursive RFC 7208 §4 `check_host()` evaluation.
//!
//! Fetches SPF records, evaluates directives, follows redirects, and maps
//! evaluation errors to SPF results.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");
const dns = securemilter.dns;

const spf = @import("spf.zig");
const context = @import("context.zig");
const mechanisms = @import("mechanisms.zig");

/// The public surface, unchanged by the split into four files. `main.zig` and
/// `check.zig` reach SPF evaluation through `evaluate.*` and should not have to
/// know which file a type came to live in.
pub const EvalContext = context.EvalContext;
pub const EvalResult = context.EvalResult;
pub const Limits = context.Limits;

const Arrival = context.Arrival;
const Eval = context.Eval;
const EvalError = context.EvalError;
const EvalState = context.EvalState;
const errorToReason = context.errorToReason;
const errorToResult = context.errorToResult;
const noRecord = context.noRecord;

/// Evaluate SPF for the given context.
///
/// 1. Extract domain from sender (or use HELO domain for null sender)
/// 2. DNS lookup TXT records for the domain
/// 3. Parse SPF record
/// 4. Walk directives, resolving DNS for a/mx/include/exists/ptr
/// 5. Enforce the RFC 7208 §4.6.4 processing limits
/// 6. Handle redirect modifier
pub fn evaluate(
    allocator: Allocator,
    resolver: *dns.Resolver,
    ctx: *const EvalContext,
) EvalResult {
    return evaluateWithLimits(allocator, resolver, ctx, .{});
}

/// Room for the longest dotted-quad, "255.255.255.255".
const ip4_text_max = 15;

/// The embedded IPv4 address of an IPv4-mapped IPv6 address, in dotted-quad form.
///
/// Returns `null` for anything else, including the IPv4-*translated* prefix
/// `::ffff:0:0:0/96` of RFC 2765, which looks similar and is a different thing.
fn mappedIp4(ip: []const u8, buf: []u8) ?[]const u8 {
    // Only an address written in IPv6 form can be mapped.
    if (mem.indexOfScalar(u8, ip, ':') == null) return null;
    const octets = spf.parseIp6Bytes(ip) catch return null;

    // RFC 4291 §2.5.5.2: 80 zero bits, then 16 one bits, then the address.
    if (!mem.allEqual(u8, octets[0..10], 0)) return null;
    if (octets[10] != 0xFF or octets[11] != 0xFF) return null;

    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{
        octets[12], octets[13], octets[14], octets[15],
    }) catch null;
}

pub fn evaluateWithLimits(
    allocator: Allocator,
    resolver: *dns.Resolver,
    raw_ctx: *const EvalContext,
    limits: Limits,
) EvalResult {
    // RFC 7208 §5 requires IPv4-mapped IPv6 clients to be evaluated as IPv4.
    // Normalize once so all mechanisms and macros use the same address.
    var mapped_buf: [ip4_text_max]u8 = undefined;
    var normalized = raw_ctx.*;
    if (raw_ctx.is_ipv6) {
        if (mappedIp4(raw_ctx.client_ip, &mapped_buf)) |dotted| {
            normalized.client_ip = dotted;
            normalized.is_ipv6 = false;
        }
    }
    // The parameter is the one with the awkward name so that `ctx` -- the name
    // every line below reaches for by reflex -- is the corrected context. Zig
    // cannot shadow a parameter, and an earlier draft of this function did leave
    // one call site reading the un-normalized address, which silently undid the
    // whole fix.
    const ctx = &normalized;

    // Determine check domain: from MAIL FROM or fall back to HELO
    const domain = extractCheckDomain(ctx);
    if (domain.len == 0) {
        return .{ .result = .none, .domain = "", .explanation = null };
    }

    var state = EvalState.init(limits);

    // The one place the four invariants exist as separate values. Everything below
    // takes them as a unit, so `ctx` here is guaranteed to be the *normalized* one --
    // the mistake the comment above describes cannot be made once per call site,
    // because there is only one site.
    const ev = Eval{
        .allocator = allocator,
        .resolver = resolver,
        .ctx = ctx,
        .state = &state,
    };

    const result = evaluateDomain(ev, domain, .checked_domain) catch |err| {
        // The top level is the only place an evaluation error becomes a result,
        // which keeps the mapping in one auditable spot.
        return .{
            .result = errorToResult(err),
            .domain = domain,
            .explanation = null,
            .reason = errorToReason(err),
        };
    };
    return .{ .result = result, .domain = domain, .explanation = null };
}

/// Recursive SPF evaluation for a specific domain.
fn evaluateDomain(ev: Eval, domain: []const u8, arrival: Arrival) EvalError!spf.Result {
    if (ev.state.expired()) return error.Timeout;

    // Fetch SPF record via DNS TXT lookup. The query for the checked domain is
    // not a "term" under §4.6.4 -- only the mechanisms are -- so it is
    // deliberately not charged against the term budget, though it is still
    // subject to the deadline and still counts as a void lookup if it finds
    // nothing, because an `include` chain is exactly how that query gets
    // amplified.
    const maybe = try ev.state.query(ev.resolver, domain, .TXT);
    if (maybe == null) return noRecord(arrival);
    var dns_result = maybe.?;
    defer dns_result.deinit();

    // Find the SPF record among TXT results
    var txt_iter = dns_result.txtRecords();
    var spf_txt: ?[]const u8 = null;
    while (txt_iter.next()) |txt| {
        if (spf.isSpf1(txt)) {
            // RFC 7208 §4.5: more than one v=spf1 record is a permerror.
            if (spf_txt != null) return error.RecordSyntax;
            spf_txt = txt;
        }
    }

    const record_txt = spf_txt orelse return noRecord(arrival);

    // Parse the SPF record
    var record = spf.parseRecord(ev.allocator, record_txt) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.RecordSyntax,
    };
    defer record.deinit(ev.allocator);

    // Walk directives
    for (record.directives.items) |directive| {
        if (try matchDirective(ev, domain, directive)) {
            return directive.qualifier.toResult();
        }
    }

    // If no directive matched, check redirect modifier
    if (record.redirect) |redirect_template| {
        try ev.state.chargeTerm();
        const target = try mechanisms.expandDomainSpec(ev, domain, redirect_template);
        defer ev.allocator.free(target);
        // RFC 7208 §6.1: no record at the redirect target is a permerror, not a
        // `none` that would let the message through unjudged.
        return evaluateDomain(ev, target, .directed);
    }

    // Default result when no directives match and no redirect: neutral
    return .neutral;
}

/// Check if a single directive matches the client.
///
/// Every prong but `.include` is a test on the connection and lives in
/// `mechanisms.zig`. `.include` is a recursive `check_host()` (§5.2), so it is
/// below — moving it out would make the mechanisms file import this one.
fn matchDirective(ev: Eval, domain: []const u8, directive: spf.Directive) EvalError!bool {
    return switch (directive.mechanism) {
        .all => true,
        .ip4 => mechanisms.matchIp4(ev.ctx, directive),
        .ip6 => mechanisms.matchIp6(ev.ctx, directive),
        .a => mechanisms.matchA(ev, domain, directive),
        .mx => mechanisms.matchMx(ev, domain, directive),
        .include => matchInclude(ev, domain, directive),
        .exists => mechanisms.matchExists(ev, domain, directive),
        .ptr => mechanisms.matchPtr(ev, domain, directive),
    };
}

/// RFC 7208 §5.2 `include`.
///
/// The result table is not "pass or bust": a `temperror` inside the included
/// record has to surface as a `temperror` for the whole check, and a target with
/// no usable record is a permerror. Collapsing all of that to `result == .pass`
/// meant an outage at an included provider read as "did not match", so the
/// evaluation walked on to the sender's own `-all` and rejected the mail.
fn matchInclude(ev: Eval, domain: []const u8, directive: spf.Directive) EvalError!bool {
    const template = directive.argument orelse return false;
    try ev.state.chargeTerm();

    // Expanded against the domain whose record holds the include, not against the
    // included one, so `%{d}` means what the author wrote it next to.
    const target = try mechanisms.expandDomainSpec(ev, domain, template);
    defer ev.allocator.free(target);

    const result = try evaluateDomain(ev, target, .directed);
    return switch (result) {
        .pass => true,
        .fail, .softfail, .neutral => false,
        // evaluateDomain reports these as errors, so they cannot arrive here;
        // handled explicitly so adding a Result variant is a compile error
        // rather than a silent "did not match".
        .temperror => error.DnsTransient,
        .permerror => error.RecordSyntax,
        .none => error.NoRecordAtTarget,
    };
}

/// Extract the domain to check from the evaluation context.
fn extractCheckDomain(ctx: *const EvalContext) []const u8 {
    // If MAIL FROM is "<>" (null reverse-path), use HELO domain
    if (ctx.sender.len == 0 or mem.eql(u8, ctx.sender, "<>")) {
        return ctx.helo_domain;
    }
    // Extract domain from MAIL FROM
    if (mem.lastIndexOfScalar(u8, ctx.sender, '@')) |at| {
        return ctx.sender[at + 1 ..];
    }
    return ctx.helo_domain;
}

// =============================================================================
// Tests
// =============================================================================

test {
    // `main.zig` reaches this daemon's SPF tests through `_ = evaluate`, so the
    // files this one was split into are only covered if it names them. A plain
    // `const` reference is not enough -- the test runner collects from test
    // blocks.
    _ = context;
    _ = mechanisms;
    _ = @import("ptr.zig");
}

test "extractCheckDomain from sender" {
    const ctx = EvalContext{
        .client_ip = "192.0.2.1",
        .is_ipv6 = false,
        .sender = "user@example.com",
        .helo_domain = "mail.example.com",
        .receiver_host = "mx.local",
    };
    try std.testing.expectEqualStrings("example.com", extractCheckDomain(&ctx));
}

test "extractCheckDomain null sender uses helo" {
    const ctx = EvalContext{
        .client_ip = "192.0.2.1",
        .is_ipv6 = false,
        .sender = "<>",
        .helo_domain = "mail.example.com",
        .receiver_host = "mx.local",
    };
    try std.testing.expectEqualStrings("mail.example.com", extractCheckDomain(&ctx));
}

test "an early exit reports both a result and the reason for it" {
    // The reason travels on EvalResult rather than only reaching the log, so the
    // A-R header and the ZMQ event can use it later without re-deriving it.
    const ctx = EvalContext{
        .client_ip = "192.0.2.1",
        .is_ipv6 = false,
        // An empty sender with an empty HELO yields no domain to check, which is
        // the one path that returns before any evaluation happens: `none` with
        // nothing to explain.
        .sender = "",
        .helo_domain = "",
        .receiver_host = "mx.local",
    };
    const out = evaluateWithLimits(std.testing.allocator, undefined, &ctx, .{});
    try std.testing.expectEqual(spf.Result.none, out.result);
    try std.testing.expect(out.reason == null);
}
