const std = @import("std");
const mem = std.mem;
const net = std.net;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");
const dns = securemilter.dns;

const spf = @import("spf.zig");
const macro = @import("macro.zig");

/// SPF evaluation context for a single message.
pub const EvalContext = struct {
    /// Client IP address string.
    client_ip: []const u8,
    /// Whether client is IPv6.
    is_ipv6: bool,
    /// MAIL FROM sender address.
    sender: []const u8,
    /// HELO/EHLO domain.
    helo_domain: []const u8,
    /// Receiving hostname (for %{r} macro).
    receiver_host: []const u8,
};

/// SPF evaluation result with explanation.
pub const EvalResult = struct {
    result: spf.Result,
    domain: []const u8,
    explanation: ?[]const u8,
};

/// Maximum DNS lookups per SPF check (RFC 7208 §4.6.4).
const MAX_DNS_LOOKUPS: usize = 10;

/// Evaluate SPF for the given context.
///
/// 1. Extract domain from sender (or use HELO domain for null sender)
/// 2. DNS lookup TXT records for the domain
/// 3. Parse SPF record
/// 4. Walk directives, resolving DNS for a/mx/include/exists/ptr
/// 5. Enforce 10-lookup limit (permerror on exceed)
/// 6. Handle redirect modifier
pub fn evaluate(
    allocator: Allocator,
    resolver: *dns.Resolver,
    ctx: *const EvalContext,
) EvalResult {
    // Determine check domain: from MAIL FROM or fall back to HELO
    const domain = extractCheckDomain(ctx);
    if (domain.len == 0) {
        return .{ .result = .none, .domain = "", .explanation = null };
    }

    var lookup_count: usize = 0;
    const result = evaluateDomain(allocator, resolver, ctx, domain, &lookup_count);
    return .{ .result = result, .domain = domain, .explanation = null };
}

/// Recursive SPF evaluation for a specific domain.
fn evaluateDomain(
    allocator: Allocator,
    resolver: *dns.Resolver,
    ctx: *const EvalContext,
    domain: []const u8,
    lookup_count: *usize,
) spf.Result {
    // Fetch SPF record via DNS TXT lookup
    var dns_result = resolver.resolve(domain, .TXT) catch return .temperror;
    defer dns_result.deinit();

    // Find the SPF record among TXT results
    var txt_iter = dns_result.txtRecords();
    var spf_txt: ?[]const u8 = null;
    while (txt_iter.next()) |txt| {
        if (spf.isSpf1(txt)) {
            if (spf_txt != null) return .permerror; // Multiple SPF records = permerror
            spf_txt = txt;
        }
    }

    const record_txt = spf_txt orelse return .none; // No SPF record found

    // Parse the SPF record
    var record = spf.parseRecord(allocator, record_txt) catch return .permerror;
    defer record.deinit(allocator);

    // Walk directives
    for (record.directives.items) |directive| {
        const matched = matchDirective(allocator, resolver, ctx, domain, directive, lookup_count) catch
            return .temperror;

        if (matched) {
            return directive.qualifier.toResult();
        }

        // Check lookup limit after each DNS-causing mechanism
        if (lookup_count.* > MAX_DNS_LOOKUPS) return .permerror;
    }

    // If no directive matched, check redirect modifier
    if (record.redirect) |redirect_domain| {
        lookup_count.* += 1;
        if (lookup_count.* > MAX_DNS_LOOKUPS) return .permerror;
        return evaluateDomain(allocator, resolver, ctx, redirect_domain, lookup_count);
    }

    // Default result when no directives match and no redirect: neutral
    return .neutral;
}

/// Check if a single directive matches the client.
fn matchDirective(
    allocator: Allocator,
    resolver: *dns.Resolver,
    ctx: *const EvalContext,
    domain: []const u8,
    directive: spf.Directive,
    lookup_count: *usize,
) !bool {
    return switch (directive.mechanism) {
        .all => true,
        .ip4 => matchIp4(ctx, directive),
        .ip6 => matchIp6(ctx, directive),
        .a => matchA(allocator, resolver, ctx, domain, directive, lookup_count),
        .mx => matchMx(allocator, resolver, ctx, domain, directive, lookup_count),
        .include => matchInclude(allocator, resolver, ctx, directive, lookup_count),
        .exists => matchExists(allocator, resolver, directive, domain, ctx, lookup_count),
        .ptr => matchPtr(allocator, resolver, ctx, domain, directive, lookup_count),
    };
}

fn matchIp4(ctx: *const EvalContext, directive: spf.Directive) bool {
    if (ctx.is_ipv6) return false;
    const arg = directive.argument orelse return false;
    const parsed = spf.parseIp4Arg(arg) catch return false;
    const client_bytes = spf.parseIp4Bytes(ctx.client_ip) catch return false;
    const prefix = directive.cidr4 orelse parsed.prefix;
    return spf.matchIp4Cidr(client_bytes, parsed.addr, prefix);
}

fn matchIp6(ctx: *const EvalContext, directive: spf.Directive) bool {
    if (!ctx.is_ipv6) return false;
    const arg = directive.argument orelse return false;
    const prefix_len = directive.cidr6 orelse 128;
    // Parse both addresses and compare with prefix
    const client = net.Ip6Address.parse(ctx.client_ip, 0) catch return false;
    const network = net.Ip6Address.parse(arg, 0) catch return false;
    return matchIp6Cidr(client.sa.addr, network.sa.addr, prefix_len);
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

fn matchA(
    allocator: Allocator,
    resolver: *dns.Resolver,
    ctx: *const EvalContext,
    domain: []const u8,
    directive: spf.Directive,
    lookup_count: *usize,
) !bool {
    lookup_count.* += 1;
    const target = directive.argument orelse domain;
    const prefix4 = directive.cidr4 orelse 32;
    const prefix6 = directive.cidr6 orelse 128;

    if (!ctx.is_ipv6) {
        var result = resolver.resolve(target, .A) catch return false;
        defer result.deinit();
        const client_bytes = spf.parseIp4Bytes(ctx.client_ip) catch return false;
        for (result.answers) |ans| {
            if (ans.record_type == @intFromEnum(dns.RecordType.A) and ans.data.len >= 4) {
                if (spf.matchIp4Cidr(client_bytes, ans.data[0..4].*, prefix4)) return true;
            }
        }
    } else {
        var result = resolver.resolve(target, .AAAA) catch return false;
        defer result.deinit();
        const client = net.Ip6Address.parse(ctx.client_ip, 0) catch return false;
        for (result.answers) |ans| {
            if (ans.record_type == @intFromEnum(dns.RecordType.AAAA) and ans.data.len >= 16) {
                if (matchIp6Cidr(client.sa.addr, ans.data[0..16].*, prefix6)) return true;
            }
        }
    }
    _ = allocator;
    return false;
}

fn matchMx(
    allocator: Allocator,
    resolver: *dns.Resolver,
    ctx: *const EvalContext,
    domain: []const u8,
    directive: spf.Directive,
    lookup_count: *usize,
) !bool {
    lookup_count.* += 1;
    const target = directive.argument orelse domain;
    const prefix4 = directive.cidr4 orelse 32;
    const prefix6 = directive.cidr6 orelse 128;

    var mx_result = resolver.resolve(target, .MX) catch return false;
    defer mx_result.deinit();

    for (mx_result.answers) |ans| {
        if (ans.record_type != @intFromEnum(dns.RecordType.MX)) continue;
        // MX data contains the exchange hostname
        const mx_host = ans.data;
        if (mx_host.len == 0) continue;

        lookup_count.* += 1;
        if (lookup_count.* > MAX_DNS_LOOKUPS) return error.LookupLimitExceeded;

        if (!ctx.is_ipv6) {
            var a_result = resolver.resolve(mx_host, .A) catch continue;
            defer a_result.deinit();
            const client_bytes = spf.parseIp4Bytes(ctx.client_ip) catch return false;
            for (a_result.answers) |a_ans| {
                if (a_ans.record_type == @intFromEnum(dns.RecordType.A) and a_ans.data.len >= 4) {
                    if (spf.matchIp4Cidr(client_bytes, a_ans.data[0..4].*, prefix4)) return true;
                }
            }
        } else {
            var aaaa_result = resolver.resolve(mx_host, .AAAA) catch continue;
            defer aaaa_result.deinit();
            const client = net.Ip6Address.parse(ctx.client_ip, 0) catch return false;
            for (aaaa_result.answers) |a_ans| {
                if (a_ans.record_type == @intFromEnum(dns.RecordType.AAAA) and a_ans.data.len >= 16) {
                    if (matchIp6Cidr(client.sa.addr, a_ans.data[0..16].*, prefix6)) return true;
                }
            }
        }
    }
    _ = allocator;
    return false;
}

fn matchInclude(
    allocator: Allocator,
    resolver: *dns.Resolver,
    ctx: *const EvalContext,
    directive: spf.Directive,
    lookup_count: *usize,
) !bool {
    const target = directive.argument orelse return false;
    lookup_count.* += 1;
    if (lookup_count.* > MAX_DNS_LOOKUPS) return error.LookupLimitExceeded;

    const result = evaluateDomain(allocator, resolver, ctx, target, lookup_count);
    // RFC 7208 §5.2: include matches only on pass
    return result == .pass;
}

fn matchExists(
    allocator: Allocator,
    resolver: *dns.Resolver,
    directive: spf.Directive,
    domain: []const u8,
    ctx: *const EvalContext,
    lookup_count: *usize,
) !bool {
    const target_template = directive.argument orelse return false;
    lookup_count.* += 1;
    if (lookup_count.* > MAX_DNS_LOOKUPS) return error.LookupLimitExceeded;

    // Expand macros in the target domain
    const macro_ctx = macro.Context{
        .sender = ctx.sender,
        .domain = domain,
        .client_ip = ctx.client_ip,
        .is_ipv6 = ctx.is_ipv6,
        .helo_domain = ctx.helo_domain,
        .receiver_host = ctx.receiver_host,
    };

    const expanded = macro.expand(allocator, target_template, &macro_ctx) catch return false;
    defer allocator.free(expanded);

    // exists: check if A record exists (any address = match)
    var result = resolver.resolve(expanded, .A) catch return false;
    defer result.deinit();
    return result.answers.len > 0;
}

fn matchPtr(
    allocator: Allocator,
    resolver: *dns.Resolver,
    ctx: *const EvalContext,
    domain: []const u8,
    directive: spf.Directive,
    lookup_count: *usize,
) !bool {
    // RFC 7208 §5.5: ptr mechanism is NOT RECOMMENDED but MUST be implemented
    lookup_count.* += 1;
    if (lookup_count.* > MAX_DNS_LOOKUPS) return error.LookupLimitExceeded;

    const target_domain = directive.argument orelse domain;
    _ = allocator;

    // Build reverse lookup name
    // For now, only IPv4 PTR is implemented
    if (ctx.is_ipv6) return false;

    const client_bytes = spf.parseIp4Bytes(ctx.client_ip) catch return false;
    var ptr_buf: [64]u8 = undefined;
    const ptr_name = std.fmt.bufPrint(&ptr_buf, "{d}.{d}.{d}.{d}.in-addr.arpa", .{
        client_bytes[3], client_bytes[2], client_bytes[1], client_bytes[0],
    }) catch return false;

    var ptr_result = resolver.resolve(ptr_name, .PTR) catch return false;
    defer ptr_result.deinit();

    // For each PTR name, verify it resolves back to client IP and
    // check if it's a subdomain of the target_domain
    for (ptr_result.answers) |ans| {
        if (ans.record_type != @intFromEnum(dns.RecordType.PTR)) continue;
        const validated_name = ans.data;

        // Confirm forward lookup matches client
        var fwd_result = resolver.resolve(validated_name, .A) catch continue;
        defer fwd_result.deinit();

        var confirmed = false;
        for (fwd_result.answers) |fwd_ans| {
            if (fwd_ans.record_type == @intFromEnum(dns.RecordType.A) and fwd_ans.data.len >= 4) {
                if (mem.eql(u8, fwd_ans.data[0..4], &client_bytes)) {
                    confirmed = true;
                    break;
                }
            }
        }

        if (confirmed and isSubdomainOf(validated_name, target_domain)) {
            return true;
        }
    }
    return false;
}

/// Check if name is a subdomain of (or equal to) domain.
fn isSubdomainOf(name: []const u8, domain: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(name, domain)) return true;
    if (name.len <= domain.len + 1) return false;
    const suffix_start = name.len - domain.len;
    if (name[suffix_start - 1] != '.') return false;
    return std.ascii.eqlIgnoreCase(name[suffix_start..], domain);
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

test "isSubdomainOf" {
    try std.testing.expect(isSubdomainOf("mail.example.com", "example.com"));
    try std.testing.expect(isSubdomainOf("example.com", "example.com"));
    try std.testing.expect(!isSubdomainOf("notexample.com", "example.com"));
    try std.testing.expect(!isSubdomainOf("evilexample.com", "example.com"));
}

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
