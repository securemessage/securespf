const std = @import("std");
const mem = std.mem;
const fmt = std.fmt;
const Allocator = mem.Allocator;

/// Context needed for SPF macro expansion (RFC 7208 §7).
pub const Context = struct {
    /// MAIL FROM sender (e.g., "user@example.com").
    sender: []const u8,
    /// Domain being evaluated (current SPF domain for include/redirect).
    domain: []const u8,
    /// Client IPv4 or IPv6 address string (dotted-quad or colon-hex).
    client_ip: []const u8,
    /// Whether client is IPv6.
    is_ipv6: bool = false,
    /// Validated domain name of client IP (PTR result), or "unknown".
    validated_domain: []const u8 = "unknown",
    /// HELO/EHLO name.
    helo_domain: []const u8 = "unknown",
    /// Receiving mail server hostname.
    receiver_host: []const u8 = "unknown",
};

/// Expand an SPF macro-string per RFC 7208 §7.
///
/// Handles `%%`, `%_`, `%-`, and `%{<letter><transformers>}`.
/// Caller owns returned slice.
pub fn expand(allocator: Allocator, template: []const u8, ctx: *const Context) ![]u8 {
    var result: std.ArrayListUnmanaged(u8) = .{};
    errdefer result.deinit(allocator);

    var i: usize = 0;
    while (i < template.len) {
        if (template[i] != '%') {
            try result.append(allocator, template[i]);
            i += 1;
            continue;
        }

        i += 1;
        if (i >= template.len) return error.InvalidMacro;

        switch (template[i]) {
            '%' => {
                try result.append(allocator, '%');
                i += 1;
            },
            '_' => {
                try result.append(allocator, ' ');
                i += 1;
            },
            '-' => {
                try result.appendSlice(allocator, "%20");
                i += 1;
            },
            '{' => {
                i += 1;
                const close = mem.indexOfScalarPos(u8, template, i, '}') orelse
                    return error.InvalidMacro;
                const spec = template[i..close];
                i = close + 1;

                const expanded = try expandSpec(allocator, spec, ctx);
                defer allocator.free(expanded);
                try result.appendSlice(allocator, expanded);
            },
            else => return error.InvalidMacro,
        }
    }

    return result.toOwnedSlice(allocator);
}

/// Expand a single macro specifier (contents between `{` and `}`).
/// Format: <letter>[<digits>][r][<delimiters>]
fn expandSpec(allocator: Allocator, spec: []const u8, ctx: *const Context) ![]u8 {
    if (spec.len == 0) return error.InvalidMacro;

    const letter = std.ascii.toLower(spec[0]);
    const uppercase = std.ascii.isUpper(spec[0]);
    _ = uppercase; // URL-encoding for uppercase is a SHOULD, skip for now

    // Parse optional digit count + reverse flag + delimiter chars
    var pos: usize = 1;
    var truncate: ?usize = null;
    var reverse = false;
    var delimiter: u8 = '.';

    // Parse digits
    const digit_start = pos;
    while (pos < spec.len and std.ascii.isDigit(spec[pos])) : (pos += 1) {}
    if (pos > digit_start) {
        truncate = fmt.parseInt(usize, spec[digit_start..pos], 10) catch return error.InvalidMacro;
        if (truncate.? == 0) return error.InvalidMacro; // RFC 7208 §7.1: MUST be nonzero
    }

    // Parse reverse flag
    if (pos < spec.len and (spec[pos] == 'r' or spec[pos] == 'R')) {
        reverse = true;
        pos += 1;
    }

    // Parse delimiter(s) — RFC 7208 §7.1: "." / "-" / "+" / "," / "/" / "_" / "="
    if (pos < spec.len) {
        delimiter = spec[pos];
        if (!isDelimiter(delimiter)) return error.InvalidMacro;
        // Only first delimiter character is used per the RFC split semantics
    }

    // Get the raw value for this macro letter
    const raw = try getMacroValue(allocator, letter, ctx);
    defer allocator.free(raw);

    // Apply transformers: split by delimiter, reverse, truncate, rejoin with '.'
    return applyTransformers(allocator, raw, delimiter, reverse, truncate);
}

fn isDelimiter(ch: u8) bool {
    return switch (ch) {
        '.', '-', '+', ',', '/', '_', '=' => true,
        else => false,
    };
}

/// Get the raw (untransformed) value for a macro letter.
fn getMacroValue(allocator: Allocator, letter: u8, ctx: *const Context) ![]u8 {
    return switch (letter) {
        's' => allocator.dupe(u8, ctx.sender),
        'l' => blk: {
            if (mem.lastIndexOfScalar(u8, ctx.sender, '@')) |at| {
                break :blk allocator.dupe(u8, ctx.sender[0..at]);
            }
            break :blk allocator.dupe(u8, "postmaster");
        },
        'o' => blk: {
            if (mem.lastIndexOfScalar(u8, ctx.sender, '@')) |at| {
                break :blk allocator.dupe(u8, ctx.sender[at + 1 ..]);
            }
            break :blk allocator.dupe(u8, ctx.sender);
        },
        'd' => allocator.dupe(u8, ctx.domain),
        'i' => expandClientIp(allocator, ctx),
        'p' => allocator.dupe(u8, ctx.validated_domain),
        'h' => allocator.dupe(u8, ctx.helo_domain),
        'c' => allocator.dupe(u8, ctx.client_ip),
        'r' => allocator.dupe(u8, ctx.receiver_host),
        't' => blk: {
            var buf: [20]u8 = undefined;
            const ts = std.time.timestamp();
            const slice = fmt.bufPrint(&buf, "{d}", .{ts}) catch unreachable;
            break :blk allocator.dupe(u8, slice);
        },
        'v' => blk: {
            break :blk allocator.dupe(u8, if (ctx.is_ipv6) "ip6" else "in-addr");
        },
        else => error.InvalidMacro,
    };
}

/// Expand %{i}: IPv4 as dotted-quad, IPv6 as dot-separated nibbles.
fn expandClientIp(allocator: Allocator, ctx: *const Context) ![]u8 {
    if (!ctx.is_ipv6) {
        return allocator.dupe(u8, ctx.client_ip);
    }

    // RFC 7208 §7.3: IPv6 → expand to 32 dot-separated nibble characters
    // Parse the colon-hex address into 16 bytes, then emit each nibble
    const parsed = std.net.Ip6Address.parse(ctx.client_ip, 0) catch
        return allocator.dupe(u8, ctx.client_ip);
    const bytes = parsed.sa.addr;

    var buf: [63]u8 = undefined; // 32 nibbles + 31 dots
    var pos: usize = 0;
    for (bytes, 0..) |byte, idx| {
        const hi: u4 = @intCast(byte >> 4);
        const lo: u4 = @intCast(byte & 0x0F);
        buf[pos] = fmt.digitToChar(hi, .lower);
        pos += 1;
        buf[pos] = '.';
        pos += 1;
        buf[pos] = fmt.digitToChar(lo, .lower);
        pos += 1;
        if (idx < 15) {
            buf[pos] = '.';
            pos += 1;
        }
    }

    return allocator.dupe(u8, buf[0..pos]);
}

/// Apply split/reverse/truncate/rejoin transformers to a macro value.
fn applyTransformers(
    allocator: Allocator,
    value: []const u8,
    delimiter: u8,
    reverse: bool,
    truncate: ?usize,
) ![]u8 {
    // Split by delimiter
    var parts: std.ArrayListUnmanaged([]const u8) = .{};
    defer parts.deinit(allocator);

    var iter = mem.splitScalar(u8, value, delimiter);
    while (iter.next()) |part| {
        try parts.append(allocator, part);
    }

    // Reverse
    if (reverse) {
        mem.reverse([]const u8, parts.items);
    }

    // Truncate (keep rightmost N parts)
    var items = parts.items;
    if (truncate) |n| {
        if (n < items.len) {
            items = items[items.len - n ..];
        }
    }

    // Rejoin with '.'
    var result: std.ArrayListUnmanaged(u8) = .{};
    errdefer result.deinit(allocator);

    for (items, 0..) |part, idx| {
        try result.appendSlice(allocator, part);
        if (idx < items.len - 1) {
            try result.append(allocator, '.');
        }
    }

    return result.toOwnedSlice(allocator);
}

// =============================================================================
// Tests
// =============================================================================

test "expand simple sender macro" {
    const ctx = Context{
        .sender = "strong-bad@email.example.com",
        .domain = "email.example.com",
        .client_ip = "192.0.2.3",
    };

    const result = try expand(std.testing.allocator, "%{s}", &ctx);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("strong-bad@email.example.com", result);
}

test "expand local-part and domain" {
    const ctx = Context{
        .sender = "strong-bad@email.example.com",
        .domain = "email.example.com",
        .client_ip = "192.0.2.3",
    };

    const l = try expand(std.testing.allocator, "%{l}", &ctx);
    defer std.testing.allocator.free(l);
    try std.testing.expectEqualStrings("strong-bad", l);

    const o = try expand(std.testing.allocator, "%{o}", &ctx);
    defer std.testing.allocator.free(o);
    try std.testing.expectEqualStrings("email.example.com", o);

    const d = try expand(std.testing.allocator, "%{d}", &ctx);
    defer std.testing.allocator.free(d);
    try std.testing.expectEqualStrings("email.example.com", d);
}

test "expand with reverse and truncation" {
    const ctx = Context{
        .sender = "strong-bad@email.example.com",
        .domain = "email.example.com",
        .client_ip = "192.0.2.3",
    };

    // %{d1} — rightmost 1 label of domain
    const d1 = try expand(std.testing.allocator, "%{d1}", &ctx);
    defer std.testing.allocator.free(d1);
    try std.testing.expectEqualStrings("com", d1);

    // %{d2} — rightmost 2 labels
    const d2 = try expand(std.testing.allocator, "%{d2}", &ctx);
    defer std.testing.allocator.free(d2);
    try std.testing.expectEqualStrings("example.com", d2);

    // %{dr} — reverse domain labels
    const dr = try expand(std.testing.allocator, "%{dr}", &ctx);
    defer std.testing.allocator.free(dr);
    try std.testing.expectEqualStrings("com.example.email", dr);
}

test "expand ipv4 client ip" {
    const ctx = Context{
        .sender = "user@example.com",
        .domain = "example.com",
        .client_ip = "192.0.2.3",
    };

    const i_val = try expand(std.testing.allocator, "%{i}", &ctx);
    defer std.testing.allocator.free(i_val);
    try std.testing.expectEqualStrings("192.0.2.3", i_val);

    // %{ir} — reverse IP octets
    const ir = try expand(std.testing.allocator, "%{ir}", &ctx);
    defer std.testing.allocator.free(ir);
    try std.testing.expectEqualStrings("3.2.0.192", ir);
}

test "expand ipv6 client ip as nibbles" {
    const ctx = Context{
        .sender = "user@example.com",
        .domain = "example.com",
        .client_ip = "2001:db8::cb01",
        .is_ipv6 = true,
    };

    const i_val = try expand(std.testing.allocator, "%{i}", &ctx);
    defer std.testing.allocator.free(i_val);
    // 2001:0db8:0000:0000:0000:0000:0000:cb01 →
    // 2.0.0.1.0.d.b.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.c.b.0.1
    try std.testing.expectEqualStrings(
        "2.0.0.1.0.d.b.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.c.b.0.1",
        i_val,
    );
}

test "expand version macro" {
    const ctx4 = Context{
        .sender = "user@example.com",
        .domain = "example.com",
        .client_ip = "192.0.2.1",
        .is_ipv6 = false,
    };

    const v4 = try expand(std.testing.allocator, "%{v}", &ctx4);
    defer std.testing.allocator.free(v4);
    try std.testing.expectEqualStrings("in-addr", v4);

    const ctx6 = Context{
        .sender = "user@example.com",
        .domain = "example.com",
        .client_ip = "2001:db8::1",
        .is_ipv6 = true,
    };

    const v6 = try expand(std.testing.allocator, "%{v}", &ctx6);
    defer std.testing.allocator.free(v6);
    try std.testing.expectEqualStrings("ip6", v6);
}

test "expand literal percent and whitespace escapes" {
    const ctx = Context{
        .sender = "user@example.com",
        .domain = "example.com",
        .client_ip = "192.0.2.1",
    };

    const pct = try expand(std.testing.allocator, "%%", &ctx);
    defer std.testing.allocator.free(pct);
    try std.testing.expectEqualStrings("%", pct);

    const sp = try expand(std.testing.allocator, "%_", &ctx);
    defer std.testing.allocator.free(sp);
    try std.testing.expectEqualStrings(" ", sp);

    const enc = try expand(std.testing.allocator, "%-", &ctx);
    defer std.testing.allocator.free(enc);
    try std.testing.expectEqualStrings("%20", enc);
}

test "expand with custom delimiter" {
    const ctx = Context{
        .sender = "strong-bad@email.example.com",
        .domain = "email.example.com",
        .client_ip = "192.0.2.3",
    };

    // %{l-} — split local-part by '-'
    const l_dash = try expand(std.testing.allocator, "%{l-}", &ctx);
    defer std.testing.allocator.free(l_dash);
    try std.testing.expectEqualStrings("strong.bad", l_dash);

    // %{lr-} — split local-part by '-', reversed
    const lr_dash = try expand(std.testing.allocator, "%{lr-}", &ctx);
    defer std.testing.allocator.free(lr_dash);
    try std.testing.expectEqualStrings("bad.strong", lr_dash);
}

test "expand sender with no at-sign defaults local to postmaster" {
    const ctx = Context{
        .sender = "postmaster",
        .domain = "example.com",
        .client_ip = "192.0.2.1",
    };

    const l = try expand(std.testing.allocator, "%{l}", &ctx);
    defer std.testing.allocator.free(l);
    try std.testing.expectEqualStrings("postmaster", l);

    // %{o} with no @ returns the whole sender
    const o = try expand(std.testing.allocator, "%{o}", &ctx);
    defer std.testing.allocator.free(o);
    try std.testing.expectEqualStrings("postmaster", o);
}

test "expand mixed template" {
    const ctx = Context{
        .sender = "user@example.com",
        .domain = "example.com",
        .client_ip = "10.1.2.3",
    };

    const r = try expand(std.testing.allocator, "%{ir}.%{v}._spf.%{d}", &ctx);
    defer std.testing.allocator.free(r);
    try std.testing.expectEqualStrings("3.2.1.10.in-addr._spf.example.com", r);
}

test "invalid macro specs" {
    const ctx = Context{
        .sender = "user@example.com",
        .domain = "example.com",
        .client_ip = "192.0.2.1",
    };

    // Unknown letter
    try std.testing.expectError(
        error.InvalidMacro,
        expand(std.testing.allocator, "%{z}", &ctx),
    );

    // Unterminated
    try std.testing.expectError(
        error.InvalidMacro,
        expand(std.testing.allocator, "%{d", &ctx),
    );

    // Zero truncation (RFC forbids)
    try std.testing.expectError(
        error.InvalidMacro,
        expand(std.testing.allocator, "%{d0}", &ctx),
    );
}
