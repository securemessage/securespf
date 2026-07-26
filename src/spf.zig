const std = @import("std");
const mem = std.mem;
const net = std.net;
const Allocator = mem.Allocator;

/// SPF evaluation results per RFC 7208 §2.6.
pub const Result = enum {
    none,
    neutral,
    pass,
    fail,
    softfail,
    temperror,
    permerror,
};

/// Qualifier prefix per RFC 7208 §4.6.2.
pub const Qualifier = enum {
    pass, // "+" (default)
    fail, // "-"
    softfail, // "~"
    neutral, // "?"

    pub fn toResult(self: Qualifier) Result {
        return switch (self) {
            .pass => .pass,
            .fail => .fail,
            .softfail => .softfail,
            .neutral => .neutral,
        };
    }
};

/// SPF mechanism types per RFC 7208 §5.
pub const MechanismType = enum {
    all,
    include,
    a,
    mx,
    ptr,
    ip4,
    ip6,
    exists,
};

/// A parsed SPF directive (qualifier + mechanism + argument).
pub const Directive = struct {
    qualifier: Qualifier,
    mechanism: MechanismType,
    argument: ?[]const u8,
    cidr4: ?u8 = null,
    cidr6: ?u8 = null,
};

/// A parsed SPF record.
pub const Record = struct {
    directives: std.ArrayList(Directive),
    redirect: ?[]const u8,
    explanation: ?[]const u8,

    pub fn deinit(self: *Record, allocator: Allocator) void {
        self.directives.deinit(allocator);
    }
};

/// Parse an SPF TXT record string.
///
/// The input must start with "v=spf1" followed by directives/modifiers.
/// Returns permerror for syntax errors per RFC 7208 §4.6.
pub fn parseRecord(allocator: Allocator, txt: []const u8) !Record {
    var record = Record{
        .directives = .{},
        .redirect = null,
        .explanation = null,
    };

    const trimmed = mem.trim(u8, txt, &std.ascii.whitespace);
    if (!isSpf1(trimmed)) return error.NotSpf1;

    const body = if (trimmed.len > 6) trimmed[6..] else "";
    var iter = mem.tokenizeScalar(u8, body, ' ');

    while (iter.next()) |term| {
        if (term.len == 0) continue;

        if (parseModifier(term, "redirect")) |target| {
            record.redirect = target;
            continue;
        }
        if (parseModifier(term, "exp")) |target| {
            record.explanation = target;
            continue;
        }

        // Skip unknown modifiers (name=value where name isn't recognized)
        if (mem.indexOfScalar(u8, term, '=') != null) {
            const eq = mem.indexOfScalar(u8, term, '=').?;
            const name = term[0..eq];
            if (name.len > 0 and isModifierName(name)) continue;
        }

        const directive = try parseDirective(term);
        try record.directives.append(allocator, directive);
    }

    return record;
}

/// Check if a TXT record is a valid SPF v1 record.
pub fn isSpf1(txt: []const u8) bool {
    if (txt.len < 6) return false;
    if (!std.ascii.eqlIgnoreCase(txt[0..6], "v=spf1")) return false;
    if (txt.len == 6) return true;
    return txt[6] == ' ' or txt[6] == '\t';
}

fn parseModifier(term: []const u8, name: []const u8) ?[]const u8 {
    if (term.len <= name.len + 1) return null;
    if (!std.ascii.eqlIgnoreCase(term[0..name.len], name)) return null;
    if (term[name.len] != '=') return null;
    return term[name.len + 1 ..];
}

fn isModifierName(name: []const u8) bool {
    for (name) |ch| {
        if (!std.ascii.isAlphanumeric(ch) and ch != '-' and ch != '_' and ch != '.') return false;
    }
    return true;
}

fn parseDirective(term: []const u8) !Directive {
    var pos: usize = 0;
    var qualifier: Qualifier = .pass;

    if (term.len > 0) {
        switch (term[0]) {
            '+' => {
                qualifier = .pass;
                pos = 1;
            },
            '-' => {
                qualifier = .fail;
                pos = 1;
            },
            '~' => {
                qualifier = .softfail;
                pos = 1;
            },
            '?' => {
                qualifier = .neutral;
                pos = 1;
            },
            else => {},
        }
    }

    const rest = term[pos..];
    const colon = mem.indexOfScalar(u8, rest, ':');
    const slash = mem.indexOfScalar(u8, rest, '/');
    const name_end = @min(colon orelse rest.len, slash orelse rest.len);
    const name = rest[0..name_end];

    const mechanism = parseMechanismName(name) orelse return error.UnknownMechanism;

    var argument: ?[]const u8 = null;
    var cidr4: ?u8 = null;
    var cidr6: ?u8 = null;

    if (colon) |col_pos| {
        const after_colon = rest[col_pos + 1 ..];
        const arg_slash = mem.indexOfScalar(u8, after_colon, '/');
        if (arg_slash) |s| {
            argument = after_colon[0..s];
            parseCidr(after_colon[s + 1 ..], &cidr4, &cidr6);
        } else {
            argument = after_colon;
        }
    } else if (slash) |s| {
        parseCidr(rest[s + 1 ..], &cidr4, &cidr6);
    }

    return .{
        .qualifier = qualifier,
        .mechanism = mechanism,
        .argument = argument,
        .cidr4 = cidr4,
        .cidr6 = cidr6,
    };
}

fn parseMechanismName(name: []const u8) ?MechanismType {
    const lower = blk: {
        if (std.ascii.eqlIgnoreCase(name, "all")) break :blk MechanismType.all;
        if (std.ascii.eqlIgnoreCase(name, "include")) break :blk MechanismType.include;
        if (std.ascii.eqlIgnoreCase(name, "a")) break :blk MechanismType.a;
        if (std.ascii.eqlIgnoreCase(name, "mx")) break :blk MechanismType.mx;
        if (std.ascii.eqlIgnoreCase(name, "ptr")) break :blk MechanismType.ptr;
        if (std.ascii.eqlIgnoreCase(name, "ip4")) break :blk MechanismType.ip4;
        if (std.ascii.eqlIgnoreCase(name, "ip6")) break :blk MechanismType.ip6;
        if (std.ascii.eqlIgnoreCase(name, "exists")) break :blk MechanismType.exists;
        return null;
    };
    return lower;
}

fn parseCidr(spec: []const u8, cidr4: *?u8, cidr6: *?u8) void {
    if (mem.indexOfScalar(u8, spec, '/')) |sep| {
        // dual-cidr: cidr4/cidr6 (e.g., "24//48" or "/48")
        const first = spec[0..sep];
        const second = spec[sep + 1 ..];
        if (first.len > 0) cidr4.* = std.fmt.parseInt(u8, first, 10) catch null;
        if (second.len > 0) cidr6.* = std.fmt.parseInt(u8, second, 10) catch null;
    } else {
        cidr4.* = std.fmt.parseInt(u8, spec, 10) catch null;
    }
}

/// Check if an IPv4 address matches a CIDR range.
pub fn matchIp4Cidr(client_ip: [4]u8, network: [4]u8, prefix_len: u8) bool {
    if (prefix_len > 32) return false;
    if (prefix_len == 0) return true;

    const client: u32 = @as(u32, client_ip[0]) << 24 | @as(u32, client_ip[1]) << 16 |
        @as(u32, client_ip[2]) << 8 | @as(u32, client_ip[3]);
    const network_int: u32 = @as(u32, network[0]) << 24 | @as(u32, network[1]) << 16 |
        @as(u32, network[2]) << 8 | @as(u32, network[3]);

    const shift: u5 = @intCast(32 - prefix_len);
    const cidr_mask: u32 = (@as(u32, 0xFFFFFFFF) >> shift) << shift;
    return (client & cidr_mask) == (network_int & cidr_mask);
}

/// Parse an ip4 mechanism argument: "network/cidr" or "address".
pub fn parseIp4Arg(arg: []const u8) !struct { addr: [4]u8, prefix: u8 } {
    const slash = mem.indexOfScalar(u8, arg, '/');
    const addr_str = if (slash) |s| arg[0..s] else arg;
    const prefix = if (slash) |s|
        std.fmt.parseInt(u8, arg[s + 1 ..], 10) catch return error.InvalidCidr
    else
        32;

    const ip = net.Ip4Address.parse(addr_str, 0) catch return error.InvalidIp;
    const bytes: [4]u8 = @bitCast(ip.sa.addr);

    return .{ .addr = bytes, .prefix = prefix };
}

/// Convert a dot-notation IPv4 string to 4 bytes.
pub fn parseIp4Bytes(ip_str: []const u8) ![4]u8 {
    const ip = net.Ip4Address.parse(ip_str, 0) catch return error.InvalidIp;
    return @bitCast(ip.sa.addr);
}

test "parse simple spf record" {
    var record = try parseRecord(std.testing.allocator, "v=spf1 +mx a:colo.example.com/28 -all");
    defer record.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 3), record.directives.items.len);

    const d0 = record.directives.items[0];
    try std.testing.expectEqual(Qualifier.pass, d0.qualifier);
    try std.testing.expectEqual(MechanismType.mx, d0.mechanism);

    const d1 = record.directives.items[1];
    try std.testing.expectEqual(MechanismType.a, d1.mechanism);
    try std.testing.expectEqualStrings("colo.example.com", d1.argument.?);
    try std.testing.expectEqual(@as(u8, 28), d1.cidr4.?);

    const d2 = record.directives.items[2];
    try std.testing.expectEqual(Qualifier.fail, d2.qualifier);
    try std.testing.expectEqual(MechanismType.all, d2.mechanism);
}

test "parse ip4 mechanism" {
    var record = try parseRecord(std.testing.allocator, "v=spf1 ip4:192.168.1.0/24 -all");
    defer record.deinit(std.testing.allocator);

    const d0 = record.directives.items[0];
    try std.testing.expectEqual(MechanismType.ip4, d0.mechanism);
    try std.testing.expectEqualStrings("192.168.1.0", d0.argument.?);
    try std.testing.expectEqual(@as(u8, 24), d0.cidr4.?);
}

test "parse include mechanism" {
    var record = try parseRecord(std.testing.allocator, "v=spf1 include:spf.example.com ~all");
    defer record.deinit(std.testing.allocator);

    const d0 = record.directives.items[0];
    try std.testing.expectEqual(MechanismType.include, d0.mechanism);
    try std.testing.expectEqualStrings("spf.example.com", d0.argument.?);
}

test "parse redirect modifier" {
    var record = try parseRecord(std.testing.allocator, "v=spf1 redirect=_spf.example.com");
    defer record.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("_spf.example.com", record.redirect.?);
    try std.testing.expectEqual(@as(usize, 0), record.directives.items.len);
}

test "reject non-spf1 record" {
    try std.testing.expectError(error.NotSpf1, parseRecord(std.testing.allocator, "v=spf2 +all"));
    try std.testing.expectError(error.NotSpf1, parseRecord(std.testing.allocator, "v=spf10 +all"));
    try std.testing.expectError(error.NotSpf1, parseRecord(std.testing.allocator, "not an spf record"));
}

test "parse v=spf1 alone (no directives)" {
    var record = try parseRecord(std.testing.allocator, "v=spf1");
    defer record.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), record.directives.items.len);
}

test "default qualifier is pass" {
    var record = try parseRecord(std.testing.allocator, "v=spf1 all");
    defer record.deinit(std.testing.allocator);
    try std.testing.expectEqual(Qualifier.pass, record.directives.items[0].qualifier);
}

test "ip4 cidr matching" {
    try std.testing.expect(matchIp4Cidr(.{ 192, 168, 1, 42 }, .{ 192, 168, 1, 0 }, 24));
    try std.testing.expect(!matchIp4Cidr(.{ 192, 168, 2, 42 }, .{ 192, 168, 1, 0 }, 24));
    try std.testing.expect(matchIp4Cidr(.{ 10, 0, 0, 1 }, .{ 10, 0, 0, 1 }, 32));
    try std.testing.expect(!matchIp4Cidr(.{ 10, 0, 0, 2 }, .{ 10, 0, 0, 1 }, 32));
    try std.testing.expect(matchIp4Cidr(.{ 1, 2, 3, 4 }, .{ 0, 0, 0, 0 }, 0));
}

test "parse ip4 arg" {
    const r1 = try parseIp4Arg("192.168.1.0/24");
    try std.testing.expectEqual(@as(u8, 24), r1.prefix);

    const r2 = try parseIp4Arg("10.0.0.1");
    try std.testing.expectEqual(@as(u8, 32), r2.prefix);
}

test "case insensitive mechanisms" {
    var record = try parseRecord(std.testing.allocator, "v=spf1 MX A:example.com IP4:1.2.3.4 -ALL");
    defer record.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 4), record.directives.items.len);
    try std.testing.expectEqual(MechanismType.mx, record.directives.items[0].mechanism);
    try std.testing.expectEqual(MechanismType.a, record.directives.items[1].mechanism);
    try std.testing.expectEqual(MechanismType.ip4, record.directives.items[2].mechanism);
    try std.testing.expectEqual(MechanismType.all, record.directives.items[3].mechanism);
}
