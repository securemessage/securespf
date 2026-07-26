const std = @import("std");
const mem = std.mem;
const net = std.net;
const Allocator = mem.Allocator;

const spf = @import("spf.zig");

/// An entry in the whitelist: either a single IP or a CIDR range.
pub const Entry = union(enum) {
    ip4_exact: [4]u8,
    ip4_cidr: struct { addr: [4]u8, prefix: u8 },
    ip6_exact: [16]u8,
    ip6_cidr: struct { addr: [16]u8, prefix: u8 },
};

/// Trusted hosts whitelist — IPs/CIDRs that bypass SPF checking.
///
/// File format: one entry per line, `#` comments, blank lines ignored.
/// Entries: bare IPs (`192.168.1.1`) or CIDR (`10.0.0.0/8`, `2001:db8::/32`).
pub const Whitelist = struct {
    entries: []Entry = &.{},
    allocator: ?Allocator = null,

    /// Load a whitelist from a file path.
    pub fn loadFile(allocator: Allocator, path: []const u8) !Whitelist {
        const file = try std.fs.cwd().openFile(path, .{});
        defer file.close();

        const content = try file.readToEndAlloc(allocator, 1024 * 1024);
        defer allocator.free(content);

        return parse(allocator, content);
    }

    /// Parse whitelist from string content.
    pub fn parse(allocator: Allocator, content: []const u8) !Whitelist {
        var entries: std.ArrayListUnmanaged(Entry) = .{};
        errdefer entries.deinit(allocator);

        var lines = mem.splitScalar(u8, content, '\n');
        while (lines.next()) |raw_line| {
            const line = mem.trim(u8, raw_line, &std.ascii.whitespace);
            if (line.len == 0) continue;
            if (line[0] == '#') continue;

            if (parseEntry(line)) |entry| {
                try entries.append(allocator, entry);
            }
        }

        return .{
            .entries = try entries.toOwnedSlice(allocator),
            .allocator = allocator,
        };
    }

    /// Check if an IP address string is in the whitelist.
    pub fn contains(self: *const Whitelist, ip_str: []const u8) bool {
        if (self.entries.len == 0) return false;

        // Determine if IPv6
        const is_v6 = mem.indexOfScalar(u8, ip_str, ':') != null;

        if (!is_v6) {
            const client = spf.parseIp4Bytes(ip_str) catch return false;
            for (self.entries) |entry| {
                switch (entry) {
                    .ip4_exact => |addr| {
                        if (mem.eql(u8, &client, &addr)) return true;
                    },
                    .ip4_cidr => |cidr| {
                        if (spf.matchIp4Cidr(client, cidr.addr, cidr.prefix)) return true;
                    },
                    else => {},
                }
            }
        } else {
            const client = net.Ip6Address.parse(ip_str, 0) catch return false;
            for (self.entries) |entry| {
                switch (entry) {
                    .ip6_exact => |addr| {
                        if (mem.eql(u8, &client.sa.addr, &addr)) return true;
                    },
                    .ip6_cidr => |cidr| {
                        if (matchIp6Prefix(client.sa.addr, cidr.addr, cidr.prefix)) return true;
                    },
                    else => {},
                }
            }
        }
        return false;
    }

    pub fn deinit(self: *Whitelist) void {
        if (self.allocator) |alloc| {
            alloc.free(self.entries);
        }
        self.* = .{};
    }
};

fn parseEntry(line: []const u8) ?Entry {
    const slash = mem.indexOfScalar(u8, line, '/');
    const is_v6 = mem.indexOfScalar(u8, line, ':') != null;

    if (is_v6) {
        const addr_str = if (slash) |s| line[0..s] else line;
        const parsed = net.Ip6Address.parse(addr_str, 0) catch return null;
        if (slash) |s| {
            const prefix = std.fmt.parseInt(u8, line[s + 1 ..], 10) catch return null;
            return .{ .ip6_cidr = .{ .addr = parsed.sa.addr, .prefix = prefix } };
        }
        return .{ .ip6_exact = parsed.sa.addr };
    } else {
        const addr_str = if (slash) |s| line[0..s] else line;
        const parsed = net.Ip4Address.parse(addr_str, 0) catch return null;
        const bytes: [4]u8 = @bitCast(parsed.sa.addr);
        if (slash) |s| {
            const prefix = std.fmt.parseInt(u8, line[s + 1 ..], 10) catch return null;
            return .{ .ip4_cidr = .{ .addr = bytes, .prefix = prefix } };
        }
        return .{ .ip4_exact = bytes };
    }
}

fn matchIp6Prefix(client: [16]u8, network: [16]u8, prefix_len: u8) bool {
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

// =============================================================================
// Tests
// =============================================================================

test "parse and match ipv4 exact" {
    var wl = try Whitelist.parse(std.testing.allocator,
        \\# Trusted relay
        \\192.168.1.100
        \\10.0.0.1
    );
    defer wl.deinit();

    try std.testing.expect(wl.contains("192.168.1.100"));
    try std.testing.expect(wl.contains("10.0.0.1"));
    try std.testing.expect(!wl.contains("192.168.1.101"));
}

test "parse and match ipv4 cidr" {
    var wl = try Whitelist.parse(std.testing.allocator,
        \\10.0.0.0/8
        \\192.168.1.0/24
    );
    defer wl.deinit();

    try std.testing.expect(wl.contains("10.255.255.255"));
    try std.testing.expect(wl.contains("192.168.1.42"));
    try std.testing.expect(!wl.contains("192.168.2.1"));
}

test "parse and match ipv6" {
    var wl = try Whitelist.parse(std.testing.allocator,
        \\2001:db8::/32
        \\::1
    );
    defer wl.deinit();

    try std.testing.expect(wl.contains("::1"));
    try std.testing.expect(wl.contains("2001:db8::1"));
    try std.testing.expect(!wl.contains("2001:db9::1"));
}

test "empty whitelist matches nothing" {
    const wl = Whitelist{};
    try std.testing.expect(!wl.contains("192.168.1.1"));
}

test "comments and blank lines ignored" {
    var wl = try Whitelist.parse(std.testing.allocator,
        \\# This is a comment
        \\
        \\127.0.0.1
        \\   # indented comment
        \\
    );
    defer wl.deinit();

    try std.testing.expectEqual(@as(usize, 1), wl.entries.len);
    try std.testing.expect(wl.contains("127.0.0.1"));
}
