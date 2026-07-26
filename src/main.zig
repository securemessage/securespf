const std = @import("std");
const posix = std.posix;
const mem = std.mem;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");
const config_mod = securemilter.config;
const listener_mod = securemilter.listener;
const connection_mod = securemilter.connection;
const worker_mod = securemilter.worker;
const daemon_mod = securemilter.daemon;
const auth_results = securemilter.auth_results;
const commands = securemilter.milter.commands;
const codec = securemilter.milter.codec;
const responses = securemilter.milter.responses;
const negotiate = securemilter.milter.negotiate;

const spf = @import("spf.zig");
const macro = @import("macro.zig");
const evaluate = @import("evaluate.zig");

/// SecureSPF runtime configuration parsed from INI config.
pub const SpfConfig = struct {
    authserv_id: []const u8,
    listen_addresses: []const listener_mod.ListenAddress,
    worker_threads: u32,
    pid_file: []const u8,
    foreground: bool,
};

/// Parse the SecureSPF config from a loaded Config.
pub fn parseSpfConfig(allocator: Allocator, cfg: *const config_mod.Config) !SpfConfig {
    const global = cfg.getSection("global") orelse return error.MissingGlobalSection;

    const authserv_id = global.get("AuthservID") orelse "localhost";
    const workers = global.getInt("WorkerThreads", u32, 0);
    const pid_file = global.getOrDefault("PidFile", "/var/run/securespf/securespf.pid");
    const foreground_val = global.getBool("Foreground", false);

    // Collect listener addresses
    var addrs: std.ArrayListUnmanaged(listener_mod.ListenAddress) = .{};
    errdefer addrs.deinit(allocator);

    for (cfg.section_order.items) |section_name| {
        if (mem.startsWith(u8, section_name, "listener:")) {
            const section = cfg.getSection(section_name) orelse continue;
            const socket_str = section.get("Socket") orelse continue;
            const addr = listener_mod.ListenAddress.parse(socket_str) catch continue;
            try addrs.append(allocator, addr);
        }
    }

    // Fallback: if no listener sections, use default port
    if (addrs.items.len == 0) {
        try addrs.append(allocator, .{ .tcp = .{ .host = "0.0.0.0", .port = 8890 } });
    }

    return .{
        .authserv_id = authserv_id,
        .listen_addresses = try addrs.toOwnedSlice(allocator),
        .worker_threads = workers,
        .pid_file = pid_file,
        .foreground = foreground_val,
    };
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse command-line for config file path
    var args = std.process.args();
    _ = args.next(); // skip argv[0]
    const config_path = args.next() orelse "/usr/local/etc/securespf/securespf.conf";

    // Load config
    var cfg = config_mod.parseFile(allocator, config_path) catch |err| {
        std.log.err("failed to load config {s}: {}", .{ config_path, err });
        return err;
    };
    defer cfg.deinit();

    const spf_cfg = try parseSpfConfig(allocator, &cfg);
    defer allocator.free(spf_cfg.listen_addresses);

    // Daemonize unless foreground mode
    if (!spf_cfg.foreground) {
        daemon_mod.daemonize() catch |err| {
            std.log.err("daemonize failed: {}", .{err});
            return err;
        };
    }

    // Write PID file
    daemon_mod.writePidFile(spf_cfg.pid_file) catch |err| {
        std.log.err("pid file write failed: {}", .{err});
    };
    defer daemon_mod.removePidFile(spf_cfg.pid_file);

    std.log.info("SecureSPF starting, AuthservID={s}, listeners={d}", .{
        spf_cfg.authserv_id,
        spf_cfg.listen_addresses.len,
    });

    // Spawn worker threads
    const callbacks = worker_mod.Callbacks{
        .on_connect = onConnect,
        .on_helo = onHelo,
        .on_mail_from = onMailFrom,
        .on_eom = onEom,
        .required_actions = .{ .add_headers = true },
        .skip_flags = .{ .no_body = true }, // SPF doesn't need message body
    };

    var threads = try worker_mod.spawnPool(
        allocator,
        spf_cfg.worker_threads,
        spf_cfg.listen_addresses,
        callbacks,
    );
    defer threads.deinit(allocator);

    // Main thread: wait for threads (in production, handle signals here)
    for (threads.items) |t| t.join();
}

// =============================================================================
// Milter Callbacks
// =============================================================================

fn onConnect(conn: *connection_mod.Connection, _: commands.ConnectInfo) u8 {
    _ = conn;
    return @intFromEnum(responses.Code.@"continue");
}

fn onHelo(conn: *connection_mod.Connection, _: []const u8) u8 {
    _ = conn;
    return @intFromEnum(responses.Code.@"continue");
}

fn onMailFrom(conn: *connection_mod.Connection, _: []const u8) u8 {
    _ = conn;
    // SPF evaluation will happen here once the evaluation engine is wired
    return @intFromEnum(responses.Code.@"continue");
}

fn onEom(conn: *connection_mod.Connection) u8 {
    // Build Authentication-Results header with SPF result
    // For now, use the data captured during the connection
    const client_addr = conn.macros.client_addr orelse "unknown";
    const mail_from = conn.mail_from_raw orelse "<>";
    const helo = conn.helo_name orelse "unknown";

    // Extract domain from MAIL FROM
    const domain = extractDomain(mail_from);

    // TODO: actual SPF evaluation via DNS — for now return "none"
    const result_str = "none";
    const reason = "SPF evaluation not yet implemented";
    _ = helo;

    // Build the A-R header value
    const ar_value = auth_results.build(conn.allocator, "localhost", &.{
        .{
            .method = "spf",
            .result = result_str,
            .reason = reason,
            .properties = &.{
                .{ .ptype = "smtp", .property = "mailfrom", .value = domain },
                .{ .ptype = "smtp", .property = "helo", .value = conn.helo_name orelse "unknown" },
            },
        },
    }) catch return @intFromEnum(responses.Code.@"continue");
    defer conn.allocator.free(ar_value);

    // Send SMFIR_ADDHEADER to prepend Authentication-Results
    const hdr_payload = responses.addHeader(
        conn.allocator,
        "Authentication-Results",
        ar_value,
    ) catch return @intFromEnum(responses.Code.@"continue");
    defer conn.allocator.free(hdr_payload);

    codec.writePacket(conn.fd, hdr_payload) catch {};

    // After adding headers, respond with accept
    _ = client_addr;
    return @intFromEnum(responses.Code.accept);
}

/// Extract domain from a MAIL FROM address (strip angle brackets and local-part).
fn extractDomain(mail_from: []const u8) []const u8 {
    var addr = mail_from;
    // Strip angle brackets: "<user@domain>" → "user@domain"
    if (addr.len > 0 and addr[0] == '<') addr = addr[1..];
    if (addr.len > 0 and addr[addr.len - 1] == '>') addr = addr[0 .. addr.len - 1];
    // Find @ and return domain
    if (mem.lastIndexOfScalar(u8, addr, '@')) |at| {
        return addr[at + 1 ..];
    }
    return addr;
}

// =============================================================================
// Tests
// =============================================================================

test {
    _ = spf;
    _ = macro;
    _ = evaluate;
}

test "extract domain from mail from" {
    try std.testing.expectEqualStrings("example.com", extractDomain("<user@example.com>"));
    try std.testing.expectEqualStrings("example.com", extractDomain("user@example.com"));
    try std.testing.expectEqualStrings("", extractDomain("<>"));
    try std.testing.expectEqualStrings("postmaster", extractDomain("postmaster"));
}
