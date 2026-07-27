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
const zmq = securemilter.zmq;

const spf = @import("spf.zig");
const macro = @import("macro.zig");
const evaluate = @import("evaluate.zig");

const whitelist = @import("whitelist.zig");
const dns_mod = securemilter.dns;

/// SecureSPF runtime configuration parsed from INI config.
pub const SpfConfig = struct {
    authserv_id: []const u8,
    listen_addresses: []const listener_mod.ListenAddress,
    worker_threads: u32,
    max_connections: u32,
    pid_file: []const u8,
    foreground: bool,
    user: ?[]const u8,
    dns_nameservers: []const []const u8,
    dns_timeout_ms: u32,
    dns_retries: u8,
    whitelist_file: ?[]const u8,
    zmq_endpoint: ?[]const u8,
    zmq_topic: []const u8,
};

const reload_mod = securemilter.reload;

// Module-level config set before worker spawn, read-only during runtime.
var g_authserv_id: []const u8 = "localhost";
var g_dns_config: dns_mod.ResolverConfig = .{};
var g_whitelist: whitelist.Whitelist = .{};
var g_zmq_endpoint: ?[]const u8 = null;
var g_zmq_topic: []const u8 = "spf.result";
var g_whitelist_file: ?[]const u8 = null;
var g_config_path: []const u8 = "/usr/local/etc/securespf/securespf.conf";
var g_allocator: Allocator = undefined;
var g_health_monitor: ?*dns_mod.HealthMonitor = null;

// Global config generation counter — incremented on SIGHUP reload.
var g_config_gen: reload_mod.ConfigGeneration = reload_mod.ConfigGeneration.init();

// Thread-local ZMQ publisher (one socket per worker thread — ZMQ thread-safety)
threadlocal var tl_publisher: ?zmq.Publisher = null;

fn getPublisher() *zmq.Publisher {
    if (tl_publisher == null) {
        tl_publisher = zmq.Publisher.init(g_zmq_endpoint, g_zmq_topic);
    }
    return &tl_publisher.?;
}

/// Parse the SecureSPF config from a loaded Config.
pub fn parseSpfConfig(allocator: Allocator, cfg: *const config_mod.Config) !SpfConfig {
    const global = cfg.getSection("global") orelse return error.MissingGlobalSection;

    const authserv_id = global.get("AuthservID") orelse "localhost";
    const workers = global.getInt("WorkerThreads", u32, 0);
    const pid_file = global.getOrDefault("PidFile", "/var/run/securespf/securespf.pid");
    const foreground_val = global.getBool("Foreground", false);
    const user = global.get("User");

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

    // Connection limits
    const max_connections = global.getInt("MaxConnections", u32, worker_mod.DEFAULT_MAX_CONNECTIONS);

    // DNS config — supports comma-separated list: DnsNameserver = 10.0.0.1, 8.8.8.8
    const dns_ns_raw = global.getOrDefault("DnsNameserver", "127.0.0.1");
    var ns_list: std.ArrayListUnmanaged([]const u8) = .{};
    var ns_iter = mem.splitSequence(u8, dns_ns_raw, ",");
    while (ns_iter.next()) |part| {
        const trimmed = mem.trim(u8, part, " \t");
        if (trimmed.len > 0) try ns_list.append(allocator, trimmed);
    }
    const dns_nameservers = try ns_list.toOwnedSlice(allocator);
    const dns_timeout = global.getInt("DnsTimeout", u32, 5) * 1000; // config is seconds, we need ms
    const dns_retries = global.getInt("DnsRetries", u8, 2);

    // Whitelist
    const wl_file = global.get("WhitelistFile");

    // ZMQ event publishing
    const zmq_endpoint = global.get("ZmqEndpoint");
    const zmq_topic = global.getOrDefault("ZmqTopic", "spf.result");

    return .{
        .authserv_id = authserv_id,
        .listen_addresses = try addrs.toOwnedSlice(allocator),
        .worker_threads = workers,
        .max_connections = max_connections,
        .pid_file = pid_file,
        .foreground = foreground_val,
        .user = user,
        .dns_nameservers = dns_nameservers,
        .dns_timeout_ms = dns_timeout,
        .dns_retries = dns_retries,
        .whitelist_file = wl_file,
        .zmq_endpoint = zmq_endpoint,
        .zmq_topic = zmq_topic,
    };
}

fn usageError() error{InvalidArgument} {
    std.log.err("usage: securespf -c <config-file>", .{});
    return error.InvalidArgument;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    g_allocator = allocator;

    // Parse command-line: securespf -c /path/to/config
    var args = std.process.args();
    _ = args.next(); // skip argv[0]
    const flag = args.next() orelse return usageError();
    if (!std.mem.eql(u8, flag, "-c")) return usageError();
    const config_path = args.next() orelse return usageError();
    g_config_path = config_path;

    // Load config
    var cfg = config_mod.parseFile(allocator, config_path) catch |err| {
        std.log.err("failed to load config {s}: {}", .{ config_path, err });
        return err;
    };
    defer cfg.deinit();

    const spf_cfg = try parseSpfConfig(allocator, &cfg);
    defer allocator.free(spf_cfg.listen_addresses);

    // Initialize module-level globals (read-only after this point)
    g_authserv_id = spf_cfg.authserv_id;
    g_dns_config = .{
        .nameservers = spf_cfg.dns_nameservers,
        .port = 53,
        .timeout_ms = spf_cfg.dns_timeout_ms,
        .retries = spf_cfg.dns_retries,
    };

    // Start proactive DNS health monitor
    if (dns_mod.HealthMonitor.init(allocator, spf_cfg.dns_nameservers, 53, 5, 2000)) |monitor| {
        monitor.start() catch |err| {
            std.log.warn("DNS health monitor thread failed: {}", .{err});
        };
        g_health_monitor = monitor;
    } else |err| {
        std.log.warn("DNS health monitor init failed: {}, falling back to reactive", .{err});
    }
    g_zmq_endpoint = spf_cfg.zmq_endpoint;
    g_zmq_topic = spf_cfg.zmq_topic;

    // Load whitelist if configured
    g_whitelist_file = spf_cfg.whitelist_file;
    if (spf_cfg.whitelist_file) |wl_path| {
        if (whitelist.Whitelist.loadFile(allocator, wl_path)) |wl| {
            g_whitelist = wl;
        } else |_| {
            std.log.warn("failed to load whitelist: {s}", .{wl_path});
        }
    }

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

    // Raise fd limit to calculated budget before dropping privileges
    const num_workers = if (spf_cfg.worker_threads == 0) @as(u32, @intCast(std.Thread.getCpuCount() catch 4)) else spf_cfg.worker_threads;
    const fd_need = daemon_mod.calculateFdNeed(num_workers, spf_cfg.max_connections, @intCast(spf_cfg.listen_addresses.len));
    daemon_mod.raiseFileLimit(fd_need);

    // Drop privileges after PID file is written, before workers spawn
    if (spf_cfg.user) |user| {
        daemon_mod.dropPrivileges(user) catch |err| {
            std.log.err("privilege drop to '{s}' failed: {}", .{ user, err });
            return err;
        };
    }

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
        .on_reload = onWorkerReload,
        .required_actions = .{ .add_headers = true },
        .skip_flags = .{ .no_body = true }, // SPF doesn't need message body
    };

    // Create shutdown pipe: write-end wakes all workers from kevent()
    const shutdown_pipe = try posix.pipe();
    defer posix.close(shutdown_pipe[0]);

    // Block signals before spawning workers so SIGTERM/SIGINT/SIGHUP are
    // delivered only via sigwait in the main thread.
    daemon_mod.ManagedSignals.blockForKqueue();

    var threads = try worker_mod.spawnPoolWithReload(
        allocator,
        spf_cfg.worker_threads,
        spf_cfg.listen_addresses,
        callbacks,
        shutdown_pipe[0],
        &g_config_gen,
        spf_cfg.max_connections,
    );
    defer threads.deinit(allocator);

    // Main thread: signal loop handles SIGHUP (reload) and SIGTERM (shutdown)
    daemon_mod.ManagedSignals.signalLoop(shutdown_pipe[1], reloadConfig);
    for (threads.items) |t| t.join();
    if (g_health_monitor) |monitor| monitor.deinit();
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
    return @intFromEnum(responses.Code.@"continue");
}

fn onEom(conn: *connection_mod.Connection) u8 {
    const client_addr = conn.macros.client_addr orelse "unknown";
    const mail_from_raw = conn.mail_from_raw orelse "<>";
    const helo = conn.helo_name orelse "unknown";

    // Strip angle brackets from MAIL FROM (Postfix sends "<user@domain>")
    const mail_from = stripAngleBrackets(mail_from_raw);

    // Check whitelist — skip SPF for trusted hosts
    if (g_whitelist.contains(client_addr)) {
        return addArHeader(conn, "pass", "client is whitelisted", extractDomain(mail_from), helo);
    }

    // Perform SPF evaluation
    var resolver = dns_mod.Resolver.initWithMonitor(conn.allocator, g_dns_config, g_health_monitor);
    defer resolver.deinit();

    const eval_ctx = evaluate.EvalContext{
        .client_ip = client_addr,
        .is_ipv6 = mem.indexOfScalar(u8, client_addr, ':') != null,
        .sender = mail_from,
        .helo_domain = helo,
        .receiver_host = g_authserv_id,
    };

    const result = evaluate.evaluate(conn.allocator, &resolver, &eval_ctx);
    const result_str = resultToString(result.result);
    const domain = if (result.domain.len > 0) result.domain else extractDomain(mail_from);

    // Publish ZMQ event (fire-and-forget, non-blocking)
    publishEvent(conn.allocator, client_addr, helo, mail_from, result_str, domain);

    return addArHeader(conn, result_str, null, domain, helo);
}

/// Strip leading '<' and trailing '>' from an address.
fn stripAngleBrackets(addr: []const u8) []const u8 {
    var s = addr;
    if (s.len > 0 and s[0] == '<') s = s[1..];
    if (s.len > 0 and s[s.len - 1] == '>') s = s[0 .. s.len - 1];
    return s;
}

fn addArHeader(
    conn: *connection_mod.Connection,
    result_str: []const u8,
    reason: ?[]const u8,
    domain: []const u8,
    helo: []const u8,
) u8 {
    const ar_value = auth_results.build(conn.allocator, g_authserv_id, &.{
        .{
            .method = "spf",
            .result = result_str,
            .reason = reason,
            .properties = &.{
                .{ .ptype = "smtp", .property = "mailfrom", .value = domain },
                .{ .ptype = "smtp", .property = "helo", .value = helo },
            },
        },
    }) catch return @intFromEnum(responses.Code.@"continue");
    defer conn.allocator.free(ar_value);

    const hdr_payload = responses.addHeader(
        conn.allocator,
        "Authentication-Results",
        ar_value,
    ) catch return @intFromEnum(responses.Code.@"continue");
    defer conn.allocator.free(hdr_payload);

    codec.writePacket(conn.fd, hdr_payload) catch {};
    return @intFromEnum(responses.Code.accept);
}

fn publishEvent(
    allocator: Allocator,
    client_ip: []const u8,
    helo: []const u8,
    mail_from: []const u8,
    result_str: []const u8,
    domain: []const u8,
) void {
    const json = std.fmt.allocPrint(allocator,
        \\{{"client_ip":"{s}","helo":"{s}","mail_from":"{s}","result":"{s}","domain":"{s}"}}
    , .{ client_ip, helo, mail_from, result_str, domain }) catch return;
    defer allocator.free(json);

    getPublisher().publish(json);
}

fn resultToString(result: spf.Result) []const u8 {
    return switch (result) {
        .none => "none",
        .neutral => "neutral",
        .pass => "pass",
        .fail => "fail",
        .softfail => "softfail",
        .temperror => "temperror",
        .permerror => "permerror",
    };
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
// Reload
// =============================================================================

/// Main-thread reload callback: re-reads whitelist file and increments
/// the config generation counter. Workers will pick up the new generation
/// on their next event loop iteration and call onWorkerReload().
fn reloadConfig() void {
    // Re-read whitelist (the primary reloadable state for SecureSPF)
    if (g_whitelist_file) |wl_path| {
        if (whitelist.Whitelist.loadFile(g_allocator, wl_path)) |new_wl| {
            // Free old entries if they were heap-allocated
            if (g_whitelist.allocator) |old_alloc| {
                old_alloc.free(g_whitelist.entries);
            }
            g_whitelist = new_wl;
            std.log.info("whitelist reloaded from {s}", .{wl_path});
        } else |_| {
            std.log.warn("reload: failed to re-read whitelist {s}, keeping previous", .{wl_path});
        }
    }

    // Signal workers that config has changed
    g_config_gen.increment();
    std.log.info("config generation advanced to {d}", .{g_config_gen.load()});
}

/// Per-worker reload callback: called when this worker detects the
/// global config generation has advanced. For SecureSPF, workers have
/// no local caches to flush (whitelist is a module global read directly),
/// so this is a no-op placeholder for the interface contract.
fn onWorkerReload() void {
    // SecureSPF workers read g_whitelist directly (module global).
    // No per-worker LRU cache to flush. Log for observability.
    std.log.debug("worker: config reload acknowledged", .{});
}

// =============================================================================
// Tests
// =============================================================================

test {
    _ = spf;
    _ = macro;
    _ = evaluate;
    _ = whitelist;
}

test "extract domain from mail from" {
    try std.testing.expectEqualStrings("example.com", extractDomain("<user@example.com>"));
    try std.testing.expectEqualStrings("example.com", extractDomain("user@example.com"));
    try std.testing.expectEqualStrings("", extractDomain("<>"));
    try std.testing.expectEqualStrings("postmaster", extractDomain("postmaster"));
}

test "strip angle brackets" {
    try std.testing.expectEqualStrings("user@example.com", stripAngleBrackets("<user@example.com>"));
    try std.testing.expectEqualStrings("user@example.com", stripAngleBrackets("user@example.com"));
    try std.testing.expectEqualStrings("", stripAngleBrackets("<>"));
    try std.testing.expectEqualStrings("", stripAngleBrackets(""));
}
