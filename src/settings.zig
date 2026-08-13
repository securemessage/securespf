//! SecureSPF INI parsing and runtime configuration.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");
const config_mod = securemilter.config;
const listener_mod = securemilter.listener;
const log = securemilter.log;
const connection_mod = securemilter.connection;
const worker_mod = securemilter.worker;

const evaluate = @import("evaluate.zig");

/// SecureSPF runtime configuration parsed from INI config.
pub const SpfConfig = struct {
    authserv_id: []const u8,
    listen_addresses: []const listener_mod.ListenAddress,
    worker_threads: u32,
    max_connections: u32,
    pid_file: []const u8,
    foreground: bool,
    user: ?[]const u8,
    /// File-creation mask for the PID file and any unix-domain listener.
    umask: ?std.posix.mode_t,
    dns_nameservers: []const []const u8,
    dns_timeout_ms: u32,
    dns_retries: u8,
    dns_cache_size: u32,
    dns_negative_ttl: u32,
    whitelist_file: ?[]const u8,
    trusted_relays_file: ?[]const u8,
    strip_auth_results: bool,
    zmq_endpoint: ?[]const u8,
    zmq_topic: []const u8,
    limits: connection_mod.Limits,
    eval_limits: evaluate.Limits,
};

/// Parse the SecureSPF config from a loaded Config.
/// Known configuration keys; anything else refuses startup. A key no table
/// knows is a typo, and a known global key inside a listener section is
/// silently inert — both reached production as real operator mistakes.
const known_global_keys: []const []const u8 = &(config_mod.base_global_keys ++ [_][]const u8{
    "AuthservID",        "WorkerThreads",  "MaxConnections",   "PidFile",
    "User",              "UMask",          "Foreground",       "DnsNameserver",
    "DnsTimeout",        "DnsRetries",     "DnsCacheSize",     "DnsNegativeTTL",
    "ZmqEndpoint",       "ZmqTopic",       "StripAuthResults", "WhitelistFile",
    "TrustedRelaysFile", "MaxVoidLookups", "MaxEvaluationMs",
});
const known_listener_keys = [_][]const u8{"Socket"};

pub fn parseSpfConfig(allocator: Allocator, cfg: *const config_mod.Config) !SpfConfig {
    if (config_mod.validateKeys(cfg, known_global_keys, &known_listener_keys)) |offense| {
        // stderr as well as the log: this fires before the logger is
        // initialized, and an operator message that only reaches an unopened
        // syslog socket is silent by another name.
        switch (offense.kind) {
            .unknown => {
                log.err("config: [{s}] unrecognized key \"{s}\" (typo?); refusing to start", .{ offense.section, offense.key });
                std.debug.print("config: [{s}] unrecognized key \"{s}\" (typo?); refusing to start\n", .{ offense.section, offense.key });
            },
            .misplaced => {
                log.err("config: [{s}] key \"{s}\" is a global key with no effect here; move it to [global]. Refusing to start", .{ offense.section, offense.key });
                std.debug.print("config: [{s}] key \"{s}\" is a global key with no effect here; move it to [global]. Refusing to start\n", .{ offense.section, offense.key });
            },
        }
        return error.InvalidConfiguration;
    }
    const global = cfg.getSection("global") orelse return error.MissingGlobalSection;

    const authserv_id = global.get("AuthservID") orelse "localhost";
    const workers = global.getInt("WorkerThreads", u32, 0);
    const pid_file = global.getOrDefault("PidFile", "/var/run/securespf/securespf.pid");
    const foreground_val = global.getBool("Foreground", false);
    const user = global.get("User");
    const umask = try global.getMode("UMask");

    // Collect listener addresses
    var addrs: std.ArrayListUnmanaged(listener_mod.ListenAddress) = .{};
    errdefer addrs.deinit(allocator);

    for (cfg.section_order.items) |section_name| {
        if (mem.startsWith(u8, section_name, "listener:")) {
            const section = cfg.getSection(section_name) orelse continue;

            // X-14: a malformed or missing Socket is refused, not skipped.
            const addr = try listener_mod.parseListenerSocket(section_name, section.get("Socket"));
            try addrs.append(allocator, addr);
        }
    }

    // Default to loopback: the milter protocol does not authenticate clients,
    // and Postfix is the intended local client.
    if (addrs.items.len == 0) {
        try addrs.append(allocator, .{ .tcp = .{ .host = "127.0.0.1", .port = 8890 } });
    }

    // Connection limits
    const max_connections = global.getInt("MaxConnections", u32, worker_mod.DEFAULT_MAX_CONNECTIONS);

    // DNS config — supports comma-separated list: DnsNameserver = 10.0.0.1, 8.8.8.8
    //
    // Owned slice, borrowed contents; unlike the ArrayLists above it does not
    // unwind itself, so it needs its own `errdefer` for every `try` below.
    const dns_nameservers = try global.getCsvList(allocator, "DnsNameserver", "127.0.0.1");
    errdefer allocator.free(dns_nameservers);
    const dns_timeout = global.getInt("DnsTimeout", u32, 5) * 1000; // config is seconds, we need ms
    const dns_retries = global.getInt("DnsRetries", u8, 2);
    const dns_cache_size = global.getInt("DnsCacheSize", u32, 1000);
    const dns_negative_ttl = global.getInt("DnsNegativeTTL", u32, 60);

    // Whitelist (assert pass for known-good senders) and trusted relays (our
    // own infrastructure; evaluation is meaningless against a relay's address,
    // so it is skipped rather than asserted). Different claims, different keys.
    const wl_file = global.get("WhitelistFile");
    const tr_file = global.get("TrustedRelaysFile");

    // Trust boundary: when this is the first milter in the chain, no A-R header
    // claiming our authserv-id can be genuine on arrival (RFC 8601 §5).
    const strip_auth_results = global.getBool("StripAuthResults", false);

    // Caps on attacker-controlled message content (audit X-4). SPF never reads
    // the body, so only the header caps bite here — they still matter, because
    // the forged-A-R scrub can only remove headers this daemon accumulated.
    const limits = connection_mod.Limits.fromSection(global);

    // Bounds on one SPF evaluation (audit S-2). An SPF record is a program the
    // sender writes, so the receiver is the one that has to bound it.
    const eval_limits = evaluate.Limits.fromSection(global);

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
        .umask = umask,
        .dns_nameservers = dns_nameservers,
        .dns_timeout_ms = dns_timeout,
        .dns_retries = dns_retries,
        .dns_cache_size = dns_cache_size,
        .dns_negative_ttl = dns_negative_ttl,
        .whitelist_file = wl_file,
        .trusted_relays_file = tr_file,
        .strip_auth_results = strip_auth_results,
        .zmq_endpoint = zmq_endpoint,
        .zmq_topic = zmq_topic,
        .limits = limits,
        .eval_limits = eval_limits,
    };
}

// =============================================================================
// Tests
// =============================================================================

fn freeTestConfig(spf_cfg: SpfConfig) void {
    std.testing.allocator.free(spf_cfg.listen_addresses);
    std.testing.allocator.free(spf_cfg.dns_nameservers);
}

// Both tests below keep `cfg` alive across their assertions on purpose. An address
// from a `Socket =` line BORROWS its host string from the parsed config, so a helper
// that parses and deinits in one call would hand back a dangling pointer -- a
// mistake the loopback case alone would not catch, because "127.0.0.1" is a
// literal in the fallback and survives the free.

// The implicit listener binds loopback, never 0.0.0.0: the milter protocol
// authenticates nobody, so a reachable port means an attacker supplies the
// client IP, HELO and MAIL FROM that check_host() runs on, and therefore
// chooses the SPF result this host stamps. Reachability IS authorization.
test "the implicit listener binds loopback, not every interface" {
    var cfg = try config_mod.parse(std.testing.allocator,
        \\[global]
        \\AuthservID = mail.test.com
    );
    defer cfg.deinit();

    const spf_cfg = try parseSpfConfig(std.testing.allocator, &cfg);
    defer freeTestConfig(spf_cfg);

    try std.testing.expectEqual(@as(usize, 1), spf_cfg.listen_addresses.len);
    switch (spf_cfg.listen_addresses[0]) {
        .tcp => |tcp| {
            try std.testing.expectEqualStrings("127.0.0.1", tcp.host);
            try std.testing.expectEqual(@as(u16, 8890), tcp.port);
        },
        else => return error.TestUnexpectedResult,
    }
}

// A safe default, not a policy override: an operator whose Postfix runs in another
// jail must still be able to ask for a routable socket.
test "an explicit 0.0.0.0 socket is still honoured" {
    var cfg = try config_mod.parse(std.testing.allocator,
        \\[global]
        \\AuthservID = mail.test.com
        \\
        \\[listener:wide]
        \\Socket = inet:8890@0.0.0.0
    );
    defer cfg.deinit();

    const spf_cfg = try parseSpfConfig(std.testing.allocator, &cfg);
    defer freeTestConfig(spf_cfg);

    switch (spf_cfg.listen_addresses[0]) {
        .tcp => |tcp| try std.testing.expectEqualStrings("0.0.0.0", tcp.host),
        else => return error.TestUnexpectedResult,
    }
}

// X-14. The pair of assertions that matter here are "it is an error" and
// "the fallback did NOT fire". The second is the dangerous half: a silently
// skipped listener would leave `addrs` empty, so the loopback default above
// would take its place and the daemon would listen somewhere the operator
// never asked for while reporting a successful start.
test "a malformed listener Socket is refused, not replaced by the default" {
    var cfg = try config_mod.parse(std.testing.allocator,
        \\[global]
        \\AuthservID = mail.test.com
        \\
        \\[listener:typo]
        \\Socket = inet6:8890@::1
    );
    defer cfg.deinit();

    try std.testing.expectError(error.InvalidListenerSocket, parseSpfConfig(std.testing.allocator, &cfg));
}

// A hostname is the likeliest form of this mistake; accepting it here would
// let it parse cleanly and fail later inside a worker thread, where the only
// response available is to log and let that thread die.
test "a hostname in Socket is refused at config time" {
    var cfg = try config_mod.parse(std.testing.allocator,
        \\[global]
        \\AuthservID = mail.test.com
        \\
        \\[listener:main]
        \\Socket = inet:8890@localhost
    );
    defer cfg.deinit();

    try std.testing.expectError(error.InvalidListenerSocket, parseSpfConfig(std.testing.allocator, &cfg));
}

// A `[listener:*]` section that names no address is self-contradictory. Kept
// distinct from the absent-section case, which still gets the documented default.
test "a listener section with no Socket is refused" {
    var cfg = try config_mod.parse(std.testing.allocator,
        \\[global]
        \\AuthservID = mail.test.com
        \\
        \\[listener:empty]
        \\
    );
    defer cfg.deinit();

    try std.testing.expectError(error.MissingListenerSocket, parseSpfConfig(std.testing.allocator, &cfg));
}
