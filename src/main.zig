const std = @import("std");
const posix = std.posix;
const mem = std.mem;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");
const config_mod = securemilter.config;
const connection_mod = securemilter.connection;
const worker_mod = securemilter.worker;
const daemon_mod = securemilter.daemon;
const bootstrap_mod = securemilter.bootstrap;
const zmq = securemilter.zmq;
const log = securemilter.log;
const header_scrub = securemilter.header_scrub;

// `spf` and `macro` are imported for test discovery only -- nothing here calls
// into them since the message path moved to `flow.zig`, but Zig does not find
// tests across files, so dropping them would silently stop running theirs.
const spf = @import("spf.zig");
const macro = @import("macro.zig");
const evaluate = @import("evaluate.zig");

const whitelist = @import("whitelist.zig");
const dns_mod = securemilter.dns;

pub const settings = @import("settings.zig");
const flow = @import("flow.zig");

// Re-exported at their old spellings so the stage 4.3 split is not a rename at
// any call site. `settings.zig` carries the reasoning for each of these.
pub const SpfConfig = settings.SpfConfig;
pub const parseSpfConfig = settings.parseSpfConfig;

const reload_mod = securemilter.reload;
const rcu_mod = securemilter.rcu;

// Module-level config set before worker spawn, read-only during runtime.
var g_authserv_id: []const u8 = "localhost";
var g_dns_config: dns_mod.ResolverConfig = .{};
/// Whitelist behind RCU: workers read while SIGHUP replaces. Freeing in place
/// was audit X-2 (freed memory read by `contains()`).
var g_whitelist: WhitelistRcu = undefined;
const WhitelistRcu = rcu_mod.Rcu(whitelist.Whitelist);

fn freeWhitelist(allocator: Allocator, wl: *whitelist.Whitelist) void {
    wl.deinit();
    allocator.destroy(wl);
}

/// Heap-allocate a parsed whitelist so it can be published. The container owns
/// it from here on.
fn boxWhitelist(allocator: Allocator, wl: whitelist.Whitelist) !*whitelist.Whitelist {
    const boxed = try allocator.create(whitelist.Whitelist);
    boxed.* = wl;
    return boxed;
}
var g_zmq_endpoint: ?[]const u8 = null;
var g_zmq_topic: []const u8 = "spf.result";
var g_whitelist_file: ?[]const u8 = null;
var g_strip_policy: header_scrub.StripPolicy = .{ .own_methods = &.{"spf"} };
var g_config_path: []const u8 = "/usr/local/etc/securespf/securespf.conf";
var g_allocator: Allocator = undefined;
var g_health_monitor: ?*dns_mod.HealthMonitor = null;

/// Start health monitor. Context-free to match `daemon.Options.spawn_threads`;
/// safe only at the single bootstrap point after daemonize and signal blocking.
fn spawnHealthMonitor() void {
    g_health_monitor = dns_mod.startMonitor(g_allocator, g_dns_config.nameservers);
}
var g_eval_limits: evaluate.Limits = .{};

// Global config generation counter — incremented on SIGHUP reload.
var g_config_gen: reload_mod.ConfigGeneration = reload_mod.ConfigGeneration.init();

// Thread-local ZMQ publisher (one socket per worker thread — ZMQ thread-safety)
threadlocal var tl_publisher: ?zmq.Publisher = null;

// Thread-local DNS resolver (audit X-3). Per-message resolver construction
// discarded the TTL and negative caches; per-worker keeps them alive.
// Lock-free, matching the publisher.
threadlocal var tl_resolver: ?dns_mod.Resolver = null;

fn getResolver() *dns_mod.Resolver {
    if (tl_resolver == null) {
        tl_resolver = dns_mod.Resolver.initWithMonitor(g_allocator, g_dns_config, g_health_monitor);
    }
    return &tl_resolver.?;
}

fn getPublisher() *zmq.Publisher {
    if (tl_publisher == null) {
        tl_publisher = zmq.Publisher.init(g_zmq_endpoint, g_zmq_topic);
    }
    return &tl_publisher.?;
}

fn usageError() error{InvalidArgument} {
    log.err("usage: securespf -c <config-file>", .{});
    return error.InvalidArgument;
}

/// Every failure below is reported by `bootstrap.fatal`, which explains why: after
/// `daemonize` stderr is /dev/null and syslog is the only channel left (X-16).
pub fn main() !void {
    runDaemon() catch |e| return bootstrap_mod.fatal(e);
}

fn runDaemon() !void {
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
        log.err("failed to load config {s}: {}", .{ config_path, err });
        return err;
    };
    defer cfg.deinit();

    const spf_cfg = try parseSpfConfig(allocator, &cfg);
    defer allocator.free(spf_cfg.listen_addresses);

    // Initialize logging from config (must be before any log calls below)
    const log_cfg = if (cfg.global()) |g| log.LogConfig.fromSection(g, "securespf") else log.LogConfig.init(true, .mail, .info, "securespf");
    log.initGlobal(&log_cfg);
    log.initThread(); // main thread logger

    // Initialize module-level globals (read-only after this point)
    g_authserv_id = spf_cfg.authserv_id;
    g_eval_limits = spf_cfg.eval_limits;
    g_dns_config = .{
        .nameservers = spf_cfg.dns_nameservers,
        .port = 53,
        .timeout_ms = spf_cfg.dns_timeout_ms,
        .retries = spf_cfg.dns_retries,
        .cache_size = spf_cfg.dns_cache_size,
        .negative_ttl = spf_cfg.dns_negative_ttl,
    };

    g_zmq_endpoint = spf_cfg.zmq_endpoint;
    g_zmq_topic = spf_cfg.zmq_topic;
    g_strip_policy = .{ .own_methods = &.{"spf"}, .strip_all = spf_cfg.strip_auth_results };

    // Load whitelist if configured
    g_whitelist = WhitelistRcu.init(allocator, freeWhitelist);
    g_whitelist_file = spf_cfg.whitelist_file;
    if (spf_cfg.whitelist_file) |wl_path| {
        if (whitelist.Whitelist.loadFile(allocator, wl_path)) |wl| {
            if (boxWhitelist(allocator, wl)) |boxed| {
                g_whitelist.publish(&g_config_gen, boxed) catch |err| {
                    freeWhitelist(allocator, boxed);
                    log.warn("failed to publish whitelist {s}: {}", .{ wl_path, err });
                };
            } else |err| {
                var owned = wl;
                owned.deinit();
                log.warn("failed to load whitelist {s}: {}", .{ wl_path, err });
            }
        } else |_| {
            log.warn("failed to load whitelist: {s}", .{wl_path});
        }
    }

    // Daemonize, block signals, start the monitor thread, claim the PID file, raise
    // the fd budget, drop privileges — in that order, for reasons recorded once in
    // `daemon.bootstrap` and enforced by its ordering tests. This was 40 lines here
    // and in each of the other three daemons, with X-7's constraint restated as a
    // comment in all four.
    var boot = try bootstrap_mod.run(.{
        .foreground = spf_cfg.foreground,
        .pid_file = spf_cfg.pid_file,
        .user = spf_cfg.user,
        .umask = spf_cfg.umask,
        .worker_threads = spf_cfg.worker_threads,
        .max_connections = spf_cfg.max_connections,
        .num_listeners = @intCast(spf_cfg.listen_addresses.len),
        .spawn_threads = spawnHealthMonitor,
    });
    defer boot.deinit();

    log.info("SecureSPF starting, AuthservID={s}, listeners={d}", .{
        spf_cfg.authserv_id,
        spf_cfg.listen_addresses.len,
    });

    // Spawn worker threads
    const callbacks = worker_mod.Callbacks{
        .on_eom = onEom,
        .on_reload = onWorkerReload,
        .required_actions = .{ .add_headers = true, .change_headers = true },
        // SPF needs no body, and no `header_leading_space` (D-23): this daemon
        // never rebuilds a header field to hash it.
        .protocol_flags = .{ .no_body = true },
        .limits = spf_cfg.limits,
    };

    // Create shutdown pipe: write-end wakes all workers from kevent()
    const shutdown_pipe = try posix.pipe();
    defer posix.close(shutdown_pipe[0]);

    var threads = try securemilter.pool.spawnPool(allocator, .{
        .num_workers = spf_cfg.worker_threads,
        .addresses = spf_cfg.listen_addresses,
        .callbacks = callbacks,
        .shutdown_pipe_rd = shutdown_pipe[0],
        .config_gen = &g_config_gen,
        .max_connections = spf_cfg.max_connections,
    });
    defer threads.deinit(allocator);

    // Bound and serving: release the parent blocked in `daemonize` (X-16).
    boot.notifyReady();

    // Main thread: signal loop handles SIGHUP (reload) and SIGTERM (shutdown)
    daemon_mod.ManagedSignals.signalLoop(shutdown_pipe[1], reloadConfig);
    for (threads.items) |t| t.join();

    // Workers are joined, so nothing can be holding a whitelist reference and
    // the retire list can be emptied unconditionally.
    g_whitelist.deinit();
    g_config_gen.deinit(allocator);

    if (g_health_monitor) |monitor| monitor.deinit();
}

// =============================================================================
// Milter Callbacks
// =============================================================================

// Only the phases this daemon acts on are registered below. An unregistered
// callback yields `Code.continue`, which is exactly what a stub returning
// `continue` did, so connect/helo/mail-from are simply absent rather than
// written out three times per daemon.

/// Snapshot this daemon's configuration for one message and run the pipeline.
///
/// The globals stay here and the decision logic lives in `flow.zig`; this is the
/// one function that spans both, which is why it is the only place that reads a
/// global on the message path. `flow.zig`'s header records why construction
/// belongs on this side of the seam rather than there.
fn onEom(conn: *connection_mod.Connection) u8 {
    return flow.doEval(conn, .{
        .authserv_id = g_authserv_id,
        .strip_policy = g_strip_policy,
        .eval_limits = g_eval_limits,
        // Resolved here, inside the message callback, so the borrow lasts
        // exactly as long as the message does.
        .whitelist = g_whitelist.get(),
        .resolver = getResolver,
        .publisher = getPublisher,
    });
}

// =============================================================================
// Reload
// =============================================================================

/// Main-thread reload callback: re-reads the whitelist file and publishes it.
///
/// Publishing advances the config generation, so workers pick the new list up
/// on their next message and call onWorkerReload() on their next loop
/// iteration. The previous list is retired rather than freed, and reclaimed
/// once every worker has been seen at a quiescent point past the swap.
fn reloadConfig() void {
    const wl_path = g_whitelist_file orelse {
        _ = g_config_gen.increment();
        log.info("config generation advanced to {d}", .{g_config_gen.load()});
        return;
    };

    var new_wl = whitelist.Whitelist.loadFile(g_allocator, wl_path) catch {
        log.warn("reload: failed to re-read whitelist {s}, keeping previous", .{wl_path});
        _ = g_config_gen.increment();
        return;
    };

    const boxed = boxWhitelist(g_allocator, new_wl) catch {
        new_wl.deinit();
        log.warn("reload: out of memory boxing whitelist, keeping previous", .{});
        _ = g_config_gen.increment();
        return;
    };

    g_whitelist.publish(&g_config_gen, boxed) catch {
        // publish reserves before it swaps, so on failure nothing changed and
        // the previous list is still installed.
        freeWhitelist(g_allocator, boxed);
        log.warn("reload: out of memory publishing whitelist, keeping previous", .{});
        _ = g_config_gen.increment();
        return;
    };

    // Pull the workers out of kevent() so they reach a quiescent point and the
    // superseded list becomes reclaimable. Without this an idle worker pins
    // the safe generation and the retire list grows for as long as reloads
    // keep arriving.
    g_config_gen.wake();

    log.info("whitelist reloaded from {s} (generation {d}, {d} awaiting reclamation)", .{
        wl_path,
        g_config_gen.load(),
        g_whitelist.retiredCount(),
    });
}

/// Per-worker reload callback: called when this worker detects the global config
/// generation has advanced. Drops this worker's DNS resolver, which is the one
/// piece of per-worker state a reload can invalidate.
fn onWorkerReload() void {
    // SecureSPF workers read g_whitelist directly (module global), so the
    // whitelist needs nothing here.
    //
    // The resolver does: it captured the nameserver list and cache sizing when
    // it was built, so a reload that changes either has to be able to replace
    // it. Dropping it also discards cached answers, which is the point -- after
    // a reload the operator's intent is the new configuration, not entries
    // fetched under the old one.
    if (tl_resolver) |*r| {
        r.deinit();
        tl_resolver = null;
    }
    log.debug("worker: config reload acknowledged", .{});
}

// =============================================================================
// Tests
// =============================================================================

test {
    _ = spf;
    _ = macro;
    _ = evaluate;
    _ = whitelist;
    _ = settings;
    _ = flow;
}
