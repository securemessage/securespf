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
const auth_stamp = securemilter.auth_stamp;
const escape = securemilter.escape;
const codec = securemilter.milter.codec;
const responses = securemilter.milter.responses;
const negotiate = securemilter.milter.negotiate;
const zmq = securemilter.zmq;
const log = securemilter.log;
const header_scrub = securemilter.header_scrub;

const spf = @import("spf.zig");
const macro = @import("macro.zig");
const evaluate = @import("evaluate.zig");

const whitelist = @import("whitelist.zig");
const dns_mod = securemilter.dns;

pub const settings = @import("settings.zig");

// Re-exported at their old spellings so the stage 4.3 split is not a rename at
// any call site. `settings.zig` carries the reasoning for each of these.
pub const SpfConfig = settings.SpfConfig;
pub const parseSpfConfig = settings.parseSpfConfig;

const reload_mod = securemilter.reload;
const rcu_mod = securemilter.rcu;

// Module-level config set before worker spawn, read-only during runtime.
var g_authserv_id: []const u8 = "localhost";
var g_dns_config: dns_mod.ResolverConfig = .{};
/// Whitelist behind an RCU container: workers read it on every message while
/// SIGHUP replaces it. Freeing the old entries in place was audit X-2 — a
/// worker iterating `entries` in `contains()` would read freed memory.
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

/// `daemon.Options.spawn_threads`: start the DNS health monitor.
///
/// Reads `g_allocator` and `g_dns_config`, both set from the parsed configuration well
/// before the bootstrap runs. Context-free because that is what `daemon.Options` takes,
/// and deliberately so — the hook is called at the one point in the sequence where
/// creating a thread is safe, and a parameter would invite calling it from elsewhere.
fn spawnHealthMonitor() void {
    g_health_monitor = dns_mod.startMonitor(g_allocator, g_dns_config.nameservers);
}
var g_eval_limits: evaluate.Limits = .{};

// Global config generation counter — incremented on SIGHUP reload.
var g_config_gen: reload_mod.ConfigGeneration = reload_mod.ConfigGeneration.init();

// Thread-local ZMQ publisher (one socket per worker thread — ZMQ thread-safety)
threadlocal var tl_publisher: ?zmq.Publisher = null;

// Thread-local DNS resolver (audit X-3).
//
// One SPF evaluation costs up to `Limits.max_dns_lookups` queries, and the names
// it asks for repeat heavily across messages: the same sending domains, the same
// `include:` targets, the same `redirect=`. Building the resolver per message
// threw its TTL cache away every time, so every one of those queries was a cold
// round trip. The negative cache mattered more still -- it exists so an
// NXDOMAIN flood is answered from memory, and a cache that never outlives one
// message cannot do that.
//
// Per worker thread so it needs no lock, matching the publisher above.
// `g_allocator`, not `conn.allocator`, because it now outlives the connection --
// the same allocator either way, since the pool is handed `g_allocator`.
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

    var threads = try securemilter.pool.spawnPoolWithReload(
        allocator,
        spf_cfg.worker_threads,
        spf_cfg.listen_addresses,
        callbacks,
        shutdown_pipe[0],
        &g_config_gen,
        spf_cfg.max_connections,
    );
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

fn onEom(conn: *connection_mod.Connection) u8 {
    const start_ns = std.time.nanoTimestamp();

    // Drop forged results before producing our own, so nothing downstream can
    // read an spf= verdict this daemon did not issue.
    _ = header_scrub.stripAuthResults(conn, g_authserv_id, g_strip_policy);

    // Via the accessor, so the address is found on a stock MTA where the
    // {client_addr} macro is not sent. Kept OPTIONAL rather than defaulted to a
    // placeholder, because SPF is a function of this address: inventing one does
    // not degrade the answer, it fabricates one.
    const client_addr_opt = conn.clientAddr();
    const mail_from_raw = conn.mail_from_raw orelse "<>";
    const helo = conn.helo_name orelse "unknown";
    const queue_id = conn.macros.queue_id orelse "-";

    // Strip angle brackets from MAIL FROM (Postfix sends "<user@domain>")
    const mail_from = stripAngleBrackets(mail_from_raw);

    // REFUSE TO EVALUATE WITHOUT A USABLE ADDRESS.
    //
    // This used to substitute the literal string "unknown" and hand it to the
    // evaluator. Nothing downstream rejected the substitution: every mechanism
    // that inspects the client address parses it with `catch return false` --
    // `matchIp4`, `matchIp6`, `matchA` and `matchMx` in mechanisms.zig, and
    // `validatedNames` in ptr.zig -- so a value that is
    // not an address matched nothing, evaluation ran on to the terminal `-all`,
    // and this daemon published spf=fail -- an affirmative claim that the domain
    // DENIES this sender, asserted from an input that never existed. Under a
    // DMARC p=reject policy that rejects legitimate mail while recording a false
    // denial. RFC 7208 SS4.3 calls for permerror when input cannot be interpreted.
    if (client_addr_opt == null or !isIpAddress(client_addr_opt.?)) {
        // A connection with no network peer at all -- a unix-socket or stdin
        // submission -- is not an error, SPF simply does not apply to it. An
        // address that was present but did not parse is a permerror.
        const no_peer = client_addr_opt == null and
            (conn.connect_family == .unix or conn.connect_family == .unknown);
        const result_str = if (no_peer) "none" else "permerror";
        const reason = if (no_peer)
            "no client IP: local submission"
        else
            "client IP address missing or malformed";
        const domain = extractDomain(mail_from);
        const elapsed_ms = @divFloor(std.time.nanoTimestamp() - start_ns, 1_000_000);
        const peer = conn.getPeerDisplay();
        log.info("id={f} peer={f}[{f}] client={f} from={f} result={s} reason={s} elapsed={d}ms", .{
            escape.logField(queue_id),
            escape.logField(peer.name),
            escape.logField(peer.ip),
            escape.logField(client_addr_opt orelse "-"),
            escape.logField(mail_from),
            result_str,
            reason,
            elapsed_ms,
        });
        publishEvent(conn.allocator, client_addr_opt orelse "", helo, mail_from, result_str, domain);
        addArHeader(conn, result_str, reason, domain, helo) catch |err|
            return auth_stamp.deferCode(err, "spf");
        return @intFromEnum(responses.Code.accept);
    }
    const client_addr = client_addr_opt.?;

    // Check whitelist — skip SPF for trusted hosts.
    //
    // The reference is valid for this message: workers only announce
    // quiescence at the top of the event loop, so nothing can free the list
    // out from under this call (see securemilter rcu.zig).
    const whitelisted = if (g_whitelist.get()) |wl| wl.contains(client_addr) else false;
    if (whitelisted) {
        const elapsed_ms = @divFloor(std.time.nanoTimestamp() - start_ns, 1_000_000);
        const peer = conn.getPeerDisplay();
        log.info("id={f} peer={f}[{f}] client={f} from={f} result=pass (whitelisted) elapsed={d}ms", .{
            escape.logField(queue_id),
            escape.logField(peer.name),
            escape.logField(peer.ip),
            escape.logField(client_addr),
            escape.logField(mail_from),
            elapsed_ms,
        });
        addArHeader(conn, "pass", "client is whitelisted", extractDomain(mail_from), helo) catch |err|
            return auth_stamp.deferCode(err, "spf");
        return @intFromEnum(responses.Code.accept);
    }

    // Perform SPF evaluation
    const resolver = getResolver();

    const eval_ctx = evaluate.EvalContext{
        .client_ip = client_addr,
        .is_ipv6 = mem.indexOfScalar(u8, client_addr, ':') != null,
        .sender = mail_from,
        .helo_domain = helo,
        .receiver_host = g_authserv_id,
    };

    const result = evaluate.evaluateWithLimits(conn.allocator, resolver, &eval_ctx, g_eval_limits);
    const result_str = resultToString(result.result);
    const domain = if (result.domain.len > 0) result.domain else extractDomain(mail_from);

    const elapsed_ms = @divFloor(std.time.nanoTimestamp() - start_ns, 1_000_000);
    const peer = conn.getPeerDisplay();
    // Every value here except `result_str` and the elapsed time is sender- or
    // rDNS-controlled, so each is rendered as a single bare token: a newline in
    // any of them would otherwise forge a second syslog line, and a space would
    // make the next key appear to hold this value (audit X-5).
    log.info("id={f} peer={f}[{f}] client={f} from={f} result={s} elapsed={d}ms", .{
        escape.logField(queue_id),
        escape.logField(peer.name),
        escape.logField(peer.ip),
        escape.logField(client_addr),
        escape.logField(mail_from),
        result_str,
        elapsed_ms,
    });

    // A permerror is four different faults sharing one label, and an operator
    // fielding "why was my mail refused" needs to know which. The reason is a
    // static string chosen from a fixed set, so there is nothing here for a
    // sender to inject.
    if (result.reason) |reason| {
        log.info("id={f} domain={f} result={s} reason={s}", .{
            escape.logField(queue_id),
            escape.logField(domain),
            result_str,
            reason,
        });
    }

    // Publish ZMQ event (fire-and-forget, non-blocking)
    publishEvent(conn.allocator, client_addr, helo, mail_from, result_str, domain);

    addArHeader(conn, result_str, null, domain, helo) catch |err|
        return auth_stamp.deferCode(err, "spf");
    return @intFromEnum(responses.Code.accept);
}

/// True when `text` parses as an IPv4 or IPv6 address.
///
/// Used to gate evaluation, because the evaluator itself cannot report the
/// difference: it parses the client address at seven separate call sites and
/// every one of them treats a parse failure as "this mechanism does not match"
/// rather than as an error, which silently turns an uninterpretable input into
/// a `fail` verdict. The check has to happen before evaluation starts.
fn isIpAddress(text: []const u8) bool {
    if (spf.parseIp4Bytes(text)) |_| {
        return true;
    } else |_| {}
    if (spf.parseIp6Bytes(text)) |_| {
        return true;
    } else |_| {}
    return false;
}

/// Strip leading '<' and trailing '>' from an address.
fn stripAngleBrackets(addr: []const u8) []const u8 {
    var s = addr;
    if (s.len > 0 and s[0] == '<') s = s[1..];
    if (s.len > 0 and s[s.len - 1] == '>') s = s[0 .. s.len - 1];
    return s;
}

/// Record the SPF result on the message.
///
/// Every failure here used to be swallowed -- two `catch return continue` and a
/// `writePacket ... catch {}` followed unconditionally by `return accept`. The
/// message was then delivered with **no `spf=` field** while this daemon
/// reported success, and `securedmarc` went on to compute a DMARC verdict from
/// the evidence that survived. A message that would have passed on an aligned
/// SPF pass could be rejected under `p=reject` because this host could not
/// allocate a header (audit X-9).
///
/// A local fault is not charged to the sender: if the result cannot be recorded,
/// the message is deferred and the sender retries.
fn addArHeader(
    conn: *connection_mod.Connection,
    result_str: []const u8,
    reason: ?[]const u8,
    domain: []const u8,
    helo: []const u8,
) !void {
    try auth_stamp.stamp(conn.allocator, conn.fd, g_authserv_id, &.{
        .{
            .method = "spf",
            .result = result_str,
            .reason = reason,
            .properties = &.{
                .{ .ptype = "smtp", .property = "mailfrom", .value = domain },
                .{ .ptype = "smtp", .property = "helo", .value = helo },
            },
        },
    }, conn.negotiated_protocol.header_leading_space);
}

fn publishEvent(
    allocator: Allocator,
    client_ip: []const u8,
    helo: []const u8,
    mail_from: []const u8,
    result_str: []const u8,
    domain: []const u8,
) void {
    // Every value but `result_str` comes from the sender or from rDNS. A bare
    // `"` in any of them used to end the JSON string early and leave the rest of
    // the payload to be reinterpreted, so the consumer -- SecureMessageWebhooks
    // -- received either invalid JSON or fields the sender chose (audit X-5).
    //
    // Escaped rather than substituted, because an event is machine-read: the
    // consumer must receive the value this daemon actually saw.
    const json = std.fmt.allocPrint(allocator,
        \\{{"client_ip":"{f}","helo":"{f}","mail_from":"{f}","result":"{s}","domain":"{f}"}}
    , .{
        escape.jsonString(client_ip),
        escape.jsonString(helo),
        escape.jsonString(mail_from),
        result_str,
        escape.jsonString(domain),
    }) catch return;
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
}

test "extract domain from mail from" {
    try std.testing.expectEqualStrings("example.com", extractDomain("<user@example.com>"));
    try std.testing.expectEqualStrings("example.com", extractDomain("user@example.com"));
    try std.testing.expectEqualStrings("", extractDomain("<>"));
    try std.testing.expectEqualStrings("postmaster", extractDomain("postmaster"));
}

// X-9: this wrapper must stay fallible.
//
// The defect was a stamping path that swallowed every failure and returned
// `accept`, delivering the message with no `spf=` field while reporting success.
// `securedmarc` then computed a DMARC verdict from the evidence that survived.
//
// A regression would look like a `catch return continue` reappearing inside
// `addArHeader` and the signature going back to `u8`, which is invisible in
// review and impossible to spot from behaviour until mail is already wrong. This
// asserts the type instead: if the error union is removed, the build fails here.
test "the Authentication-Results wrapper cannot swallow failures" {
    comptime {
        const ret = @typeInfo(@TypeOf(addArHeader)).@"fn".return_type.?;
        if (@typeInfo(ret) != .error_union) @compileError(
            "addArHeader must return an error union. Swallowing a stamping failure " ++
                "delivers the message with no spf= field while reporting success, and " ++
                "securedmarc then evaluates DMARC without it (audit X-9).",
        );
        if (@typeInfo(ret).error_union.payload != void) @compileError(
            "addArHeader should return !void; the caller maps the error to a tempfail.",
        );
    }
}

test "strip angle brackets" {
    try std.testing.expectEqualStrings("user@example.com", stripAngleBrackets("<user@example.com>"));
    try std.testing.expectEqualStrings("user@example.com", stripAngleBrackets("user@example.com"));
    try std.testing.expectEqualStrings("", stripAngleBrackets("<>"));
    try std.testing.expectEqualStrings("", stripAngleBrackets(""));
}
