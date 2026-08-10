//! End-of-message SPF evaluation, stamping, and event publishing.
//!
//! `main.zig` supplies a configuration snapshot through `MsgCtx`; this module
//! does not read daemon globals.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");
const connection_mod = securemilter.connection;
const auth_stamp = securemilter.auth_stamp;
const auth_results = securemilter.auth_results;
const escape = securemilter.escape;
const responses = securemilter.milter.responses;
const zmq = securemilter.zmq;
const log = securemilter.log;
const header_scrub = securemilter.header_scrub;
const dns_mod = securemilter.dns;

const spf = @import("spf.zig");
const evaluate = @import("evaluate.zig");
const whitelist_mod = @import("whitelist.zig");

/// Everything one message needs from the daemon's configuration.
///
/// Constructed by `main.zig`, never here — see this file's header for why.
pub const MsgCtx = struct {
    /// Who this hop identifies as in `Authentication-Results`, and the identity
    /// whose forged results are scrubbed on the way in.
    authserv_id: []const u8,
    strip_policy: header_scrub.StripPolicy,
    /// Bounds on one evaluation (audit S-2). An SPF record is a program the
    /// sender writes, so the receiver is the one that has to bound it.
    eval_limits: evaluate.Limits,
    /// The list as it stood when this message arrived, already resolved from its
    /// RCU container by `main.zig`.
    ///
    /// The reference is valid for the whole message: workers only announce
    /// quiescence at the top of the event loop, so nothing can free the list
    /// while this runs (see securemilter rcu.zig).
    whitelist: ?*const whitelist_mod.Whitelist,

    /// Lazy per-thread resolver and publisher accessors.
    resolver: *const fn () *dns_mod.Resolver,
    publisher: *const fn () *zmq.Publisher,
};

pub fn doEval(conn: *connection_mod.Connection, ctx: MsgCtx) u8 {
    const start_ns = std.time.nanoTimestamp();

    // Drop forged results before producing our own, so nothing downstream can
    // read an spf= verdict this daemon did not issue.
    _ = header_scrub.stripAuthResults(conn, ctx.authserv_id, ctx.strip_policy);

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
    // Substituting a placeholder string (e.g. "unknown") and handing it to the
    // evaluator would not be rejected downstream: every mechanism that inspects
    // the client address parses it with `catch return false` -- `matchIp4`,
    // `matchIp6`, `matchA` and `matchMx` in mechanisms.zig, and `validatedNames`
    // in ptr.zig -- so a value that is not an address matches nothing,
    // evaluation runs on to the terminal `-all`, and this daemon would publish
    // spf=fail -- an affirmative claim that the domain DENIES this sender,
    // asserted from an input that never existed. Under a DMARC p=reject policy
    // that rejects legitimate mail while recording a false denial. RFC 7208
    // §4.3 calls for permerror when input cannot be interpreted.
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
        publishEvent(conn.allocator, ctx.publisher(), client_addr_opt orelse "", helo, mail_from, result_str, domain);
        // No smtp.client-ip on this path: the value is either absent or is a
        // string that is not an address, and neither belongs in the header.
        addArHeader(conn, ctx.authserv_id, result_str, reason, domain, helo, null) catch |err|
            return auth_stamp.deferCode(err, "spf");
        return @intFromEnum(responses.Code.accept);
    }
    const client_addr = client_addr_opt.?;

    // Check whitelist — skip SPF for trusted hosts.
    const whitelisted = if (ctx.whitelist) |wl| wl.contains(client_addr) else false;
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
        addArHeader(conn, ctx.authserv_id, "pass", "client is whitelisted", extractDomain(mail_from), helo, client_addr) catch |err|
            return auth_stamp.deferCode(err, "spf");
        return @intFromEnum(responses.Code.accept);
    }

    // Perform SPF evaluation
    const resolver = ctx.resolver();

    const eval_ctx = evaluate.EvalContext{
        .client_ip = client_addr,
        .is_ipv6 = mem.indexOfScalar(u8, client_addr, ':') != null,
        .sender = mail_from,
        .helo_domain = helo,
        .receiver_host = ctx.authserv_id,
    };

    const result = evaluate.evaluateWithLimits(conn.allocator, resolver, &eval_ctx, ctx.eval_limits);
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
    publishEvent(conn.allocator, ctx.publisher(), client_addr, helo, mail_from, result_str, domain);

    addArHeader(conn, ctx.authserv_id, result_str, null, domain, helo, client_addr) catch |err|
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
/// Must stay fallible (audit X-9): swallowing a failure and returning `accept`
/// unconditionally would deliver the message with **no `spf=` field** while
/// this daemon reported success, and `securedmarc` would go on to compute a
/// DMARC verdict from the evidence that survived. A message that would have
/// passed on an aligned SPF pass could then be rejected under `p=reject`
/// because this host could not allocate a header.
///
/// A local fault is not charged to the sender: if the result cannot be recorded,
/// the message is deferred and the sender retries.
fn addArHeader(
    conn: *connection_mod.Connection,
    authserv_id: []const u8,
    result_str: []const u8,
    reason: ?[]const u8,
    domain: []const u8,
    helo: []const u8,
    client_ip: ?[]const u8,
) !void {
    // smtp.client-ip records the address the verdict was computed FROM. Without
    // it an A-R header says "spf=fail" but not *of whom*, and the only remaining
    // record is a log line on this host. Omitted rather than written empty when
    // the address is missing or malformed -- the property asserts an address
    // existed.
    //
    // An IPv6 address contains ':', outside the pvalue token set, so the builder
    // renders it quoted (smtp.client-ip="fd10:99::254"). That is RFC 8601 §2.2
    // quoted-string form, not a defect.
    var properties: [3]auth_results.MethodResult.Property = undefined;
    var prop_count: usize = 0;
    if (client_ip) |ip| {
        properties[prop_count] = .{ .ptype = "smtp", .property = "client-ip", .value = ip };
        prop_count += 1;
    }
    properties[prop_count] = .{ .ptype = "smtp", .property = "mailfrom", .value = domain };
    prop_count += 1;
    properties[prop_count] = .{ .ptype = "smtp", .property = "helo", .value = helo };
    prop_count += 1;

    try auth_stamp.stamp(conn.allocator, conn.fd, authserv_id, &.{
        .{
            .method = "spf",
            .result = result_str,
            .reason = reason,
            .properties = properties[0..prop_count],
        },
    }, conn.negotiated_protocol.header_leading_space);
}

fn publishEvent(
    allocator: Allocator,
    publisher: *zmq.Publisher,
    client_ip: []const u8,
    helo: []const u8,
    mail_from: []const u8,
    result_str: []const u8,
    domain: []const u8,
) void {
    // Every value but `result_str` comes from the sender or from rDNS. An
    // unescaped `"` in any of them would end the JSON string early and leave
    // the rest of the payload to be reinterpreted, so the consumer --
    // SecureMessageWebhooks -- would receive either invalid JSON or fields the
    // sender chose (audit X-5).
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

    publisher.publish(json);
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
// Tests
// =============================================================================

test "extract domain from mail from" {
    try std.testing.expectEqualStrings("example.com", extractDomain("<user@example.com>"));
    try std.testing.expectEqualStrings("example.com", extractDomain("user@example.com"));
    try std.testing.expectEqualStrings("", extractDomain("<>"));
    try std.testing.expectEqualStrings("postmaster", extractDomain("postmaster"));
}

test "the A-R stamp records smtp.client-ip, quoted for IPv6, omitted when absent" {
    // The property is what ties a verdict to an address once the message has
    // left this host. Three cases: a bare IPv4 pvalue, an IPv6 address forced
    // into quoted-string form by the ':' bytes, and no property at all when the
    // connection carried no usable address (the none/permerror path).
    const posix = std.posix;
    const Case = struct { ip: ?[]const u8, want: ?[]const u8 };
    const cases = [_]Case{
        .{ .ip = "10.99.0.254", .want = "smtp.client-ip=10.99.0.254" },
        .{ .ip = "fd10:99::254", .want = "smtp.client-ip=\"fd10:99::254\"" },
        .{ .ip = null, .want = null },
    };
    for (cases) |c| {
        const fds = try posix.pipe2(.{ .NONBLOCK = true });
        defer posix.close(fds[0]);

        var conn = connection_mod.Connection.init(std.testing.allocator, fds[1], 0, .{});
        try addArHeader(&conn, "mail.test", "fail", null, "example.com", "relay.test", c.ip);
        conn.deinit(); // closes fds[1]

        var buf: [512]u8 = undefined;
        const n = try posix.read(fds[0], &buf);
        const packet = buf[0..n];
        try std.testing.expect(mem.indexOf(u8, packet, "spf=fail") != null);
        if (c.want) |w| {
            if (mem.indexOf(u8, packet, w) == null) {
                std.debug.print("WANT: {s}\nPACKET({d}): {s}\n", .{ w, n, packet });
            }
            try std.testing.expect(mem.indexOf(u8, packet, w) != null);
        } else {
            try std.testing.expect(mem.indexOf(u8, packet, "client-ip") == null);
        }
    }
}

// X-9: this wrapper must stay fallible.
//
// A stamping path that swallowed every failure and returned `accept` would
// deliver the message with no `spf=` field while reporting success, and
// `securedmarc` would then compute a DMARC verdict from the evidence that
// survived.
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
