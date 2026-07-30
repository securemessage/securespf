const std = @import("std");
const mem = std.mem;
const net = std.net;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");
const config = securemilter.config;
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
    /// The sender's own `exp=` text (RFC 7208 §6.2), meant for the SMTP
    /// rejection message. Not the same thing as `reason`.
    explanation: ?[]const u8,
    /// Why the evaluation ended early, when it did.
    ///
    /// A bare `spf=permerror` is four different faults wearing the same label:
    /// a malformed record, a term-limit blowout, a void-lookup blowout, and an
    /// `include` pointing at a domain with no policy. They need four different
    /// conversations — one with the sender, one with nobody — and the log line is
    /// where an operator looks to find out which. Always a static string, so it
    /// is safe to log verbatim and needs no lifetime management.
    reason: ?[]const u8 = null,
};

/// Bounds on a single SPF evaluation.
///
/// The processing limits in RFC 7208 §4.6.4 exist because an SPF record is a
/// program supplied by the sender: `include` and `redirect` are calls, and a
/// hostile or merely broken record can otherwise direct a receiver to make an
/// unbounded number of DNS queries per message.
pub const Limits = struct {
    /// DNS-querying terms per evaluation. RFC 7208 §4.6.4 fixes this at 10 and
    /// the value is not configurable, because it is what senders design against.
    pub const MAX_TERMS: usize = 10;

    /// Records examined inside one `mx` or `ptr` mechanism. Also fixed at 10 by
    /// §4.6.4, and counted *separately* from the term budget.
    pub const MAX_RECORDS_PER_MECHANISM: usize = 10;

    /// Terms whose lookup finds nothing. RFC 7208 §4.6.4 makes this a SHOULD, so
    /// unlike the term limit it is configurable.
    max_void_lookups: usize = 2,

    /// Wall-clock ceiling for one evaluation. §4.6.4 asks for a time limit
    /// without naming a number; the RFC 7208 §10.1 guidance of 20 seconds for
    /// the whole check is the closest thing to a specified value.
    max_duration_ms: i64 = 20_000,

    pub const OPTION_VOID_LOOKUPS = "MaxVoidLookups";
    pub const OPTION_DURATION_MS = "MaxEvaluationMs";

    /// Read the configurable limits from a config section.
    ///
    /// `0` disables a limit, matching the `Max*` convention the rest of the suite
    /// uses. These are resource limits, not the RFC 8301 key-size floor, so
    /// switching one off is a legitimate operator choice rather than a way to
    /// re-admit something a standard forbids.
    ///
    /// An unparseable value falls back to the default instead of becoming zero,
    /// because a typo silently removing a limit is the one outcome nobody wants.
    pub fn fromSection(section: *const config.Config.Section) Limits {
        const defaults = Limits{};
        return .{
            .max_void_lookups = section.getInt(OPTION_VOID_LOOKUPS, usize, defaults.max_void_lookups),
            .max_duration_ms = section.getInt(OPTION_DURATION_MS, i64, defaults.max_duration_ms),
        };
    }
};

/// Conditions that end an evaluation early.
///
/// These are separate from `spf.Result` so they cannot be silently dropped: a
/// mechanism that swallowed a DNS failure and answered "did not match" would let
/// a transient outage carry the evaluation on to a `-all` and reject mail that
/// should have been deferred.
const EvalError = error{
    /// More than `Limits.MAX_TERMS` DNS-querying terms. RFC 7208 §4.6.4: permerror.
    TermLimitExceeded,
    /// More than `Limits.MAX_RECORDS_PER_MECHANISM` records examined inside one
    /// `mx` mechanism. §4.6.4 names permerror for that case specifically, and
    /// keeping it distinct from `TermLimitExceeded` means the log says which of
    /// the two budgets a record actually blew.
    MechanismRecordLimitExceeded,
    /// More than `max_void_lookups` terms found nothing. §4.6.4: permerror.
    VoidLookupLimitExceeded,
    /// `include`/`redirect` reached a domain with no usable SPF record.
    /// §5.2 and §6.1: permerror.
    NoRecordAtTarget,
    /// Syntax error in a record. §4.6: permerror.
    RecordSyntax,
    /// DNS said "ask again later". §4.4: temperror.
    DnsTransient,
    /// The evaluation ran out of wall-clock budget. temperror, so the sender
    /// retries rather than being judged on an incomplete evaluation.
    Timeout,
    /// Allocation failed part-way through. temperror: the verdict was never
    /// computed, so publishing one would be publishing a guess. Carried in the
    /// error set rather than collapsed into `RecordSyntax` because a permerror
    /// blames the sender for a fault on this side of the connection.
    OutOfMemory,
};

fn errorToResult(err: EvalError) spf.Result {
    return switch (err) {
        error.TermLimitExceeded,
        error.MechanismRecordLimitExceeded,
        error.VoidLookupLimitExceeded,
        error.NoRecordAtTarget,
        error.RecordSyntax,
        => .permerror,
        error.DnsTransient, error.Timeout, error.OutOfMemory => .temperror,
    };
}

/// A short, static account of why an evaluation stopped.
///
/// The RFC section is in the text on purpose: the operator reading this line is
/// about to have to explain to a sender why their mail was refused, and the
/// citation is the difference between "our filter did not like it" and a
/// specific, fixable defect in their record.
fn errorToReason(err: EvalError) []const u8 {
    return switch (err) {
        error.TermLimitExceeded => "more than 10 DNS-querying terms (RFC 7208 4.6.4)",
        error.MechanismRecordLimitExceeded => "more than 10 records in one mechanism (RFC 7208 4.6.4)",
        error.VoidLookupLimitExceeded => "too many void DNS lookups (RFC 7208 4.6.4)",
        error.NoRecordAtTarget => "include or redirect target publishes no SPF record (RFC 7208 5.2, 6.1)",
        error.RecordSyntax => "malformed SPF record (RFC 7208 4.6)",
        error.DnsTransient => "DNS lookup failed transiently (RFC 7208 4.4)",
        error.Timeout => "evaluation exceeded its time budget (RFC 7208 4.6.4)",
        error.OutOfMemory => "receiver out of memory",
    };
}

/// How the evaluation arrived at a domain.
///
/// RFC 7208 makes one DNS fact mean two different things. A domain with no
/// usable SPF record is `none` when it is the domain being checked (§4.3), and a
/// permerror when an `include` (§5.2) or a `redirect` (§6.1) sent us there.
/// Nothing in the DNS answer distinguishes the two — only the path taken to it —
/// so the path is passed in rather than guessed at from the answer.
const Arrival = enum { checked_domain, directed };

/// The four values every mechanism needs, bound once for the whole evaluation.
///
/// Each `match*` used to take `(allocator, resolver, ctx, domain, directive, state)`.
/// Six parameters, of which four never vary across a single `check_host()` — and
/// `matchExists` listed those four in a **different order** from its five siblings,
/// so the convention a reader relies on was already broken. The types differed
/// enough that a swap would not compile, which is luck rather than a design.
///
/// Passed by value: it is four words, and every field is either a pointer or an
/// allocator, so copying it copies no state. `state` stays a pointer because the term
/// and void-lookup budgets must be shared across the whole recursive walk — an
/// `include` that spent five lookups has to be visible to the caller that resumes
/// after it.
const Eval = struct {
    allocator: Allocator,
    resolver: *dns.Resolver,
    ctx: *const EvalContext,
    state: *EvalState,
};

/// Accounting for one evaluation.
///
/// This was a bare `*usize` threaded through every mechanism, which put the
/// burden on each DNS-issuing site to remember both to increment it and to
/// compare it against the limit — and gave the void-lookup count nowhere to
/// live at all. Every query now goes through `query()`, so a mechanism added
/// later is accounted for whether or not its author thought about limits.
const EvalState = struct {
    limits: Limits,
    /// DNS-querying terms consumed so far.
    terms: usize = 0,
    /// Terms whose lookup found nothing.
    void_lookups: usize = 0,
    deadline_ms: i64,

    fn init(limits: Limits) EvalState {
        return .{
            .limits = limits,
            .deadline_ms = if (limits.max_duration_ms == 0)
                std.math.maxInt(i64)
            else
                std.time.milliTimestamp() + limits.max_duration_ms,
        };
    }

    fn expired(self: *const EvalState) bool {
        return std.time.milliTimestamp() >= self.deadline_ms;
    }

    /// Charge one DNS-querying term against the RFC 7208 §4.6.4 budget.
    ///
    /// Called before the query rather than after, so a record cannot buy an
    /// extra lookup by being the one that trips the limit.
    fn chargeTerm(self: *EvalState) EvalError!void {
        if (self.expired()) return error.Timeout;
        self.terms += 1;
        if (self.terms > Limits.MAX_TERMS) return error.TermLimitExceeded;
    }

    fn noteVoid(self: *EvalState) EvalError!void {
        self.void_lookups += 1;
        if (self.limits.max_void_lookups == 0) return;
        if (self.void_lookups > self.limits.max_void_lookups) {
            return error.VoidLookupLimitExceeded;
        }
    }

    /// Issue a DNS query as part of the current evaluation.
    ///
    /// Returns `null` for a *void lookup* — an authoritative "no such name" or an
    /// empty answer section — which RFC 7208 §4.6.4 counts and which means the
    /// mechanism simply does not match. A transient failure is returned as an
    /// error instead, because the only correct answer to one is `temperror`;
    /// treating it as a non-match is what lets a nameserver blip turn into a
    /// rejection.
    fn query(
        self: *EvalState,
        resolver: *dns.Resolver,
        name: []const u8,
        rtype: dns.RecordType,
    ) EvalError!?dns.resolver.Result {
        if (self.expired()) return error.Timeout;

        var result = resolver.resolve(name, rtype) catch |err| {
            if (dns.isTransientError(err)) return error.DnsTransient;
            try self.noteVoid();
            return null;
        };
        if (result.answers.len == 0) {
            result.deinit();
            try self.noteVoid();
            return null;
        }
        return result;
    }

    /// Issue a query that belongs to a term already charged.
    ///
    /// Used for the address lookups inside `mx` and the forward confirmation
    /// inside `ptr`. These are deliberately *not* counted as void lookups:
    /// RFC 7208 §4.6.4 limits the number of "terms" that resolve to nothing, and
    /// a term here is the whole mechanism. Counting each sub-query instead would
    /// mean a domain whose MX hosts are IPv6-only trips the limit of two on an
    /// IPv4 connection and gets a permerror for a perfectly valid record.
    ///
    /// Transient failures still propagate, and the deadline still applies.
    fn querySub(
        self: *EvalState,
        resolver: *dns.Resolver,
        name: []const u8,
        rtype: dns.RecordType,
    ) EvalError!?dns.resolver.Result {
        if (self.expired()) return error.Timeout;

        var result = resolver.resolve(name, rtype) catch |err| {
            if (dns.isTransientError(err)) return error.DnsTransient;
            return null;
        };
        if (result.answers.len == 0) {
            result.deinit();
            return null;
        }
        return result;
    }
};

/// Evaluate SPF for the given context.
///
/// 1. Extract domain from sender (or use HELO domain for null sender)
/// 2. DNS lookup TXT records for the domain
/// 3. Parse SPF record
/// 4. Walk directives, resolving DNS for a/mx/include/exists/ptr
/// 5. Enforce the RFC 7208 §4.6.4 processing limits
/// 6. Handle redirect modifier
pub fn evaluate(
    allocator: Allocator,
    resolver: *dns.Resolver,
    ctx: *const EvalContext,
) EvalResult {
    return evaluateWithLimits(allocator, resolver, ctx, .{});
}

/// Room for the longest dotted-quad, "255.255.255.255".
const ip4_text_max = 15;

/// The embedded IPv4 address of an IPv4-mapped IPv6 address, in dotted-quad form.
///
/// Returns `null` for anything else, including the IPv4-*translated* prefix
/// `::ffff:0:0:0/96` of RFC 2765, which looks similar and is a different thing.
fn mappedIp4(ip: []const u8, buf: []u8) ?[]const u8 {
    // Only an address written in IPv6 form can be mapped.
    if (mem.indexOfScalar(u8, ip, ':') == null) return null;
    const octets = spf.parseIp6Bytes(ip) catch return null;

    // RFC 4291 §2.5.5.2: 80 zero bits, then 16 one bits, then the address.
    if (!mem.allEqual(u8, octets[0..10], 0)) return null;
    if (octets[10] != 0xFF or octets[11] != 0xFF) return null;

    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{
        octets[12], octets[13], octets[14], octets[15],
    }) catch null;
}

pub fn evaluateWithLimits(
    allocator: Allocator,
    resolver: *dns.Resolver,
    raw_ctx: *const EvalContext,
    limits: Limits,
) EvalResult {
    // RFC 7208 §5: "IP4 mapped IP6 connections MUST be treated as IP4".
    //
    // Done once here rather than inside each mechanism, because the requirement
    // is about the connection and so reaches everything downstream: `ip4:` has to
    // compare against the embedded address, `ip6:` must not match at all, `a` and
    // `mx` have to fetch A records rather than AAAA, an ip6-cidr-length stops
    // applying, and `%{i}`/`%{v}` have to expand in their IPv4 forms. Patching
    // the mechanisms individually would be the same one-rule-in-many-places
    // mistake that produced D-1, A-5 and D-15.
    //
    // The buffer lives for the whole evaluation because every caller below
    // borrows `client_ip` rather than copying it.
    var mapped_buf: [ip4_text_max]u8 = undefined;
    var normalized = raw_ctx.*;
    if (raw_ctx.is_ipv6) {
        if (mappedIp4(raw_ctx.client_ip, &mapped_buf)) |dotted| {
            normalized.client_ip = dotted;
            normalized.is_ipv6 = false;
        }
    }
    // The parameter is the one with the awkward name so that `ctx` -- the name
    // every line below reaches for by reflex -- is the corrected context. Zig
    // cannot shadow a parameter, and an earlier draft of this function did leave
    // one call site reading the un-normalized address, which silently undid the
    // whole fix.
    const ctx = &normalized;

    // Determine check domain: from MAIL FROM or fall back to HELO
    const domain = extractCheckDomain(ctx);
    if (domain.len == 0) {
        return .{ .result = .none, .domain = "", .explanation = null };
    }

    var state = EvalState.init(limits);

    // The one place the four invariants exist as separate values. Everything below
    // takes them as a unit, so `ctx` here is guaranteed to be the *normalized* one --
    // the mistake the comment above describes cannot be made once per call site,
    // because there is only one site.
    const ev = Eval{
        .allocator = allocator,
        .resolver = resolver,
        .ctx = ctx,
        .state = &state,
    };

    const result = evaluateDomain(ev, domain, .checked_domain) catch |err| {
        // The top level is the only place an evaluation error becomes a result,
        // which keeps the mapping in one auditable spot.
        return .{
            .result = errorToResult(err),
            .domain = domain,
            .explanation = null,
            .reason = errorToReason(err),
        };
    };
    return .{ .result = result, .domain = domain, .explanation = null };
}

/// Recursive SPF evaluation for a specific domain.
fn evaluateDomain(ev: Eval, domain: []const u8, arrival: Arrival) EvalError!spf.Result {
    if (ev.state.expired()) return error.Timeout;

    // Fetch SPF record via DNS TXT lookup. The query for the checked domain is
    // not a "term" under §4.6.4 -- only the mechanisms are -- so it is
    // deliberately not charged against the term budget, though it is still
    // subject to the deadline and still counts as a void lookup if it finds
    // nothing, because an `include` chain is exactly how that query gets
    // amplified.
    const maybe = try ev.state.query(ev.resolver, domain, .TXT);
    if (maybe == null) return noRecord(arrival);
    var dns_result = maybe.?;
    defer dns_result.deinit();

    // Find the SPF record among TXT results
    var txt_iter = dns_result.txtRecords();
    var spf_txt: ?[]const u8 = null;
    while (txt_iter.next()) |txt| {
        if (spf.isSpf1(txt)) {
            // RFC 7208 §4.5: more than one v=spf1 record is a permerror.
            if (spf_txt != null) return error.RecordSyntax;
            spf_txt = txt;
        }
    }

    const record_txt = spf_txt orelse return noRecord(arrival);

    // Parse the SPF record
    var record = spf.parseRecord(ev.allocator, record_txt) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.RecordSyntax,
    };
    defer record.deinit(ev.allocator);

    // Walk directives
    for (record.directives.items) |directive| {
        if (try matchDirective(ev, domain, directive)) {
            return directive.qualifier.toResult();
        }
    }

    // If no directive matched, check redirect modifier
    if (record.redirect) |redirect_template| {
        try ev.state.chargeTerm();
        const target = try expandDomainSpec(ev, domain, redirect_template);
        defer ev.allocator.free(target);
        // RFC 7208 §6.1: no record at the redirect target is a permerror, not a
        // `none` that would let the message through unjudged.
        return evaluateDomain(ev, target, .directed);
    }

    // Default result when no directives match and no redirect: neutral
    return .neutral;
}

/// What "this domain publishes no usable SPF record" means, given how we got here.
fn noRecord(arrival: Arrival) EvalError!spf.Result {
    return switch (arrival) {
        // RFC 7208 §4.3: the checked domain having no record is not an error,
        // it is the absence of a policy.
        .checked_domain => .none,
        // §5.2 and §6.1: a record that points at a domain with no policy is a
        // broken record, and saying `none` here would discard the sender's own
        // `-all` along with it.
        .directed => error.NoRecordAtTarget,
    };
}

/// Check if a single directive matches the client.
fn matchDirective(ev: Eval, domain: []const u8, directive: spf.Directive) EvalError!bool {
    return switch (directive.mechanism) {
        .all => true,
        .ip4 => matchIp4(ev.ctx, directive),
        .ip6 => matchIp6(ev.ctx, directive),
        .a => matchA(ev, domain, directive),
        .mx => matchMx(ev, domain, directive),
        .include => matchInclude(ev, domain, directive),
        .exists => matchExists(ev, domain, directive),
        .ptr => matchPtr(ev, domain, directive),
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
    // Both addresses go through the same RFC 4291 parser the record was validated
    // with, so a literal accepted at parse time cannot be read differently here.
    const client = spf.parseIp6Bytes(ctx.client_ip) catch return false;
    const network = spf.parseIp6Bytes(arg) catch return false;
    return matchIp6Cidr(client, network, prefix_len);
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

/// Expand a domain-spec against the evaluation context.
///
/// **Every** term carrying a domain-spec goes through here: `a`, `mx`, `ptr`,
/// `exists`, `include` and `redirect`. Only `exists` used to expand, so the other
/// five queried the macro's literal characters -- `a:%{H}` looked up the name
/// "%{H}" and `redirect=%{d}.d.spf.example.com` the name "%{d}.d.spf.example.com".
/// The name resolved was never the name the record named.
///
/// This is the fifth rule found implemented in several places and honoured in only
/// some, after D-1, A-5, D-15 and the macro-less mechanisms above, which is why
/// there is one function rather than six call sites.
///
/// Caller owns the returned memory.
fn expandDomainSpec(ev: Eval, domain: []const u8, template: []const u8) EvalError![]u8 {
    // `%{p}` costs a reverse lookup and a forward confirmation per candidate, so it
    // is resolved only when a template actually asks for it. Everything else in the
    // macro set is derived from the context we already hold.
    var validated: ?[]u8 = null;
    defer if (validated) |v| ev.allocator.free(v);
    if (usesValidatedDomain(template)) {
        validated = try validatedDomain(ev, domain);
    }

    const macro_ctx = macro.Context{
        .sender = ev.ctx.sender,
        .domain = domain,
        .client_ip = ev.ctx.client_ip,
        .is_ipv6 = ev.ctx.is_ipv6,
        .validated_domain = validated orelse "unknown",
        .helo_domain = ev.ctx.helo_domain,
        .receiver_host = ev.ctx.receiver_host,
    };

    // A macro that will not expand is a defect in the record, and §4.6 makes a
    // syntax defect a permerror. Reporting "did not match" instead carries the
    // evaluation on to the record's own `-all` and rejects the mail on the
    // strength of a term that was never evaluated.
    return macro.expand(ev.allocator, template, &macro_ctx) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.RecordSyntax,
    };
}

/// Whether a domain-spec uses the `%{p}` macro, in either case.
fn usesValidatedDomain(template: []const u8) bool {
    var i: usize = 0;
    while (mem.indexOfScalarPos(u8, template, i, '%')) |at| {
        if (at + 2 < template.len and template[at + 1] == '{' and
            std.ascii.toLower(template[at + 2]) == 'p')
        {
            return true;
        }
        i = at + 1;
    }
    return false;
}

/// The name a mechanism's domain-spec refers to, defaulting to the current domain
/// for the mechanisms whose argument is optional.
fn expandTarget(ev: Eval, domain: []const u8, directive: spf.Directive) EvalError![]u8 {
    const template = directive.argument orelse return ev.allocator.dupe(u8, domain);
    return expandDomainSpec(ev, domain, template);
}

fn matchA(ev: Eval, domain: []const u8, directive: spf.Directive) EvalError!bool {
    try ev.state.chargeTerm();
    const target = try expandTarget(ev, domain, directive);
    defer ev.allocator.free(target);
    const prefix4 = directive.cidr4 orelse 32;
    const prefix6 = directive.cidr6 orelse 128;

    const rtype: dns.RecordType = if (ev.ctx.is_ipv6) .AAAA else .A;
    var result = (try ev.state.query(ev.resolver, target, rtype)) orelse return false;
    defer result.deinit();

    if (!ev.ctx.is_ipv6) {
        const client_bytes = spf.parseIp4Bytes(ev.ctx.client_ip) catch return false;
        for (result.answers) |ans| {
            if (ans.record_type == @intFromEnum(dns.RecordType.A) and ans.data.len >= 4) {
                if (spf.matchIp4Cidr(client_bytes, ans.data[0..4].*, prefix4)) return true;
            }
        }
    } else {
        const client = spf.parseIp6Bytes(ev.ctx.client_ip) catch return false;
        for (result.answers) |ans| {
            if (ans.record_type == @intFromEnum(dns.RecordType.AAAA) and ans.data.len >= 16) {
                if (matchIp6Cidr(client, ans.data[0..16].*, prefix6)) return true;
            }
        }
    }
    return false;
}

fn matchMx(ev: Eval, domain: []const u8, directive: spf.Directive) EvalError!bool {
    try ev.state.chargeTerm();
    const target = try expandTarget(ev, domain, directive);
    defer ev.allocator.free(target);
    const prefix4 = directive.cidr4 orelse 32;
    const prefix6 = directive.cidr6 orelse 128;

    var mx_result = (try ev.state.query(ev.resolver, target, .MX)) orelse return false;
    defer mx_result.deinit();

    const rtype: dns.RecordType = if (ev.ctx.is_ipv6) .AAAA else .A;

    // RFC 7208 §4.6.4 caps the records examined *inside* one `mx` at 10, as a
    // separate budget from the 10 terms. The previous code charged each MX host
    // to the term budget instead, so a domain with ten MX hosts spent the whole
    // evaluation allowance on a single valid mechanism.
    var records: usize = 0;

    for (mx_result.answers) |ans| {
        if (ans.record_type != @intFromEnum(dns.RecordType.MX)) continue;
        // MX data contains the exchange hostname
        const mx_host = ans.data;
        if (mx_host.len == 0) continue;

        records += 1;
        if (records > Limits.MAX_RECORDS_PER_MECHANISM) {
            return error.MechanismRecordLimitExceeded;
        }

        var addr_result = (try ev.state.querySub(ev.resolver, mx_host, rtype)) orelse continue;
        defer addr_result.deinit();

        if (!ev.ctx.is_ipv6) {
            const client_bytes = spf.parseIp4Bytes(ev.ctx.client_ip) catch return false;
            for (addr_result.answers) |a_ans| {
                if (a_ans.record_type == @intFromEnum(dns.RecordType.A) and a_ans.data.len >= 4) {
                    if (spf.matchIp4Cidr(client_bytes, a_ans.data[0..4].*, prefix4)) return true;
                }
            }
        } else {
            const client = spf.parseIp6Bytes(ev.ctx.client_ip) catch return false;
            for (addr_result.answers) |a_ans| {
                if (a_ans.record_type == @intFromEnum(dns.RecordType.AAAA) and a_ans.data.len >= 16) {
                    if (matchIp6Cidr(client, a_ans.data[0..16].*, prefix6)) return true;
                }
            }
        }
    }
    return false;
}

/// RFC 7208 §5.2 `include`.
///
/// The result table is not "pass or bust": a `temperror` inside the included
/// record has to surface as a `temperror` for the whole check, and a target with
/// no usable record is a permerror. Collapsing all of that to `result == .pass`
/// meant an outage at an included provider read as "did not match", so the
/// evaluation walked on to the sender's own `-all` and rejected the mail.
fn matchInclude(ev: Eval, domain: []const u8, directive: spf.Directive) EvalError!bool {
    const template = directive.argument orelse return false;
    try ev.state.chargeTerm();

    // Expanded against the domain whose record holds the include, not against the
    // included one, so `%{d}` means what the author wrote it next to.
    const target = try expandDomainSpec(ev, domain, template);
    defer ev.allocator.free(target);

    const result = try evaluateDomain(ev, target, .directed);
    return switch (result) {
        .pass => true,
        .fail, .softfail, .neutral => false,
        // evaluateDomain reports these as errors, so they cannot arrive here;
        // handled explicitly so adding a Result variant is a compile error
        // rather than a silent "did not match".
        .temperror => error.DnsTransient,
        .permerror => error.RecordSyntax,
        .none => error.NoRecordAtTarget,
    };
}

fn matchExists(ev: Eval, domain: []const u8, directive: spf.Directive) EvalError!bool {
    try ev.state.chargeTerm();

    const expanded = try expandTarget(ev, domain, directive);
    defer ev.allocator.free(expanded);

    // exists: any A record is a match. RFC 7208 §5.7 specifies an A query even
    // when the client is IPv6, which is why this does not branch on is_ipv6.
    var result = (try ev.state.query(ev.resolver, expanded, .A)) orelse return false;
    result.deinit();
    return true;
}

/// The `ip6.arpa` reverse name for an IPv6 address.
///
/// RFC 3596 §2.5: each of the 32 nibbles as a hex digit, least significant first,
/// dot-separated, under `ip6.arpa`.
fn reverseIp6Name(buf: []u8, octets: [16]u8) ?[]const u8 {
    const hex = "0123456789abcdef";
    const suffix = "ip6.arpa";
    if (buf.len < 32 * 2 + suffix.len) return null;

    var len: usize = 0;
    var i: usize = octets.len;
    while (i > 0) {
        i -= 1;
        buf[len] = hex[octets[i] & 0x0F];
        buf[len + 1] = '.';
        buf[len + 2] = hex[octets[i] >> 4];
        buf[len + 3] = '.';
        len += 4;
    }
    @memcpy(buf[len..][0..suffix.len], suffix);
    return buf[0 .. len + suffix.len];
}

/// The validated domain names of the client address.
const ValidatedNames = struct {
    names: std.ArrayListUnmanaged([]u8) = .{},
    allocator: Allocator,

    fn deinit(self: *ValidatedNames) void {
        for (self.names.items) |name| self.allocator.free(name);
        self.names.deinit(self.allocator);
    }
};

/// Collect the client address's validated domain names, per RFC 7208 §5.5.
///
/// A PTR name counts only once its forward lookup, in the address family the
/// connection actually used, contains the connecting address. The reverse zone is
/// controlled by whoever holds the address, so the PTR names are candidates and
/// nothing more until confirmed -- skipping the confirmation would let an address
/// owner claim any name.
///
/// §5.5 caps the names examined at 10, which is a budget separate from the term
/// count: without it a reverse zone returning hundreds of names would buy hundreds
/// of forward confirmations off a single mechanism.
fn validatedNames(ev: Eval) EvalError!ValidatedNames {
    var out = ValidatedNames{ .allocator = ev.allocator };
    errdefer out.deinit();

    var client4: [4]u8 = undefined;
    var client6: [16]u8 = undefined;
    var ptr_buf: [80]u8 = undefined;
    const ptr_name = if (ev.ctx.is_ipv6) blk: {
        client6 = spf.parseIp6Bytes(ev.ctx.client_ip) catch return out;
        break :blk reverseIp6Name(&ptr_buf, client6) orelse return out;
    } else blk: {
        client4 = spf.parseIp4Bytes(ev.ctx.client_ip) catch return out;
        break :blk std.fmt.bufPrint(&ptr_buf, "{d}.{d}.{d}.{d}.in-addr.arpa", .{
            client4[3], client4[2], client4[1], client4[0],
        }) catch return out;
    };

    var ptr_result = (try ev.state.query(ev.resolver, ptr_name, .PTR)) orelse return out;
    defer ptr_result.deinit();

    const fwd_type: dns.RecordType = if (ev.ctx.is_ipv6) .AAAA else .A;
    var records: usize = 0;

    for (ptr_result.answers) |ans| {
        if (ans.record_type != @intFromEnum(dns.RecordType.PTR)) continue;
        const candidate = ans.data;

        records += 1;
        if (records > Limits.MAX_RECORDS_PER_MECHANISM) break;

        var fwd_result = (try ev.state.querySub(ev.resolver, candidate, fwd_type)) orelse continue;
        defer fwd_result.deinit();

        for (fwd_result.answers) |fwd_ans| {
            if (fwd_ans.record_type != @intFromEnum(fwd_type)) continue;
            const matches = if (ev.ctx.is_ipv6)
                fwd_ans.data.len >= 16 and mem.eql(u8, fwd_ans.data[0..16], &client6)
            else
                fwd_ans.data.len >= 4 and mem.eql(u8, fwd_ans.data[0..4], &client4);
            if (matches) {
                try out.names.append(ev.allocator, try ev.allocator.dupe(u8, candidate));
                break;
            }
        }
    }
    return out;
}

/// The value of the `%{p}` macro.
///
/// RFC 7208 §7.2 builds it from the §5.5 validated names: prefer `domain` itself if
/// it is among them, then a subdomain of `domain`, then any of them. With none, or
/// on a DNS error, the value is the literal string "unknown".
///
/// §7.2 also says of this macro, in parentheses, "do not use". It costs a reverse
/// lookup plus a forward confirmation per candidate, and the candidate list is
/// chosen by whoever controls the reverse zone. It is implemented because a
/// verifier does not get to ignore a macro a record actually uses.
///
/// Caller owns the returned memory.
fn validatedDomain(ev: Eval, domain: []const u8) EvalError![]u8 {
    var validated = validatedNames(ev) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        // "If there are no validated domain names or if a DNS error occurs, the
        // string 'unknown' is used" -- so a lookup failure here must not become the
        // verdict for the whole evaluation.
        else => return ev.allocator.dupe(u8, "unknown"),
    };
    defer validated.deinit();

    if (validated.names.items.len == 0) return ev.allocator.dupe(u8, "unknown");

    for (validated.names.items) |name| {
        if (std.ascii.eqlIgnoreCase(name, domain)) return ev.allocator.dupe(u8, name);
    }
    for (validated.names.items) |name| {
        if (isSubdomainOf(name, domain)) return ev.allocator.dupe(u8, name);
    }
    return ev.allocator.dupe(u8, validated.names.items[0]);
}

fn matchPtr(ev: Eval, domain: []const u8, directive: spf.Directive) EvalError!bool {
    // RFC 7208 §5.5: ptr mechanism is NOT RECOMMENDED but MUST be implemented
    try ev.state.chargeTerm();

    const target_domain = try expandTarget(ev, domain, directive);
    defer ev.allocator.free(target_domain);

    // §5.5: the mechanism matches when any *validated* name for the client address
    // is the target domain or a subdomain of it. The validation itself is shared
    // with the `%{p}` macro, which §7.2 defines in terms of this same procedure.
    var validated = try validatedNames(ev);
    defer validated.deinit();

    for (validated.names.items) |name| {
        if (isSubdomainOf(name, target_domain)) return true;
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

test "void lookup limit trips on the third void term" {
    // RFC 7208 §4.6.4 SHOULD limit void lookups to two. The third must end the
    // evaluation rather than let a record keep spending DNS on names that do not
    // exist.
    var state = EvalState.init(.{ .max_void_lookups = 2 });
    try state.noteVoid();
    try state.noteVoid();
    try std.testing.expectError(error.VoidLookupLimitExceeded, state.noteVoid());
    try std.testing.expectEqual(spf.Result.permerror, errorToResult(error.VoidLookupLimitExceeded));
}

test "void lookup limit of zero disables the check" {
    // Consistent with the Max* convention: a resource limit an operator may
    // switch off, unlike the RFC 8301 key-size floor.
    var state = EvalState.init(.{ .max_void_lookups = 0 });
    for (0..100) |_| try state.noteVoid();
    try std.testing.expectEqual(@as(usize, 100), state.void_lookups);
}

test "term limit trips on the eleventh DNS-querying term" {
    var state = EvalState.init(.{});
    for (0..Limits.MAX_TERMS) |_| try state.chargeTerm();
    try std.testing.expectError(error.TermLimitExceeded, state.chargeTerm());
    try std.testing.expectEqual(spf.Result.permerror, errorToResult(error.TermLimitExceeded));
}

test "an exhausted deadline is a temperror, never a verdict" {
    // The distinction matters: answering `fail` because we ran out of time would
    // reject mail on an incomplete evaluation, while temperror asks the sender
    // to try again.
    var state = EvalState.init(.{ .max_duration_ms = 1 });
    std.Thread.sleep(5 * std.time.ns_per_ms);
    try std.testing.expect(state.expired());
    try std.testing.expectError(error.Timeout, state.chargeTerm());
    try std.testing.expectEqual(spf.Result.temperror, errorToResult(error.Timeout));
}

test "zero duration disables the deadline" {
    var state = EvalState.init(.{ .max_duration_ms = 0 });
    try std.testing.expectEqual(std.math.maxInt(i64), state.deadline_ms);
    try std.testing.expect(!state.expired());
}

test "limit and failure conditions map to the results RFC 7208 requires" {
    // Guards the classification itself: a transient DNS failure reported as
    // permerror would turn an outage into a permanent rejection, and a syntax
    // error reported as temperror would make broken records retry forever.
    try std.testing.expectEqual(spf.Result.permerror, errorToResult(error.NoRecordAtTarget));
    try std.testing.expectEqual(spf.Result.permerror, errorToResult(error.RecordSyntax));
    try std.testing.expectEqual(spf.Result.permerror, errorToResult(error.MechanismRecordLimitExceeded));
    try std.testing.expectEqual(spf.Result.temperror, errorToResult(error.DnsTransient));
    // An allocation failure is ours, not the sender's: a permerror here would
    // blame a record that may be perfectly valid, and DMARC would consume it.
    try std.testing.expectEqual(spf.Result.temperror, errorToResult(error.OutOfMemory));
}

test "every evaluation error carries a distinct reason" {
    // Two errors sharing a reason string would put the operator back where the
    // bare `spf=permerror` left them. The switch in errorToReason is exhaustive,
    // so a new error variant is a compile error; this catches the other failure
    // mode, which is copy-pasting an existing reason onto it.
    const all = [_]EvalError{
        error.TermLimitExceeded,
        error.MechanismRecordLimitExceeded,
        error.VoidLookupLimitExceeded,
        error.NoRecordAtTarget,
        error.RecordSyntax,
        error.DnsTransient,
        error.Timeout,
        error.OutOfMemory,
    };
    for (all, 0..) |err, i| {
        const reason = errorToReason(err);
        try std.testing.expect(reason.len > 0);
        for (all[i + 1 ..]) |other| {
            try std.testing.expect(!mem.eql(u8, reason, errorToReason(other)));
        }
    }
}

test "an early exit reports both a result and the reason for it" {
    // The reason travels on EvalResult rather than only reaching the log, so the
    // A-R header and the ZMQ event can use it later without re-deriving it.
    const ctx = EvalContext{
        .client_ip = "192.0.2.1",
        .is_ipv6 = false,
        // An empty sender with an empty HELO yields no domain to check, which is
        // the one path that returns before any evaluation happens: `none` with
        // nothing to explain.
        .sender = "",
        .helo_domain = "",
        .receiver_host = "mx.local",
    };
    const out = evaluateWithLimits(std.testing.allocator, undefined, &ctx, .{});
    try std.testing.expectEqual(spf.Result.none, out.result);
    try std.testing.expect(out.reason == null);
}

test "Limits.fromSection reads overrides and keeps defaults otherwise" {
    const source =
        \\MaxVoidLookups = 5
    ;
    var cfg = try config.parse(std.testing.allocator, source);
    defer cfg.deinit();

    const limits = Limits.fromSection(cfg.global().?);
    try std.testing.expectEqual(@as(usize, 5), limits.max_void_lookups);

    // An untouched option keeps the struct default rather than becoming zero,
    // which would silently switch the limit off.
    try std.testing.expectEqual((Limits{}).max_duration_ms, limits.max_duration_ms);
}

test "Limits.fromSection falls back to the default on an unparseable value" {
    const source =
        \\MaxVoidLookups = two
    ;
    var cfg = try config.parse(std.testing.allocator, source);
    defer cfg.deinit();

    const limits = Limits.fromSection(cfg.global().?);
    try std.testing.expectEqual((Limits{}).max_void_lookups, limits.max_void_lookups);
}

test "a missing record is none at the checked domain and permerror at a target" {
    // The same DNS fact, two RFC-mandated answers. Getting this backwards is
    // load-bearing in both directions: permerror at the checked domain would
    // manufacture an authentication failure for every domain that publishes no
    // SPF at all, and `none` at an include target would silently drop the
    // including record's own `-all`.
    try std.testing.expectEqual(spf.Result.none, try noRecord(.checked_domain));
    try std.testing.expectError(error.NoRecordAtTarget, noRecord(.directed));
}

test "term budget is not spent on records inside one mechanism" {
    // The mx and ptr mechanisms have their own 10-record allowance, and the
    // sub-queries they issue go through querySub, which charges no term. The
    // pre-S-2 code charged each MX host to the term budget instead, so a domain
    // with ten MX hosts permerrored on a single valid mechanism.
    var state = EvalState.init(.{});
    try state.chargeTerm(); // the `mx` term itself
    try std.testing.expectEqual(@as(usize, 1), state.terms);

    // Nine terms remain for the rest of the record.
    for (0..Limits.MAX_TERMS - 1) |_| try state.chargeTerm();
    try std.testing.expectError(error.TermLimitExceeded, state.chargeTerm());
}

test "sub-queries inside a mechanism are not counted as void lookups" {
    // A domain whose MX hosts are IPv6-only answers nothing to the A queries an
    // IPv4 connection makes. Counting each of those as a void lookup would trip
    // the limit of two on the third host and permerror a valid record, which is
    // why querySub deliberately does not call noteVoid.
    var state = EvalState.init(.{ .max_void_lookups = 2 });
    try state.chargeTerm();
    try std.testing.expectEqual(@as(usize, 0), state.void_lookups);
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
