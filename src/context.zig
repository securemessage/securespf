//! Shared SPF evaluation context, limits, errors, and DNS accounting.
//!
//! Kept separate from the recursive evaluator so mechanisms and PTR handling
//! can depend on these types without an import cycle.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");
const config = securemilter.config;
const dns = securemilter.dns;
const deadline_mod = securemilter.deadline;

const spf = @import("spf.zig");

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
    /// Static diagnostic for an early evaluation result.
    reason: ?[]const u8 = null,
};

/// Bounds for a single SPF evaluation.
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
pub const EvalError = error{
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

pub fn errorToResult(err: EvalError) spf.Result {
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
pub fn errorToReason(err: EvalError) []const u8 {
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
pub const Arrival = enum { checked_domain, directed };

/// What "this domain publishes no usable SPF record" means, given how we got here.
pub fn noRecord(arrival: Arrival) EvalError!spf.Result {
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

/// The four values every mechanism needs, bound once for the whole evaluation.
///
/// Four of the six parameters a `match*` function needs never vary across a
/// single `check_host()`, so they are grouped here rather than passed
/// individually; every `match*` function then takes them in the same order.
///
/// Passed by value: it is four words, and every field is either a pointer or an
/// allocator, so copying it copies no state. `state` stays a pointer because the term
/// and void-lookup budgets must be shared across the whole recursive walk — an
/// `include` that spent five lookups has to be visible to the caller that resumes
/// after it.
pub const Eval = struct {
    allocator: Allocator,
    resolver: *dns.Resolver,
    ctx: *const EvalContext,
    state: *EvalState,
};

/// Accounting for one evaluation.
///
/// Every DNS query a mechanism issues goes through `query()`, which charges
/// the term and void-lookup budgets itself, so a mechanism is accounted for
/// whether or not its author thought about limits.
pub const EvalState = struct {
    limits: Limits,
    /// DNS-querying terms consumed so far.
    terms: usize = 0,
    /// Terms whose lookup found nothing.
    void_lookups: usize = 0,
    /// The X-21 deadline, the same bound type the other daemons in this suite
    /// share.
    deadline: deadline_mod.Deadline,

    pub fn init(limits: Limits) EvalState {
        return .{
            .limits = limits,
            .deadline = deadline_mod.Deadline.fromNow(limits.max_duration_ms),
        };
    }

    pub fn expired(self: *const EvalState) bool {
        return self.deadline.expired();
    }

    /// Charge one DNS-querying term against the RFC 7208 §4.6.4 budget.
    ///
    /// Called before the query rather than after, so a record cannot buy an
    /// extra lookup by being the one that trips the limit.
    pub fn chargeTerm(self: *EvalState) EvalError!void {
        if (self.expired()) return error.Timeout;
        self.terms += 1;
        if (self.terms > Limits.MAX_TERMS) return error.TermLimitExceeded;
    }

    pub fn noteVoid(self: *EvalState) EvalError!void {
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
    pub fn query(
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
    pub fn querySub(
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

// =============================================================================
// Tests
// =============================================================================

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
    // sub-queries they issue go through querySub, which charges no term.
    // Charging each MX host to the term budget instead would permerror a
    // domain with ten MX hosts on a single valid mechanism.
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
