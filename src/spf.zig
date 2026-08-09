const std = @import("std");
const mem = std.mem;
const net = std.net;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");

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

/// Everything that makes a record syntactically invalid.
///
/// Distinguished rather than collapsed into one error so that a future change can
/// say *why* a record was rejected. RFC 7208 gives no way to carry that to the
/// sender -- permerror has no reason field -- but the operator running the daemon
/// still has to diagnose it, which is the same argument as D-17.
pub const ParseError = error{
    NotSpf1,
    UnknownMechanism,
    MissingArgument,
    UnexpectedArgument,
    UnexpectedCidr,
    InvalidCidr,
    InvalidIp,
    InvalidDomainSpec,
    InvalidMacro,
    InvalidModifier,
    DuplicateModifier,
    OutOfMemory,
};

/// Parse an SPF TXT record string.
///
/// The input must start with "v=spf1" followed by directives/modifiers.
///
/// **Every term is checked here, including terms evaluation will never reach.**
/// RFC 7208 §4.6 requires the whole record to satisfy the grammar before it is
/// used at all: "If the <domain>'s DNS record ... cannot be interpreted ... then
/// check_host() produces the permerror result." A syntax error anywhere poisons
/// the record.
///
/// This used to validate lazily instead -- terms were accepted almost verbatim
/// and the mechanism handlers did `catch return false` when they turned out to be
/// malformed. At match time the only answer a handler can express is "does not
/// match", so a broken term became a silently skipped one. That produced 45
/// wrong verdicts in the RFC 7208 suite and one outright bypass: `v=spf1 include
/// +all` has no `:domain` on the include, which is a syntax error, and skipping
/// it left `+all` to authorize the world.
pub fn parseRecord(allocator: Allocator, txt: []const u8) ParseError!Record {
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

        if (try parseModifierTerm(term, &record)) continue;

        const directive = try parseDirective(term);
        try record.directives.append(allocator, directive);
    }

    return record;
}

/// Handle a term if it is a modifier, returning whether it was one.
///
///   modifier         = redirect / explanation / unknown-modifier
///   redirect         = "redirect" "=" domain-spec
///   explanation      = "exp" "=" domain-spec
///   unknown-modifier = name "=" macro-string
///   name             = ALPHA *( ALPHA / DIGIT / "-" / "_" / "." )
///
/// An unknown modifier is ignored, but only once it has been proven well formed:
/// §6 says a verifier ignores modifiers it does not recognise, not that it
/// ignores anything containing an "=". `1up=foo` is not a modifier at all,
/// because a name must start with a letter, and `foo=%abc` is not one either,
/// because `%a` is not a macro-expand. Both are permerror.
fn parseModifierTerm(term: []const u8, record: *Record) ParseError!bool {
    const eq = mem.indexOfScalar(u8, term, '=') orelse return false;
    const name = term[0..eq];
    const value = term[eq + 1 ..];

    // A directive's domain-spec may itself contain "=", so a term only looks like
    // a modifier when everything before the first "=" is a legal name. That also
    // keeps `a:foo=bar.example.com` a directive, and leaves `moo.cow:far_out=x`
    // to be rejected as an unknown mechanism.
    if (!validModifierName(name)) return false;

    if (std.ascii.eqlIgnoreCase(name, "redirect")) {
        // §6: "redirect" and "exp" MUST NOT appear in a record more than once.
        if (record.redirect != null) return error.DuplicateModifier;
        try validateDomainSpec(value);
        record.redirect = value;
        return true;
    }
    if (std.ascii.eqlIgnoreCase(name, "exp")) {
        if (record.explanation != null) return error.DuplicateModifier;
        // `exp` validated as domain-spec, without exp-only macro letters (c, r, t):
        // those are allowed in the resolved explanation text, not the name being resolved.
        try validateDomainSpec(value);
        record.explanation = value;
        return true;
    }

    _ = try validateMacroString(value, false);
    return true;
}

/// `name = ALPHA *( ALPHA / DIGIT / "-" / "_" / "." )` per RFC 7208 §12.
fn validModifierName(name: []const u8) bool {
    if (name.len == 0) return false;
    if (!std.ascii.isAlphabetic(name[0])) return false;
    for (name[1..]) |ch| {
        if (std.ascii.isAlphanumeric(ch)) continue;
        if (ch == '-' or ch == '_' or ch == '.') continue;
        return false;
    }
    return true;
}

/// Check if a TXT record is a valid SPF v1 record.
pub fn isSpf1(txt: []const u8) bool {
    if (txt.len < 6) return false;
    if (!std.ascii.eqlIgnoreCase(txt[0..6], "v=spf1")) return false;
    if (txt.len == 6) return true;
    return txt[6] == ' ' or txt[6] == '\t';
}

fn isAllDigits(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |ch| {
        if (!std.ascii.isDigit(ch)) return false;
    }
    return true;
}

/// Parse the digits of an ip4-cidr-length or ip6-cidr-length.
///
///   ip4-cidr-length = "/" ( "0" / %x31-39 0*1DIGIT )   ; value range 0-32
///   ip6-cidr-length = "/" ( "0" / %x31-39 0*2DIGIT )   ; value range 0-128
///
/// Spelled out digit by digit in RFC 7208 §5, and the spelling carries two rules
/// a range check alone misses: "0" stands alone, so anything longer must start
/// 1-9 and a leading zero is a syntax error rather than another way to write the
/// number, and the digit count itself is capped. `ip4:1.2.3.4/032` is invalid;
/// treating it as 32 is what let it return pass.
fn parseCidrLength(digits: []const u8, max: u8, max_digits: usize) ParseError!u8 {
    if (digits.len == 0 or digits.len > max_digits) return error.InvalidCidr;
    if (!isAllDigits(digits)) return error.InvalidCidr;
    if (digits.len > 1 and digits[0] == '0') return error.InvalidCidr;
    const value = std.fmt.parseInt(u8, digits, 10) catch return error.InvalidCidr;
    if (value > max) return error.InvalidCidr;
    return value;
}

const DualCidr = struct {
    /// The term with any dual-cidr-length removed.
    body: []const u8,
    cidr4: ?u8 = null,
    cidr6: ?u8 = null,
};

/// Split a trailing `dual-cidr-length` off an `a` or `mx` term.
///
///   dual-cidr-length = [ ip4-cidr-length ] [ "/" ip6-cidr-length ]
///
/// Scanned from the end, and accepted only when the tail really matches the cidr
/// grammar, because a domain-spec may legitimately contain "/" -- macro-literal is
/// %x21-24 / %x26-7E, which includes it. Splitting on the *first* "/" instead, as
/// this code used to, truncates the domain of `a:foo/bar.example.com` and
/// evaluates a name the record never named.
fn splitDualCidr(term: []const u8) ParseError!DualCidr {
    var out = DualCidr{ .body = term };

    const last = mem.lastIndexOfScalar(u8, out.body, '/') orelse return out;
    const tail = out.body[last + 1 ..];
    // Not digits, so not a cidr-length: it belongs to the domain-spec.
    if (!isAllDigits(tail)) return out;

    if (last > 0 and out.body[last - 1] == '/') {
        out.cidr6 = try parseCidrLength(tail, 128, 3);
        out.body = out.body[0 .. last - 1];

        // An ip4-cidr-length may precede the ip6 one, as in "a/24//64".
        if (mem.lastIndexOfScalar(u8, out.body, '/')) |prev| {
            const tail4 = out.body[prev + 1 ..];
            if (isAllDigits(tail4)) {
                out.cidr4 = try parseCidrLength(tail4, 32, 2);
                out.body = out.body[0..prev];
            }
        }
    } else {
        out.cidr4 = try parseCidrLength(tail, 32, 2);
        out.body = out.body[0..last];
    }
    return out;
}

/// `toplabel` per RFC 7208 §7.1.
///
///   toplabel = ( *alphanum ALPHA *alphanum )
///            / ( 1*alphanum "-" *( alphanum / "-" ) alphanum )
///
/// Both alternatives require at least one letter, so an all-numeric toplabel is a
/// syntax error -- that is what stops `a:111.222.33.44` being queried as a domain
/// -- and neither permits a leading or trailing "-".
fn validToplabel(label: []const u8) bool {
    if (label.len == 0) return false;
    if (label[0] == '-' or label[label.len - 1] == '-') return false;

    var has_alpha = false;
    for (label) |ch| {
        if (std.ascii.isAlphabetic(ch)) {
            has_alpha = true;
        } else if (!std.ascii.isDigit(ch) and ch != '-') {
            return false;
        }
    }
    return has_alpha;
}

fn isMacroDelimiter(ch: u8) bool {
    return switch (ch) {
        '.', '-', '+', ',', '/', '_', '=' => true,
        else => false,
    };
}

/// Length of the `macro-expand` at the start of `s`, which must begin with "%".
///
///   macro-expand = ( "%{" macro-letter transformers *delimiter "}" )
///                / "%%" / "%_" / "%-"
///   macro-letter = "s"/"l"/"o"/"d"/"i"/"p"/"h"/"c"/"r"/"t"/"v"
///   transformers = *DIGIT [ "r" ]
///
/// `allow_exp_only` admits c, r and t, which §7.1 permits only in explanation
/// text. They are a syntax error in a domain-spec, including in the domain-spec
/// of the `exp=` modifier itself.
///
/// An uppercase letter is legal: §7.1 has uppercase expand as the lowercase
/// equivalent and then URL-escape it, which is why `a:%{H}` must be accepted.
fn macroExpandLength(s: []const u8, allow_exp_only: bool) ParseError!usize {
    if (s.len < 2) return error.InvalidMacro;
    switch (s[1]) {
        '%', '_', '-' => return 2,
        '{' => {},
        else => return error.InvalidMacro,
    }

    if (s.len < 4) return error.InvalidMacro;
    const letter = std.ascii.toLower(s[2]);
    if (mem.indexOfScalar(u8, "slodiphv", letter) == null) {
        if (mem.indexOfScalar(u8, "crt", letter) == null) return error.InvalidMacro;
        if (!allow_exp_only) return error.InvalidMacro;
    }

    var i: usize = 3;
    while (i < s.len and std.ascii.isDigit(s[i])) i += 1;
    if (i < s.len and (s[i] == 'r' or s[i] == 'R')) i += 1;
    while (i < s.len and isMacroDelimiter(s[i])) i += 1;

    if (i >= s.len or s[i] != '}') return error.InvalidMacro;
    return i + 1;
}

/// Validate a `macro-string`, reporting whether it ends with a macro-expand.
///
///   macro-string  = *( macro-expand / macro-literal )
///   macro-literal = %x21-24 / %x26-7E
///
/// A literal is therefore visible ASCII except "%". Anything else -- a control
/// character, or any octet with the high bit set -- makes the record a permerror
/// instead of a name to be looked up, which is what rejects a record carrying a
/// UTF-8 BOM or an embedded CR.
fn validateMacroString(s: []const u8, allow_exp_only: bool) ParseError!bool {
    var i: usize = 0;
    var ends_with_macro = false;
    while (i < s.len) {
        if (s[i] == '%') {
            i += try macroExpandLength(s[i..], allow_exp_only);
            ends_with_macro = true;
            continue;
        }
        if (s[i] < 0x21 or s[i] > 0x7E) return error.InvalidDomainSpec;
        ends_with_macro = false;
        i += 1;
    }
    return ends_with_macro;
}

/// Validate a `domain-spec` per RFC 7208 §7.1.
///
///   domain-spec = macro-string domain-end
///   domain-end  = ( "." toplabel [ "." ] ) / macro-expand
///
/// The `domain-end` is the half that is easy to miss and does most of the
/// rejecting: a name must finish either with a genuine toplabel or with a
/// macro-expand whose value is not knowable until evaluation. That is what makes
/// `a:museum` and `a:abc.123` syntax errors while `a:%{H}` and `include:_spfh.%{d2}`
/// are well formed.
fn validateDomainSpec(spec: []const u8) ParseError!void {
    if (spec.len == 0) return error.InvalidDomainSpec;

    if (try validateMacroString(spec, false)) return;

    var name = spec;
    // domain-end allows one trailing dot, which is not part of the toplabel.
    if (name[name.len - 1] == '.') name = name[0 .. name.len - 1];

    const dot = mem.lastIndexOfScalar(u8, name, '.') orelse return error.InvalidDomainSpec;
    if (!validToplabel(name[dot + 1 ..])) return error.InvalidDomainSpec;
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
    // The mechanism name runs to the first ":" or "/". Both characters may occur
    // again afterwards -- inside a domain-spec, or in an IPv6 literal -- so only
    // the first one delimits the name.
    const colon = mem.indexOfScalar(u8, rest, ':');
    const slash = mem.indexOfScalar(u8, rest, '/');
    const name_end = @min(colon orelse rest.len, slash orelse rest.len);

    const mechanism = parseMechanismName(rest[0..name_end]) orelse return error.UnknownMechanism;
    const name = rest[0..name_end];

    var argument: ?[]const u8 = null;
    var cidr4: ?u8 = null;
    var cidr6: ?u8 = null;

    switch (mechanism) {
        // all = "all". No argument and no cidr-length, so anything trailing the
        // name is a syntax error rather than something to ignore.
        .all => if (rest.len != name.len) return error.UnexpectedArgument,

        // include = "include" ":" domain-spec
        // exists  = "exists"  ":" domain-spec
        // The argument is mandatory, and the whole of it is the domain-spec: no
        // cidr-length is permitted, so a trailing "/24" has to validate as part of
        // the name, which it cannot.
        .include, .exists => {
            const col = colon orelse return error.MissingArgument;
            if (col != name.len) return error.UnknownMechanism;
            const arg = rest[col + 1 ..];
            try validateDomainSpec(arg);
            argument = arg;
        },

        // PTR = "ptr" [ ":" domain-spec ]. Optional argument, never a cidr-length.
        .ptr => {
            if (colon) |col| {
                const arg = rest[col + 1 ..];
                try validateDomainSpec(arg);
                argument = arg;
            } else if (slash != null) {
                return error.UnexpectedCidr;
            }
        },

        // A  = "a"  [ ":" domain-spec ] [ dual-cidr-length ]
        // MX = "mx" [ ":" domain-spec ] [ dual-cidr-length ]
        .a, .mx => {
            const split = try splitDualCidr(rest);
            cidr4 = split.cidr4;
            cidr6 = split.cidr6;

            const body = split.body;
            if (mem.indexOfScalar(u8, body, ':')) |col| {
                if (col != name.len) return error.UnknownMechanism;
                const arg = body[col + 1 ..];
                try validateDomainSpec(arg);
                argument = arg;
            } else if (body.len != name.len) {
                // No domain-spec, so once the dual-cidr-length is removed nothing
                // may remain but the bare name. This is what rejects "a/24/64",
                // whose second length is missing the second slash.
                return error.InvalidCidr;
            }
        },

        // IP4 = "ip4" ":" ip4-network [ ip4-cidr-length ]
        // IP6 = "ip6" ":" ip6-network [ ip6-cidr-length ]
        // The network is a literal address, not a domain-spec, so it is checked
        // here: an unparseable one is a permanent error in the record and must not
        // be deferred to match time, where it can only be reported as a non-match.
        // Only the mechanism's own family of cidr-length is allowed, which is why
        // "ip4:1.2.3.4//32" is invalid.
        .ip4, .ip6 => {
            const col = colon orelse return error.MissingArgument;
            if (col != name.len) return error.UnknownMechanism;
            const spec = rest[col + 1 ..];

            // An IPv6 literal contains colons but never a slash, so the first
            // slash always begins the cidr-length for both families.
            const addr_str = if (mem.indexOfScalar(u8, spec, '/')) |s| blk: {
                const digits = spec[s + 1 ..];
                if (mechanism == .ip4) {
                    cidr4 = try parseCidrLength(digits, 32, 2);
                } else {
                    cidr6 = try parseCidrLength(digits, 128, 3);
                }
                break :blk spec[0..s];
            } else spec;

            if (addr_str.len == 0) return error.MissingArgument;
            if (mechanism == .ip4) {
                _ = parseIp4Bytes(addr_str) catch return error.InvalidIp;
            } else {
                _ = try parseIp6Bytes(addr_str);
            }
            argument = addr_str;
        },
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

/// L-7: the strict RFC 4291 IPv6 parser lives in `securemilter-lib`
/// (`securemilter.ip`) since 2026-08-08 -- MOVED, not copied, so the
/// authorization path here and the config path in the library cannot
/// disagree about what an address is. These aliases keep the call sites'
/// spelling; the parser's own tests moved with it.
pub const parseIp6Bytes = securemilter.ip.parseIp6Bytes;
pub const parseIp4Bytes = securemilter.ip.parseIp4Bytes;

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
