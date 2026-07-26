const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

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
    explanation: ?[]const u8,
};

/// Evaluate SPF for the given context.
///
/// This is the main entry point that will:
/// 1. Extract domain from sender (or use HELO domain for null sender)
/// 2. DNS lookup TXT records for the domain
/// 3. Parse SPF record
/// 4. Walk directives, resolving DNS for a/mx/include/exists/ptr
/// 5. Enforce 10-lookup limit
/// 6. Handle redirect modifier
///
/// TODO: Implement full DNS-based evaluation. Currently returns .none.
pub fn evaluate(
    _: Allocator,
    ctx: *const EvalContext,
) EvalResult {
    _ = ctx;
    return .{
        .result = .none,
        .domain = "",
        .explanation = null,
    };
}

test "evaluate returns none for stub" {
    const ctx = EvalContext{
        .client_ip = "192.0.2.1",
        .is_ipv6 = false,
        .sender = "user@example.com",
        .helo_domain = "mail.example.com",
        .receiver_host = "mx.local",
    };

    const result = evaluate(std.testing.allocator, &ctx);
    try std.testing.expectEqual(spf.Result.none, result.result);
}
