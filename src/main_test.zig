//! Configuration tests for `main.zig` — listener addresses.
//!
//! Separated following the `settings_test.zig` / `dmarc_test.zig` precedent, so
//! `main.zig` reflects the daemon rather than its test fixtures. Pulled into the
//! test build by `main.zig`.
//!
//! Only tests touching ALREADY-PUBLIC symbols live here — `parseSpfConfig` and
//! `SpfConfig` were both `pub` before this file existed, so nothing was exported
//! merely to move a test. `extractDomain` and `addArHeader` are private and their
//! tests stay in `main.zig` deliberately: publishing internals to satisfy a line
//! count is the worse trade.

const std = @import("std");

const securemilter = @import("securemilter");
const config_mod = securemilter.config;

const main = @import("main.zig");
const SpfConfig = main.SpfConfig;
const parseSpfConfig = main.parseSpfConfig;

fn freeTestConfig(spf_cfg: SpfConfig) void {
    std.testing.allocator.free(spf_cfg.listen_addresses);
    std.testing.allocator.free(spf_cfg.dns_nameservers);
}

// Both tests below keep `cfg` alive across their assertions on purpose. An address
// from a `Socket =` line BORROWS its host string from the parsed config, so a helper
// that parses and deinits in one call hands back a dangling pointer -- which is
// exactly how the first version of the 0.0.0.0 test failed, comparing against freed
// memory. The loopback case masked it, because "127.0.0.1" is a literal in the
// fallback and survives the free.

// The implicit listener binds loopback, never 0.0.0.0.
//
// Until 2026-07-29 it bound 0.0.0.0 and nothing tested it -- this daemon had no
// configuration test at all. The milter protocol authenticates nobody, so a
// reachable port means an attacker supplies the client IP, HELO and MAIL FROM that
// check_host() runs on, and therefore chooses the SPF result this host stamps.
// Reachability IS authorization.
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
