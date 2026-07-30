const std = @import("std");
const mem = std.mem;
const posix = std.posix;
const process = std.process;

const securemilter = @import("securemilter");
const cli = securemilter.cli.Tool("securespf-check");
const dns_mod = securemilter.dns;

const spf = @import("spf.zig");
const evaluate = @import("evaluate.zig");

const Usage =
    \\Usage: securespf-check [options]
    \\
    \\Perform an SPF evaluation and display the result.
    \\
    \\Options:
    \\  -i <ip>          Client IP address (required)
    \\  -s <sender>      MAIL FROM address, e.g. user@example.com (required)
    \\  -e <helo>        EHLO/HELO domain (default: extracted from sender)
    \\  -n <nameserver>  DNS nameserver (default: 127.0.0.1)
    \\  -p <port>        DNS nameserver port (default: 53)
    \\  -h               Show this help
    \\
    \\Examples:
    \\  securespf-check -i 192.168.1.233 -s user@bambania.com
    \\  securespf-check -i 203.0.113.1 -s bounce@example.com -e mail.example.com
    \\  securespf-check -i 2001:db8::1 -s user@example.org -n 8.8.8.8
    \\
;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args = process.args();
    _ = args.next(); // skip argv[0]

    var client_ip: ?[]const u8 = null;
    var sender: ?[]const u8 = null;
    var helo: ?[]const u8 = null;
    var nameserver: []const u8 = "127.0.0.1";
    // Exposed so an evaluation can be pointed at a nameserver that is not on
    // port 53 -- a local resolver under test, or the mock zone the RFC 7208
    // conformance suite is driven against, neither of which can bind 53 without
    // privilege.
    var port: u16 = 53;

    while (args.next()) |arg| {
        if (mem.eql(u8, arg, "-h") or mem.eql(u8, arg, "--help")) {
            cli.out(Usage);
            return;
        } else if (mem.eql(u8, arg, "-i")) {
            client_ip = args.next() orelse return cli.fatal("missing argument for -i");
        } else if (mem.eql(u8, arg, "-s")) {
            sender = args.next() orelse return cli.fatal("missing argument for -s");
        } else if (mem.eql(u8, arg, "-e")) {
            helo = args.next() orelse return cli.fatal("missing argument for -e");
        } else if (mem.eql(u8, arg, "-n")) {
            nameserver = args.next() orelse return cli.fatal("missing argument for -n");
        } else if (mem.eql(u8, arg, "-p")) {
            const raw = args.next() orelse return cli.fatal("missing argument for -p");
            port = std.fmt.parseInt(u16, raw, 10) catch return cli.fatal("-p must be a port number");
        } else {
            return cli.fatal("unknown option (use -h for help)");
        }
    }

    const ip = client_ip orelse return cli.fatal("-i <ip> is required");
    const snd = sender orelse return cli.fatal("-s <sender> is required");

    // Extract domain from sender for default HELO
    const sender_domain = extractDomain(snd);
    const helo_domain = helo orelse sender_domain;
    const is_ipv6 = mem.indexOfScalar(u8, ip, ':') != null;

    // Set up DNS resolver
    const ns_slice: []const []const u8 = &.{nameserver};
    const dns_config = dns_mod.ResolverConfig{
        .nameservers = ns_slice,
        .port = port,
        .timeout_ms = 5000,
        .retries = 2,
    };
    var resolver = dns_mod.Resolver.init(allocator, dns_config);
    defer resolver.deinit();

    // Build evaluation context
    const eval_ctx = evaluate.EvalContext{
        .client_ip = ip,
        .is_ipv6 = is_ipv6,
        .sender = snd,
        .helo_domain = helo_domain,
        .receiver_host = "localhost",
    };

    // Evaluate SPF
    const result = evaluate.evaluate(allocator, &resolver, &eval_ctx);
    const result_str = resultToString(result.result);
    const domain = if (result.domain.len > 0) result.domain else sender_domain;

    // Format and print result
    var buf: [512]u8 = undefined;
    const line = std.fmt.bufPrint(&buf,
        \\securespf-check: {s}
        \\  domain: {s}
        \\  client-ip: {s}
        \\  sender: {s}
        \\  helo: {s}
        \\
    , .{ result_str, domain, ip, snd, helo_domain }) catch return cli.fatal("output format error");
    cli.out(line);

    // Exit non-zero on definitive failure
    switch (result.result) {
        .pass, .none, .neutral => {},
        .fail, .softfail, .temperror, .permerror => process.exit(1),
    }
}

fn extractDomain(addr: []const u8) []const u8 {
    if (mem.lastIndexOfScalar(u8, addr, '@')) |at| {
        return addr[at + 1 ..];
    }
    return addr;
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
