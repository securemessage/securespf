const std = @import("std");
const spf = @import("spf.zig");
const macro = @import("macro.zig");

pub fn main() !void {
    _ = try std.posix.write(std.posix.STDOUT_FILENO, "SecureSPF v0.1.0\n");
}

test {
    _ = spf;
    _ = macro;
}
