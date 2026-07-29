const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const securemilter_dep = b.dependency("securemilter", .{
        .target = target,
        .optimize = optimize,
    });
    const securemilter_mod = securemilter_dep.module("securemilter");

    const exe = b.addExecutable(.{
        .name = "securespf",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "securemilter", .module = securemilter_mod },
            },
        }),
    });

    b.installArtifact(exe);

    // securespf-check CLI tool (SPF evaluation from command line)
    const check_mod = b.createModule(.{
        .root_source_file = b.path("src/check.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "securemilter", .module = securemilter_mod },
        },
    });
    const check_exe = b.addExecutable(.{
        .name = "securespf-check",
        .root_module = check_mod,
    });
    b.installArtifact(check_exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run SecureSPF");
    run_step.dependOn(&run_cmd.step);

    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "securemilter", .module = securemilter_mod },
        },
    });

    const tests = b.addTest(.{
        .root_module = test_mod,
    });

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);

    // One canonical checker, shared from securemilter-lib rather than copied.
    const lint = b.addSystemCommand(&.{"sh"});
    lint.addFileArg(securemilter_dep.path("tools/check-line-limit.sh"));
    lint.addArg("src");
    lint.addArg(".line-limit-allow");
    if (b.args) |args| lint.addArgs(args);
    lint.has_side_effects = true;
    const lint_step = b.step("lint", "Fail on source files over the 400-line limit");
    lint_step.dependOn(&lint.step);
}
