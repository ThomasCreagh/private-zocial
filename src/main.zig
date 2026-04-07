const std = @import("std");
const mastadon = @import("mastadon.zig");
const crypto = @import("crypto.zig");
const client_mod = @import("client.zig");
const tui_mod = @import("tui.zig");

const Client = client_mod.Client;

var tui: tui_mod.Tui = .{};

fn logFn(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.enum_literal),
    comptime fmt: []const u8,
    args: anytype,
) void {
    _ = scope;
    switch (level) {
        .info => tui.appendMsg(fmt, args),
        .debug => tui.appendLog("DEBUG: " ++ fmt, args),
        .err => tui.appendLog("ERR: " ++ fmt, args),
        .warn => tui.appendLog("WARNING: " ++ fmt, args),
    }
}

pub const std_options: std.Options = .{
    .log_level = .info,
    .logFn = logFn,
};

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    const allocator = gpa.allocator();
    defer {
        const deinit_status = gpa.deinit();
        if (deinit_status == .leak) std.testing.expect(false) catch @panic("TEST FAIL");
    }

    var stdout_buf: [1024]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
    const stdout: *std.io.Writer = &stdout_writer.interface;

    var stdin_buf: [1024]u8 = undefined;
    var stdin_reader = std.fs.File.stdin().reader(&stdin_buf);
    const stdin: *std.io.Reader = &stdin_reader.interface;

    try stdout.writeAll("Enter client save name: ");
    try stdout.flush();
    const bare_line = try stdin.takeDelimiter('\n') orelse unreachable;
    const name = std.mem.trim(u8, bare_line, "\r");

    var client = try Client.init(allocator, name, null);
    defer client.deinit();

    try tui.init(&client);
    try tui.runInputLoop();

    try client.saveToFile();
}
