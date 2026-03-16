const std = @import("std");
const mastadon = @import("mastadon.zig");
const crypto = @import("crypto.zig");

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    const allocator = gpa.allocator();
    defer {
        const deinit_status = gpa.deinit();
        if (deinit_status == .leak) std.testing.expect(false) catch @panic("TEST FAIL");
    }

    const access_token = try mastadon.authenticateUser(allocator);
    defer allocator.free(access_token);

    try mastadon.sendMessage(allocator, access_token, "client test", null);

    const parsed_messages = try mastadon.getMessages(allocator, access_token, null);
    defer parsed_messages.deinit();

    var stdout_buf: [1024]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
    const stdout = &stdout_writer.interface;

    for (0..parsed_messages.value.len) |i| {
        try stdout.print("message: {s}\n", .{parsed_messages.value[i].getContent()});
    }
    try stdout.flush();
}
