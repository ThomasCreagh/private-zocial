const std = @import("std");
const mastadon = @import("mastadon.zig");
const crypto = @import("crypto.zig");
const client_mod = @import("client.zig");

const Client = client_mod.Client;

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    const allocator = gpa.allocator();
    defer {
        const deinit_status = gpa.deinit();
        if (deinit_status == .leak) std.testing.expect(false) catch @panic("TEST FAIL");
    }

    var username: mastadon.Username = std.mem.zeroes(mastadon.Username);
    @memcpy(username[0..14], "private_zocial");

    var client: Client = try .init(allocator);
    defer client.deinit();

    try client.dmInvite(username);

    //var stdout_buf: [1024]u8 = undefined;
    //var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
    //const stdout = &stdout_writer.interface;
}
