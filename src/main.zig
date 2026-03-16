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

    const keys = crypto.generateSigningKeyPair();
    var key_buf: [crypto.base64.Encoder.calcSize(keys.public_key.bytes.len)]u8 = undefined;
    const public_key = crypto.base64.Encoder.encode(&key_buf, &keys.public_key.toBytes());

    //try mastadon.sendMessage(allocator, access_token, str, null);
    try mastadon.setBio(allocator, access_token, public_key);

    var username: mastadon.Username = std.mem.zeroes(mastadon.Username);
    @memcpy(username[0..14], "private_zocial");
    const parsed_user = try mastadon.getUser(allocator, username);
    defer parsed_user.deinit();
    var user = parsed_user.value;

    const parsed_messages = try mastadon.getMessages(allocator, access_token, null);
    defer parsed_messages.deinit();

    var stdout_buf: [1024]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
    const stdout = &stdout_writer.interface;

    try stdout.print("username: {s}, id: {}, public key: {s}\n", .{ user.username, user.id, user.getPublicKey() });

    for (0..parsed_messages.value.len) |i| {
        try stdout.print("message: {s}\n", .{parsed_messages.value[i].getContent()});
    }
    try stdout.flush();
}
