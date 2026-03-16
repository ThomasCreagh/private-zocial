const std = @import("std");
const config = @import("config.zig");
const Client = std.http.Client;
const Allocator = std.mem.Allocator;

pub const username_legth = 30;
pub const Username = [username_legth]u8;

const UserToken = struct {
    access_token: []u8,
    token_type: []u8,
    scope: []u8,
    created_at: usize,
};

pub fn authenticateUser(allocator: Allocator) ![]const u8 {
    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
    const stdout = &stdout_writer.interface;

    var stdin_buf: [1024]u8 = undefined;
    var stdin_reader = std.fs.File.stdin().reader(&stdin_buf);
    const stdin: *std.io.Reader = &stdin_reader.interface;

    const auth_url: []const u8 =
        "\thttps://mastodon.social/oauth/authorize" ++
        "?client_id={s}" ++
        "&scope=read+write+push" ++
        "&redirect_uri=urn:ietf:wg:oauth:2.0:oob" ++
        "&response_type=code";

    try stdout.writeAll("Please authenticate with this url:\n\n");
    try stdout.print(auth_url, .{config.CLIENT_ID});
    try stdout.writeAll("\n\nAnd enter the auth code below: ");

    try stdout.flush();
    const raw_line = try stdin.takeDelimiter('\n') orelse unreachable;
    const auth_code = std.mem.trim(u8, raw_line, "\r");

    var client = Client{ .allocator = allocator };
    defer client.deinit();

    const uri = try std.Uri.parse("https://mastodon.social/oauth/token");

    // Make the connection to the server.
    var request = try client.request(.POST, uri, .{
        .headers = .{
            .accept_encoding = .{ .override = "identity" },
            .content_type = .{ .override = "application/x-www-form-urlencoded" },
        },
    });
    defer request.deinit();

    const redirect_uri = "urn:ietf:wg:oauth:2.0:oob";
    const body_options = "grant_type=authorization_code&client_id={s}&client_secret={s}&redirect_uri={s}&code={s}";

    const body = try std.fmt.allocPrint(allocator, body_options, .{ config.CLIENT_ID, config.CLIENT_SECRET, redirect_uri, auth_code });
    defer allocator.free(body);

    try request.sendBodyComplete(body);

    var redirect_buf: [1024]u8 = undefined;
    var response = try request.receiveHead(&redirect_buf);

    var transfer_buf: [4096]u8 = undefined;
    const response_reader = response.reader(&transfer_buf);

    const raw_body = try response_reader.allocRemaining(allocator, .limited(1024));
    defer allocator.free(raw_body);

    const parsed = try std.json.parseFromSlice(UserToken, allocator, raw_body, .{});
    defer parsed.deinit();

    const access_token = allocator.dupe(u8, parsed.value.access_token);
    return access_token;
}
