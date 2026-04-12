const std = @import("std");
const Client = @import("client.zig").Client;
const posix = std.posix;
const mem = std.mem;
const log = std.log;

const MENU_WIDTH = 21;
const DIVIDER_COL = MENU_WIDTH + 1;

var g_original_termios: posix.termios = undefined;

pub const Tui = struct {
    client: *Client = undefined,
    log_row: u16 = 3,
    log_end: u16 = 7,
    msg_row: u16 = 10,
    term_end: u16 = 24,
    term_cols: u16 = 80,
    quit: bool = false,

    pub fn init(self: *Tui, client: *Client) !void {
        self.client = client;
        try self.getTermSize();
        try self.drawChrome();
    }

    fn getTermSize(self: *Tui) !void {
        var ws: posix.winsize = undefined;
        _ = std.os.linux.ioctl(posix.STDOUT_FILENO, 0x5413, @intFromPtr(&ws));
        self.term_end = ws.row;
        self.term_cols = ws.col;
    }

    fn drawChrome(self: *Tui) !void {
        var buf: [4096]u8 = undefined;
        var stdout_impl = std.fs.File.stdout().writer(&buf);
        const w = &stdout_impl.interface;

        try w.writeAll("\x1b[2J");
        try w.writeAll("\x1b[1;1H\x1b[7m private-zocial cmds \x1b[0m");
        try w.print("\x1b[1;{d}H\x1b[7m command outputs \x1b[0m", .{DIVIDER_COL});
        var row: u16 = 1;
        while (row < self.term_end) : (row += 1) {
            try w.print("\x1b[{d};{d}H|", .{ row, DIVIDER_COL });
        }
        try w.writeAll("\x1b[3;1H  msgs (get msgs)");
        try w.writeAll("\x1b[4;1H  dm <user> <msg>");
        try w.writeAll("\x1b[5;1H  gm <group> <msg>");
        try w.writeAll("\x1b[6;1H  create <group>");
        try w.writeAll("\x1b[7;1H  inv <user> <group>");
        try w.writeAll("\x1b[8;1H  rm <user> <group>");
        try w.writeAll("\x1b[9;1H      <group name>");
        try w.writeAll("\x1b[10;1H  clear");
        try w.writeAll("\x1b[11;1H  quit");
        try w.print("\x1b[8;{d}H\x1b[7m **{s}** message outputs \x1b[0m", .{ DIVIDER_COL, self.client.name });
        try w.print("\x1b[{d};1H Enter command: ", .{self.term_end});
        try w.flush();
    }

    pub fn clearLog(self: *Tui) void {
        var buf: [512]u8 = undefined;
        var stdout_impl = std.fs.File.stdout().writer(&buf);
        const w = &stdout_impl.interface;

        self.log_row = 3;
        var row: u16 = 3;
        while (row < self.log_end) : (row += 1) {
            w.print("\x1b[{d};{d}H\x1b[K", .{ row, DIVIDER_COL + 2 }) catch return;
        }
        w.writeAll("\x1b[u") catch return;
        w.flush() catch return;
    }

    pub fn appendLog(self: *Tui, comptime fmt: []const u8, args: anytype) void {
        var buf: [512]u8 = undefined;
        var stdout_impl = std.fs.File.stdout().writer(&buf);
        const w = &stdout_impl.interface;

        if (self.log_row >= self.log_end) {
            self.clearLog();
        }

        w.print("\x1b[s\x1b[{d};{d}H", .{ self.log_row, DIVIDER_COL + 2 }) catch return;
        w.print(fmt, args) catch return;
        w.writeAll("\x1b[u") catch return;
        w.flush() catch return;

        self.log_row += 1;
    }

    pub fn clearMsg(self: *Tui) void {
        var buf: [512]u8 = undefined;
        var stdout_impl = std.fs.File.stdout().writer(&buf);
        const w = &stdout_impl.interface;

        self.msg_row = 10;
        var row: u16 = 10;
        while (row < self.term_end) : (row += 1) {
            w.print("\x1b[{d};{d}H\x1b[K", .{ row, DIVIDER_COL + 2 }) catch return;
        }
        w.writeAll("\x1b[u") catch return;
        w.flush() catch return;
    }

    pub fn appendMsg(self: *Tui, comptime fmt: []const u8, args: anytype) void {
        var buf: [512]u8 = undefined;
        var stdout_impl = std.fs.File.stdout().writer(&buf);
        const w = &stdout_impl.interface;

        if (self.msg_row >= self.term_end) {
            self.clearMsg();
        }

        w.print("\x1b[s\x1b[{d};{d}H", .{ self.msg_row, DIVIDER_COL + 2 }) catch return;
        w.print(fmt, args) catch return;
        w.writeAll("\x1b[u") catch return;
        w.flush() catch return;

        self.msg_row += 1;
    }

    pub fn updateMsgs(self: *Tui) !void {
        self.clearMsg();
        try self.client.recieveAllMessages();
    }

    pub fn runInputLoop(self: *Tui) !void {
        try self.updateMsgs();

        const stdin = std.fs.File.stdin();

        const original_termios = try posix.tcgetattr(stdin.handle);
        g_original_termios = original_termios;
        var raw = original_termios;
        raw.lflag.ECHO = false;
        raw.lflag.ICANON = false;
        try posix.tcsetattr(stdin.handle, .FLUSH, raw);

        defer {
            posix.tcsetattr(stdin.handle, .FLUSH, g_original_termios) catch {};
            var buf: [64]u8 = undefined;
            var stdout_impl = std.fs.File.stdout().writer(&buf);
            const w = &stdout_impl.interface;
            w.writeAll("\x1b[?25h\x1b[2J\x1b[H") catch {};
            w.flush() catch {};
        }

        // handle ctrl+c via sigaction so we can restore terminal first
        const handler = struct {
            fn handle(_: c_int) callconv(.c) void {
                // restore terminal
                var buf: [64]u8 = undefined;
                var stdout_impl = std.fs.File.stdout().writer(&buf);
                const w = &stdout_impl.interface;
                posix.tcsetattr(std.fs.File.stdin().handle, .FLUSH, g_original_termios) catch {};
                w.writeAll("\x1b[?25h\x1b[2J\x1b[H") catch {};
                w.flush() catch {};
                posix.exit(0);
            }
        };
        var sa: posix.Sigaction = .{
            .handler = .{ .handler = handler.handle },
            .mask = posix.sigemptyset(),
            .flags = 0,
        };
        posix.sigaction(posix.SIG.INT, &sa, null);

        var cmd_buf: [256]u8 = undefined;
        var cmd_len: usize = 0;

        var f_buf: [64]u8 = undefined;
        var f_stdout_impl = std.fs.File.stdout().writer(&f_buf);
        const f_w = &f_stdout_impl.interface;
        try f_w.print("\x1b[{d};1H\x1b[2K Enter command: ", .{self.term_end});
        try f_w.flush();

        while (self.quit == false) {
            var byte: [1]u8 = undefined;
            _ = try stdin.read(&byte);

            switch (byte[0]) {
                '\r', '\n' => {
                    const cmd = std.mem.trim(u8, cmd_buf[0..cmd_len], " ");
                    self.handleCommand(cmd) catch |err| {
                        log.err("{}", .{err});
                    };
                    cmd_len = 0;

                    var buf: [64]u8 = undefined;
                    var stdout_impl = std.fs.File.stdout().writer(&buf);
                    const w = &stdout_impl.interface;
                    try w.print("\x1b[{d};1H\x1b[2K Enter command: ", .{self.term_end});
                    try w.flush();
                },
                127, 8 => {
                    if (cmd_len > 0) {
                        cmd_len -= 1;
                        var buf: [16]u8 = undefined;
                        var stdout_impl = std.fs.File.stdout().writer(&buf);
                        const w = &stdout_impl.interface;
                        try w.writeAll("\x1b[D \x1b[D");
                        try w.flush();
                    }
                },
                3 => return, // ctrl+c
                else => {
                    if (cmd_len < cmd_buf.len - 1 and byte[0] >= 32) {
                        cmd_buf[cmd_len] = byte[0];
                        cmd_len += 1;
                        var buf: [8]u8 = undefined;
                        var stdout_impl = std.fs.File.stdout().writer(&buf);
                        const w = &stdout_impl.interface;
                        try w.writeByte(byte[0]);
                        try w.flush();
                    }
                },
            }
        }
    }

    fn handleCommand(self: *Tui, cmd: []const u8) !void {
        const dm_str: []const u8 = "dm";
        const gm_str: []const u8 = "gm";
        const msgs_str: []const u8 = "msgs";
        const create_str: []const u8 = "create";
        const rm_str: []const u8 = "rm";
        const inv_str: []const u8 = "inv";
        if (std.mem.startsWith(u8, cmd, dm_str)) {
            const args = cmd[dm_str.len + 1 ..];
            var it = mem.splitScalar(u8, args, ' ');
            const id = self.client.getUserIdFromName(it.next().?) catch |err| {
                self.appendLog("{s} failed: {}", .{ dm_str, err });
                return;
            };
            _ = self.client.sendDmMessage(id, it.rest()) catch |err| {
                self.appendLog("{s} failed: {}", .{ dm_str, err });
                return;
            };
            self.appendLog("{s} successful", .{dm_str});
            try self.updateMsgs();
        } else if (std.mem.startsWith(u8, cmd, gm_str)) {
            const args = cmd[gm_str.len + 1 ..];
            var it = mem.splitScalar(u8, args, ' ');
            const id = self.client.getGroupIdFromName(it.next().?) catch |err| {
                self.appendLog("{s} failed: {}", .{ gm_str, err });
                return;
            };
            _ = self.client.sendGroupMessage(id, it.rest()) catch |err| {
                self.appendLog("{s} failed: {}", .{ gm_str, err });
                return;
            };
            self.appendLog("{s} successful", .{gm_str});
            try self.updateMsgs();
        } else if (std.mem.startsWith(u8, cmd, msgs_str)) {
            try self.updateMsgs();
            self.appendLog("{s} successful", .{msgs_str});
        } else if (std.mem.startsWith(u8, cmd, create_str)) {
            const name = cmd[create_str.len + 1 ..];
            _ = self.client.createGroup(name) catch |err| {
                self.appendLog("{s} failed: {}", .{ create_str, err });
                return;
            };
            self.appendLog("{s} successful", .{create_str});
        } else if (std.mem.startsWith(u8, cmd, rm_str)) {
            const args = cmd[rm_str.len + 1 ..];
            var it = mem.splitScalar(u8, args, ' ');
            const user_id = self.client.getUserIdFromName(it.next().?) catch |err| {
                self.appendLog("{s} failed: {}", .{ rm_str, err });
                return;
            };
            const group_id = self.client.getGroupIdFromName(it.next().?) catch |err| {
                self.appendLog("{s} failed: {}", .{ rm_str, err });
                return;
            };
            const group_name = it.next().?;
            _ = self.client.removeFromGroup(user_id, group_id, group_name) catch |err| {
                self.appendLog("{s} failed: {}", .{ rm_str, err });
                return;
            };
            self.appendLog("{s} successful", .{rm_str});
        } else if (std.mem.startsWith(u8, cmd, inv_str)) {
            const args = cmd[inv_str.len + 1 ..];
            var it = mem.splitScalar(u8, args, ' ');
            const user_id = self.client.getUserIdFromName(it.next().?) catch |err| {
                self.appendLog("{s} failed: {}", .{ inv_str, err });
                return;
            };
            const group_id = self.client.getGroupIdFromName(it.next().?) catch |err| {
                self.appendLog("{s} failed: {}", .{ inv_str, err });
                return;
            };
            _ = self.client.groupInvite(user_id, group_id) catch |err| {
                self.appendLog("{s} failed: {}", .{ inv_str, err });
                return;
            };
            self.appendLog("{s} successful", .{inv_str});
        } else if (std.mem.startsWith(u8, cmd, "clear")) {
            self.clearLog();
        } else if (std.mem.startsWith(u8, cmd, "quit")) {
            self.appendLog("quitting...", .{});
            self.quit = true;
        } else if (cmd.len > 0) {
            self.appendLog("unknown command: {s}", .{cmd});
        }
    }
};
