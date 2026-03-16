const std = @import("std");
const indexOf = std.mem.indexOf;
const Allocator = std.mem.Allocator;

pub const UserToken = struct {
    access_token: []u8,
};

pub const Message = struct {
    id: usize,
    created_at: []u8,
    content: []u8,
    pub fn getContent(self: *@This()) []const u8 {
        const eom = indexOf(u8, self.content, "</p>") orelse unreachable;
        return self.content[3..eom];
    }
};

pub const User = struct {
    id: usize,
    username: []u8,
    created_at: []u8,
    note: []u8,
    pub fn getPublicKey(self: *@This()) []const u8 {
        const eom = indexOf(u8, self.note, "</p>") orelse unreachable;
        return self.note[3..eom];
    }
};
