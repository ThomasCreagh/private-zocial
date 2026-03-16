const std = @import("std");
const indexOf = std.mem.indexOf;
const Allocator = std.mem.Allocator;

pub const UserToken = struct {
    access_token: []u8,
    created_at: usize,
};

pub const Message = struct {
    id: usize,
    created_at: []u8,
    content: []u8,
    pub fn getContent(self: *@This()) []const u8 {
        const eom = indexOf(u8, self.content, "</p>") orelse unreachable;
        return self.content[3..eom];
    }
    pub fn deinit(self: *@This(), allocator: Allocator) void {
        allocator.free(self.created_at);
        allocator.free(self.content);
    }
};
