//! Client Module

const std = @import("std");
const Allocator = std.mem.Allocator;
const HashMap = std.AutoArrayHashMap;
const crypto = @import("crypto.zig");
const mastadon = @import("mastadon.zig");

pub const Member = struct {
    admin: bool,
};

pub const Members = struct {
    /// map from username to Member
    map: HashMap(mastadon.Username, Member),
    signature: crypto.Ed25519.Signature,

    pub fn init(signature: crypto.Ed25519.Signature, allocator: Allocator) @This() {
        return .{
            .map = HashMap(mastadon.Username, Member).init(allocator),
            .signature = signature,
        };
    }
    pub fn deinit(self: *@This()) void {
        self.map.deinit();
    }
};

pub const Group = struct {
    aes_key: [crypto.Aes128Ocb.key_length]u8,
    members: Members,

    pub fn init(aes_key: [crypto.Aes128Ocb.key_length]u8, allocator: Allocator) @This() {
        return .{
            .aes_key = aes_key,
            .members = Members.init(allocator),
        };
    }
    pub fn deinit(self: *@This()) void {
        self.members.deinit();
    }
};

pub const Client = struct {
    username: mastadon.Username,
    long_term_keys: crypto.Ed25519.KeyPair,
    groups: HashMap(crypto.UUID, Group),
    dms: HashMap(crypto.UUID, crypto.AES_KEY),
    allocator: Allocator,

    pub fn init(username: []const u8, allocator: Allocator) @This() {
        const long_term_keys = crypto.generateSigningKeypair();
        const groups = HashMap(crypto.UUID, Group).init(allocator);
        const dms = HashMap(crypto.UUID, crypto.AES_KEY).init(allocator);
        return .{
            .username = username,
            .long_term_keys = long_term_keys,
            .groups = groups,
            .dms = dms,
            .allocator = allocator,
        };
    }
    // pub fn post_
    pub fn deinit(self: *@This()) void {
        var it = self.groups.iterator();
        while (it.next()) |group| {
            group.value_ptr.*.deinit();
        }
        self.groups.deinit();
        self.dms.deinit();
    }
};
