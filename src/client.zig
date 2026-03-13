const std = @import("std");
const HashMap = std.AutoArrayHashMap;
const crypto = @import("crypto.zig");

pub const Member = struct {
    admin: bool,
};

pub const Members = struct {
    /// map from username to Member
    map: HashMap([]const u8, Member),
    signature: crypto.Ed25519.Signature,
};

pub const Group = struct {
    aes_key: [crypto.Aes128Ocb.key_length]u8,
    members: Members,
};

pub const Client = struct {
    username: []const u8,
    long_term_keys: crypto.Ed25519.KeyPair,
    groups: HashMap(crypto.UUID, Group),
    dms: HashMap(crypto.UUID, crypto.AES_KEY),
};
