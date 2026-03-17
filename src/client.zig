//! Client Module

const std = @import("std");
const models = @import("models.zig");
const crypto = @import("crypto.zig");
const social = @import("mastadon.zig");

const Allocator = std.mem.Allocator;
const HashMap = std.AutoArrayHashMap;

pub const Member = struct {
    admin: bool,
};

pub const Members = struct {
    /// map from username to Member
    map: HashMap(social.Username, Member),
    signature: crypto.Ed25519.Signature,

    pub fn init(signature: crypto.Ed25519.Signature, allocator: Allocator) @This() {
        return .{
            .map = HashMap(social.Username, Member).init(allocator),
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
    access_token: []const u8,
    long_term_keys: crypto.Ed25519.KeyPair,
    groups: HashMap(crypto.UUID, Group),
    dms: HashMap(crypto.UUID, crypto.AesKey),
    allocator: Allocator,

    pub fn init(allocator: Allocator) !@This() {
        var client = Client{
            .access_token = try social.authenticateUser(allocator),
            .long_term_keys = crypto.generateSigningKeyPair(),
            .groups = HashMap(crypto.UUID, Group).init(allocator),
            .dms = HashMap(crypto.UUID, crypto.AesKey).init(allocator),
            .allocator = allocator,
        };
        try client.postPublicKey();

        return client;
    }

    pub fn postPublicKey(self: *@This()) !void {
        const keys = self.long_term_keys;
        var key_buf: [crypto.base64.Encoder.calcSize(keys.public_key.bytes.len)]u8 = undefined;
        const public_key = crypto.base64.Encoder.encode(&key_buf, &keys.public_key.toBytes());
        try social.setBio(self.allocator, self.access_token, public_key);
    }

    pub fn dmInvite(self: *@This(), username: social.Username) !void {
        const ephemeral_keys = crypto.getEphemeralKeyPair();
        const sender_public_key = ephemeral_keys.public_key;
        const sender_secret_key = ephemeral_keys.secret_key;

        const parsed_user = try social.getUser(self.allocator, username);
        defer parsed_user.deinit();

        var user = parsed_user.value;
        const reciever_public_ed25519_key = user.getPublicKey();
        var decoded_buf: [crypto.Ed25519.PublicKey.encoded_length]u8 = undefined;
        try crypto.base64.Decoder.decode(&decoded_buf, reciever_public_ed25519_key);
        const decoded_key = try crypto.Ed25519.PublicKey.fromBytes(decoded_buf);
        const reciever_public_key = try crypto.getRecieversPublicKeyFromEd25519(decoded_key);

        const uuid = crypto.UUID.init();

        var nonce: [crypto.Aes128Ocb.nonce_length]u8 = undefined;
        crypto.random.bytes(&nonce);

        var aes_key: crypto.AesKey = undefined;
        try crypto.deriveAesKey(&aes_key, sender_secret_key, reciever_public_key, nonce, &uuid.key);

        try self.dms.put(uuid, aes_key);

        const json_secret = models.DmInvite.Secret{
            .id = uuid,
        };

        var serial_secret: std.io.Writer.Allocating = .init(self.allocator);
        defer serial_secret.deinit();

        try serial_secret.writer.print("{f}", .{std.json.fmt(json_secret, .{})});
        const secret_str = serial_secret.written();

        const encrypted_secret = try self.allocator.alloc(u8, secret_str.len);
        defer self.allocator.free(encrypted_secret);
        var tag: [crypto.Aes128Ocb.tag_length]u8 = undefined;
        crypto.aesEncrypt(encrypted_secret, &tag, secret_str, &nonce, aes_key);

        const json_model = models.DmInvite.Encrypted{
            .ephemeral_key = sender_public_key,
            .nonce = nonce,
            .tag = tag,
            .encrypted = encrypted_secret,
        };

        var serialized: std.io.Writer.Allocating = .init(self.allocator);
        defer serialized.deinit();

        try serialized.writer.print("{f}", .{std.json.fmt(json_model, .{})});
        const serialized_str = serialized.written();

        const encode_buf = try self.allocator.alloc(u8, crypto.base64.Encoder.calcSize(serialized_str.len));
        defer self.allocator.free(encode_buf);
        const decoded_str = crypto.base64.Encoder.encode(encode_buf, serialized_str);

        try social.sendMessage(self.allocator, self.access_token, decoded_str, null);
    }
    //try mastadon.sendMessage(allocator, access_token, str, null);
    pub fn deinit(self: *@This()) void {
        var it = self.groups.iterator();
        while (it.next()) |group| {
            group.value_ptr.*.deinit();
        }
        self.groups.deinit();
        self.dms.deinit();
    }
};
