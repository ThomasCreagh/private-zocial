//! Client Module

const std = @import("std");
const models = @import("models.zig");
const crypto = @import("crypto.zig");
const social = @import("mastadon.zig");
const base32 = @import("base32.zig").standard;

const json = std.json;
const Allocator = std.mem.Allocator;
const HashMap = std.AutoArrayHashMap;
const ArrayList = std.ArrayList;
const BaseMethods = models.BaseMethods;

pub const Member = struct {
    username: social.Username,
    admin: bool,
};

pub const Members = struct {
    /// map from username to Member
    list: ArrayList(Member),
    signature: crypto.Ed25519.Signature,

    pub fn init(signature: crypto.Ed25519.Signature) @This() {
        return .{
            .list = ArrayList(Member){},
            .signature = signature,
        };
    }
    pub fn deinit(self: *@This(), allocator: Allocator) void {
        self.list.deinit(allocator);
    }
};

pub const Group = struct {
    name: []const u8,
    aes_key: crypto.AesKey,
    members: Members,

    pub fn init(aes_key: [crypto.Aes128Ocb.key_length]u8, allocator: Allocator) @This() {
        return .{
            .aes_key = aes_key,
            .members = Members.init(allocator),
        };
    }
    pub fn deinit(self: *@This(), allocator: Allocator) void {
        allocator.free(self.name);
        self.members.deinit(allocator);
    }
};

pub const Dm = struct {
    name: []const u8,
    key: crypto.AesKey,

    pub fn deinit(self: *@This(), allocator: Allocator) void {
        allocator.free(self.name);
    }
};

pub const Client = struct {
    name: []const u8,
    access_token: []const u8,
    /// Long term Ed25519 signing keys
    lt_sign_keys: crypto.Ed25519.KeyPair,
    /// Long term X25519 key exchange keys
    lt_ke_keys: crypto.X25519.KeyPair,
    groups: HashMap(crypto.UUID, Group),
    dms: HashMap(crypto.UUID, Dm),
    allocator: Allocator,
    free_token: bool,

    pub fn init(allocator: Allocator, name: []const u8, access_token: ?[]const u8) !@This() {
        const lt_sign_keys = crypto.generateSigningKeyPair();
        var token: []const u8 = undefined;
        var free_token: bool = false;
        if (access_token) |t| {
            token = t;
        } else {
            token = try social.authenticateUser(allocator);
            free_token = true;
        }

        var client = Client{
            .name = name,
            .access_token = token,
            .lt_sign_keys = lt_sign_keys,
            .lt_ke_keys = try crypto.deriveX25519KeyPair(lt_sign_keys),
            .groups = HashMap(crypto.UUID, Group).init(allocator),
            .dms = HashMap(crypto.UUID, Dm).init(allocator),
            .allocator = allocator,
            .free_token = free_token,
        };
        try client.postPublicKey();

        return client;
    }
    pub fn postPublicKey(self: *@This()) !void {
        const keys = self.lt_sign_keys;
        var key_buf: [base32.Encoder.calcSize(keys.public_key.bytes.len)]u8 = undefined;
        const public_key = base32.Encoder.encode(&key_buf, &keys.public_key.toBytes());
        try social.setBio(self.allocator, self.access_token, public_key);
    }
    pub fn acceptInvites(self: *@This()) !void {
        const parsed_messages = try social.getMessages(self.allocator, self.access_token, null);
        defer parsed_messages.deinit();

        const messages = parsed_messages.value;
        for (0..messages.len) |i| {
            const encoded_message = messages[i].getContent();

            var dm_invite = try BaseMethods(models.DmInvite).fromBase32(self.allocator, encoded_message);
            defer dm_invite.base.deinit(self.allocator);

            const enc: *models.DmInvite.Encrypted = &dm_invite.base.encrypted.?;

            var aes_key: crypto.AesKey = undefined;

            crypto.deriveAesKey(
                &aes_key,
                self.lt_ke_keys.secret_key,
                enc.ephemeral_key,
                enc.nonce,
                &enc.id.key,
            ) catch |err| {
                std.debug.print("acceptInvite: couldnt get key {}\n", .{err});
                break;
            };

            dm_invite.base.decrypt(self.allocator, aes_key) catch {
                std.debug.print("acceptInvite: couldnt decrypt message\n", .{});
                break;
            };

            if (dm_invite.base.secret.?.label != .dm_invite) {
                std.debug.print("acceptInvite: wrong label\n", .{});
                break;
            }

            try self.dms.put(enc.id, Dm{
                .name = try self.allocator.dupe(u8, messages[i].account.username),
                .key = aes_key,
            });
        }
    }
    pub fn dmInvite(self: *@This(), username: social.Username, id: ?crypto.UUID) !void {
        const uuid = id orelse crypto.UUID.init();

        const ephemeral_keys = crypto.getEphemeralKeyPair();

        const parsed_user = try social.getUser(self.allocator, username);
        defer parsed_user.deinit();

        var user = parsed_user.value;
        var decoded_buf: [crypto.Ed25519.PublicKey.encoded_length]u8 = undefined;
        const decoded_key = try user.getPublicKey(&decoded_buf);
        const reciever_public_key = try crypto.getRecieversPublicKeyFromEd25519(decoded_key);

        var dm_invite: models.DmInvite = try BaseMethods(models.DmInvite).fromEncryptedAndSecret(
            self.allocator,
            models.DmInvite.Encrypted{
                .ephemeral_key = ephemeral_keys.public_key,
                .id = uuid,
            },
            models.DmInvite.Secret{},
        );
        defer dm_invite.base.deinit(self.allocator);

        var aes_key: crypto.AesKey = undefined;
        try crypto.deriveAesKey(&aes_key, ephemeral_keys.secret_key, reciever_public_key, dm_invite.base.encrypted.?.nonce, &uuid.key);

        try self.dms.put(uuid, Dm{
            .name = try self.allocator.dupe(u8, username),
            .key = aes_key,
        });

        try dm_invite.base.encrypt(self.allocator, aes_key);

        const encode_buf = try self.allocator.alloc(u8, base32.Encoder.calcSize(dm_invite.base.json_encrypted.?.written().len));
        defer self.allocator.free(encode_buf);

        const encoded_str = try dm_invite.base.toBase32(encode_buf);

        try social.sendMessage(self.allocator, self.access_token, encoded_str, null);
    }
    pub fn getIdFromUsername(self: *@This(), username: []const u8) !crypto.UUID {
        var it = self.dms.iterator();
        while (it.next()) |dm| {
            if (std.mem.eql(u8, dm.value_ptr.*.name, username)) {
                return dm.key_ptr.*;
            }
        }
        const uuid = crypto.UUID.init();
        try self.dmInvite(username, uuid);
        return uuid;
    }
    pub fn sendMessage(self: *@This(), id: crypto.UUID, message: []const u8) !void {
        var aes_key: crypto.AesKey = undefined;
        if (self.dms.get(id)) |x| {
            aes_key = x.key;
        } else {
            return error.IdNotInMap;
        }

        var dm_message: models.DmMessage = try BaseMethods(models.DmMessage).fromEncryptedAndSecret(
            self.allocator,
            models.DmMessage.Encrypted{},
            models.DmMessage.Secret{
                .message = message,
            },
        );
        defer dm_message.base.deinit(self.allocator);

        try dm_message.base.encrypt(self.allocator, aes_key);

        const encode_buf = try self.allocator.alloc(u8, base32.Encoder.calcSize(dm_message.base.json_encrypted.?.written().len));
        defer self.allocator.free(encode_buf);

        const encoded_str = try dm_message.base.toBase32(encode_buf);

        try social.sendMessage(self.allocator, self.access_token, encoded_str, id);
    }
    pub fn recieveMessage(self: *@This(), id: crypto.UUID) !void {
        var aes_key: crypto.AesKey = undefined;
        if (self.dms.get(id)) |x| {
            aes_key = x.key;
        } else {
            return error.IdNotInMap;
        }

        const parsed_messages = try social.getMessages(self.allocator, self.access_token, id);
        defer parsed_messages.deinit();
        const messages: []models.Message = parsed_messages.value;

        std.debug.print("ID: {s}\n", .{id.str});
        for (0..messages.len) |i| {
            const encoded_message = messages[i].getContent();

            var dm_message = try BaseMethods(models.DmMessage).fromBase32(self.allocator, encoded_message);
            defer dm_message.base.deinit(self.allocator);

            dm_message.base.decrypt(self.allocator, aes_key) catch {
                std.debug.print("recieveMessage: couldnt decrypt message\n", .{});
                break;
            };

            if (dm_message.base.secret.?.label != .dm_message) {
                std.debug.print("acceptInvite: wrong label\n", .{});
                break;
            }

            std.debug.print("recieveMessage: Message {} from {s}:\n\t{s}\n", .{
                i,
                messages[i].account.username,
                dm_message.base.secret.?.message,
            });
        }
    }
    pub fn saveToFile(self: *@This()) !void {
        var client_save = ClientSave{
            .name = self.name,
            .access_token = self.access_token,
            .lt_sign_keys = self.lt_sign_keys,
            .lt_ke_keys = self.lt_ke_keys,
        };
        var group_array = try client_save.groupMapToArray(self.allocator, self.groups);
        defer group_array.deinit(self.allocator);

        var dm_array = try client_save.dmMapToArray(self.allocator, self.dms);
        defer dm_array.deinit(self.allocator);

        var string: std.io.Writer.Allocating = .init(self.allocator);
        defer string.deinit();

        try string.writer.print("{f}", .{std.json.fmt(client_save, .{})});

        const path = try std.fmt.allocPrint(self.allocator, "data/{s}.json", .{self.name});
        defer self.allocator.free(path);

        const file = std.fs.cwd().createFile(path, .{}) catch |err| {
            std.debug.print("saveToFile: file error: {}\n", .{err});
            return err;
        };
        defer file.close();

        try file.writeAll(string.written());

        std.debug.print("saveToFile: file written with: {s}\n", .{string.written()});
    }
    pub fn fromFile(allocator: Allocator, name: []const u8) !@This() {
        const path = try std.fmt.allocPrint(allocator, "data/{s}.json", .{name});
        defer allocator.free(path);

        const file = try std.fs.cwd().openFile(path, .{});

        try file.seekTo(0);
        const raw = try file.readToEndAlloc(allocator, 4096 * 8);
        defer allocator.free(raw);

        const parsed = try std.json.parseFromSlice(
            ClientSave,
            allocator,
            raw,
            .{},
        );
        defer parsed.deinit();

        var saved_client: ClientSave = parsed.value;
        const client = Client{
            .name = name,
            .access_token = try allocator.dupe(u8, saved_client.access_token),
            .lt_sign_keys = saved_client.lt_sign_keys,
            .lt_ke_keys = saved_client.lt_ke_keys,
            .groups = try saved_client.arrayToGroupMap(allocator),
            .dms = try saved_client.arrayToDmMap(allocator),
            .allocator = allocator,
            .free_token = true,
        };
        return client;
    }
    pub fn deinit(self: *@This()) void {
        var group_it = self.groups.iterator();
        while (group_it.next()) |group| {
            group.value_ptr.*.deinit(self.allocator);
        }
        var dm_it = self.dms.iterator();
        while (dm_it.next()) |dm| {
            dm.value_ptr.*.deinit(self.allocator);
        }
        if (self.free_token) self.allocator.free(self.access_token);
        self.groups.deinit();
        self.dms.deinit();
    }
};

pub const GroupPair = struct {
    id: crypto.UUID,
    group: Group,
};

pub const DmPair = struct {
    id: crypto.UUID,
    key: Dm,
};

pub const ClientSave = struct {
    name: []const u8,
    access_token: []const u8,
    /// Long term Ed25519 signing keys
    lt_sign_keys: crypto.Ed25519.KeyPair,
    /// Long term X25519 key exchange keys
    lt_ke_keys: crypto.X25519.KeyPair,
    groups: []const GroupPair = undefined,
    dms: []const DmPair = undefined,

    pub fn groupMapToArray(self: *@This(), allocator: Allocator, group_map: HashMap(crypto.UUID, Group)) !ArrayList(GroupPair) {
        var array = ArrayList(GroupPair){};
        var it = group_map.iterator();
        while (it.next()) |group| {
            try array.append(allocator, .{
                .id = group.key_ptr.*,
                .group = group.value_ptr.*,
            });
        }
        self.groups = array.items;
        return array;
    }
    pub fn arrayToGroupMap(self: *@This(), allocator: Allocator) !HashMap(crypto.UUID, Group) {
        // This is definetly super broken.
        var hashmap = HashMap(crypto.UUID, Group).init(allocator);
        for (0..self.groups.len) |i| {
            try hashmap.put(self.groups[i].id, Group{
                .aes_key = self.groups[i].group.aes_key,
                .members = self.groups[i].group.members,
                .name = try allocator.dupe(u8, self.groups[i].group.name),
            });
        }
        return hashmap;
    }
    pub fn dmMapToArray(self: *@This(), allocator: Allocator, group_map: HashMap(crypto.UUID, Dm)) !ArrayList(DmPair) {
        var array = ArrayList(DmPair){};
        var it = group_map.iterator();
        while (it.next()) |group| {
            try array.append(allocator, .{
                .id = group.key_ptr.*,
                .key = group.value_ptr.*,
            });
        }
        self.dms = array.items;
        return array;
    }
    pub fn arrayToDmMap(self: *@This(), allocator: Allocator) !HashMap(crypto.UUID, Dm) {
        var hashmap = HashMap(crypto.UUID, Dm).init(allocator);
        for (0..self.dms.len) |i| {
            try hashmap.put(self.dms[i].id, Dm{
                .name = try allocator.dupe(u8, self.dms[i].key.name),
                .key = self.dms[i].key.key,
            });
        }
        return hashmap;
    }
};
