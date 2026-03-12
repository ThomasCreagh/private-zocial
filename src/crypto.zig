const std = @import("std");
const crypto = std.crypto;

pub fn gen_nonce(length: usize) [length]u8 {
    var nonce: [length]u8 = undefined;
    crypto.random.bytes(&nonce);
}
