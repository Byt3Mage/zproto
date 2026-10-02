const std = @import("std");
const zPortoKey = std.crypto.dh.X25519;
const zProtoSymmetric = std.crypto.kdf.hkdf.HkdfSha256;
const chachapoly = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const zProtoErrors = std.crypto.errors;

// Nonce struct
const Nonce = struct {
   counter: u64 = 0,

    pub fn next(self: *Nonce) [chachapoly.nonce_length]u8 {
        var buffer_nonce = [_]u8{0} ** chachapoly.nonce_length;
        std.mem.writeInt(u64, buffer_nonce[0..8], self.counter, .little);
        self.counter += 1;
        return buffer_nonce;
    }
};

// generate public and private keys
pub fn generateKey(io: std.Io) zPortoKey.KeyPair {
    return zPortoKey.KeyPair.generate(io);
}

// do DH symmetric stuff then hash the result and return it
pub fn getSharedKsymetric(secret_key: [zPortoKey.secret_length]u8, public_key: [zPortoKey.public_length]u8) ![32]u8 {
    const ourK = try zPortoKey.scalarmult(secret_key, public_key);
    const fake = [_]u8{0} ** 32;
    return zProtoSymmetric.extract(&fake, &ourK);
}

// Encrypting
pub fn zProtoEncrypt(nounce: *Nonce, out_data: []u8, tag: *[chachapoly.tag_length]u8, in_data: []const u8, out_nonce: *[chachapoly.nonce_length]u8, symetric_key: [zProtoSymmetric.prk_length]u8) !void {
    const current_nounce = nounce.next();
    out_nonce.* = current_nounce;
    return chachapoly.encrypt(out_data, tag, in_data, &.{}, out_nonce.*, symetric_key);
}

// Decrypt
pub fn zProtoDecrypt(out_data: []u8, in_data: []const u8, tag: [chachapoly.tag_length]u8, in_nonce: [chachapoly.nonce_length]u8, symmetricKey: [zProtoSymmetric.prk_length]u8) !void {
    return chachapoly.decrypt(out_data, in_data, tag, &.{}, in_nonce, symmetricKey);
}
