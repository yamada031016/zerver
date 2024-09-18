const std = @import("std");
const ExtensionType = std.crypto.tls.ExtensionType;
const handshake = @import("handshake.zig");
const TLSHandshakeError = handshake.TLSHandshakeError;
const helloFields = @import("helloFields.zig");
const Version = helloFields.Version;
const LegacySessionId = helloFields.LegacySessionId;
const CipherSuite = helloFields.CipherSuite;
const legacyCompressionMethods = helloFields.legacyCompressionMethods;
const Extensions = helloFields.Extensions;
const ExtensionField = helloFields.ExtensionField;
const ch = @import("ClientHello.zig");
const RawClientHello = ch.RawClientHello;

pub const ServerHello = extern struct {
    version: Version,
    random: [32]u8,
    legacy_session_id_echo: LegacySessionId,
    cipher_suite: CipherSuite,
    legacy_compression_methods: legacyCompressionMethods = legacyCompressionMethods{},
    extensions: Extensions,

    pub fn parse(client_hello: RawClientHello) !ServerHello {
        var random: [32]u8 = undefined;
        std.crypto.random.bytes(&random);
        const cipher_suite = choice: {
            for (client_hello.cipher_suite.cipher_suites) |suite| {
                switch (suite) {
                    0x1301...0x1307 => {
                        const cipher_suite: std.crypto.tls.CipherSuite = @enumFromInt(suite);
                        std.debug.print("suite: {any}\n", .{cipher_suite});
                        break :choice cipher_suite;
                    },
                    else => {
                        // std.debug.print("Not support suite: 0x{x}", suite);
                    },
                }
            }
            unreachable;
        };
        const secret_key = [32]u8{ 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf };
        const key_pair = try std.crypto.dh.X25519.KeyPair.create(secret_key);
        var key_share: [37]u8 = undefined;
        const key_share_header = [6]u8{ 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20 };
        @memcpy(key_share[0..6], &key_share_header);
        @memcpy(key_share[5..], &key_pair.public_key);
        var version = [_]u8{ 0x03, 0x04 };
        var pre_shared_key = [_]u8{ 0x00, 0x00 };
        const extension = .{
            ExtensionField{ .extension_type = .supported_versions, .length = [_]u8{ 0, 0, 2 }, .extension = &version },
            ExtensionField{ .extension_type = .pre_shared_key, .length = [_]u8{ 0, 0, 2 }, .extension = &pre_shared_key },
            ExtensionField{ .extension_type = .key_share, .length = [_]u8{ 0, 0, 0x38 }, .extension = &key_share },
        };
        const extensions = Extensions.init(extension);
        return ServerHello{
            .version = Version{ .major = 0x03, .minor = 0x03 },
            .random = random,
            .cipher_suite = CipherSuite{ .count = 1, .cipher_suites = [_]u16{@intFromEnum(cipher_suite)} ** 64 },
            .legacy_session_id_echo = client_hello.legacy_session_id,
            .extensions = extensions,
        };
    }
};

test "encrypt_key_share_by_X25519" {
    const secret_key = [32]u8{ 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf };
    const public_key = [32]u8{ 0x9f, 0xd7, 0xad, 0x6d, 0xcf, 0xf4, 0x29, 0x8d, 0xd3, 0xf9, 0x6d, 0x5b, 0x1b, 0x2a, 0xf9, 0x10, 0xa0, 0x53, 0x5b, 0x14, 0x88, 0xd7, 0xf8, 0xfa, 0xbb, 0x34, 0x9a, 0x98, 0x28, 0x80, 0xb6, 0x15 };
    const key_pair = try std.crypto.dh.X25519.KeyPair.create(secret_key);
    std.log.info("secret_key: {x}\npublic_key: {x}", .{ key_pair.secret_key, key_pair.public_key });
    try std.testing.expectEqual(key_pair.public_key, public_key);
}
