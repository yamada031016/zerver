const std = @import("std");
const handshake = @import("handshake.zig");
const TLSHandshakeError = handshake.TLSHandshakeError;
const helloFields = @import("helloFields.zig");
const Version = helloFields.Version;
const LegacySessionId = helloFields.LegacySessionId;
const CipherSuite = helloFields.CipherSuite;
const legacyCompressionMethods = helloFields.legacyCompressionMethods;
const Extensions = helloFields.Extensions;
const ExtensionList = helloFields.ExtensionList;

pub const RawClientHello = extern struct {
    version: Version,
    random: [32]u8,
    legacy_session_id: LegacySessionId,
    cipher_suite: CipherSuite,
    legacy_compression_methods: legacyCompressionMethods = legacyCompressionMethods{},
    extensions: Extensions,

    pub fn parse(data: []u8) !RawClientHello {
        var data_pos: usize = 0;
        const version = Version.parse(data, data_pos);
        std.debug.print("version: {x:0>2}{x:0>2}.\n", .{ data[0], data[1] });
        data_pos += 2;

        const random = getRandom: {
            var buf: [32]u8 = undefined;
            @memcpy(&buf, data[data_pos .. data_pos + 32]);
            break :getRandom buf;
        };
        data_pos += 32;

        const legacy_session_id = LegacySessionId.parse(data, data_pos);
        data_pos += 1 + legacy_session_id.length;
        std.debug.print("session_id: {any} len({}).\n", .{ legacy_session_id.session_id, legacy_session_id.length });

        const cipher_suite = CipherSuite.parse(data, data_pos);
        data_pos += 2 + cipher_suite.count;

        const legacy_compression_methods_length = data[data_pos];
        data_pos += 1;
        if (legacy_compression_methods_length == 0x01 and data[data_pos] != 0x00) {
            std.debug.print("invalid legacy_compression_methods: {}\n", .{data[data_pos]});
            return TLSHandshakeError.IllegalParameter;
        }
        data_pos += 1;

        const extensions = Extensions.parse(data, data_pos);
        data_pos += extensions.length;

        return RawClientHello{
            .version = version,
            .random = random,
            .legacy_session_id = legacy_session_id,
            .cipher_suite = cipher_suite,
            .extensions = extensions,
        };
    }
};

pub const ClientHello = struct {
    version: std.crypto.tls.ProtocolVersion,
    random: [32]u8,
    legacy_session_id: LegacySessionId,
    cipher_suite: []std.crypto.tls.CipherSuite,
    legacy_compression_methods: legacyCompressionMethods = legacyCompressionMethods{},
    extensions: []ExtensionList,

    pub fn parse(data: []u8) !ClientHello {
        var data_pos: usize = 0;
        const version = parse: {
            const tmp = (@as(u16, @intCast(data[data_pos])) << 8) + @as(u16, data[data_pos + 1]);
            break :parse @as(std.crypto.tls.ProtocolVersion, @enumFromInt(tmp));
        };
        std.debug.print("version: {any}.\n", .{version});
        data_pos += 2;

        const random = getRandom: {
            var buf: [32]u8 = undefined;
            @memcpy(&buf, data[data_pos .. data_pos + 32]);
            break :getRandom buf;
        };
        data_pos += random.len;

        const legacy_session_id = LegacySessionId.parse(data, data_pos);
        data_pos += 1 + legacy_session_id.length;
        std.debug.print("session_id: {any} len({}).\n", .{ legacy_session_id.session_id, legacy_session_id.length });

        const cipher_suite = parse: {
            const cipher_suites_count: u16 = (@as(u16, @intCast(data[data_pos])) << 8) + @as(u16, data[data_pos + 1]);
            data_pos += 2;

            var _cipher_suites: [40]std.crypto.tls.CipherSuite = undefined;
            for (0..cipher_suites_count / 2) |i| {
                const tmp = (@as(u16, @intCast(data[data_pos])) << 8) + @as(u16, data[data_pos + 1]);
                _cipher_suites[i] = @as(std.crypto.tls.CipherSuite, @enumFromInt(tmp));
                std.debug.print("cipher suites: {any}\n", .{_cipher_suites[i]});
                data_pos += 2;
            }
            break :parse _cipher_suites[0 .. cipher_suites_count / 2];
        };

        const legacy_compression_methods_length = data[data_pos];
        data_pos += 1;
        if (legacy_compression_methods_length == 0x01 and data[data_pos] != 0x00) {
            std.debug.print("invalid legacy_compression_methods: {}\n", .{data[data_pos]});
            return TLSHandshakeError.IllegalParameter;
        }
        data_pos += 1;

        const extensions = Extensions.parse(data, data_pos);
        data_pos += extensions.length;
        const ex_list = try ExtensionList.init(extensions);

        return ClientHello{
            .version = version,
            .random = random,
            .legacy_session_id = legacy_session_id,
            .cipher_suite = cipher_suite,
            .extensions = ex_list,
        };
    }
};
