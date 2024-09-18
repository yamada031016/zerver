const std = @import("std");
const ExtensionType = std.crypto.tls.ExtensionType;

pub const Version = extern struct {
    major: u8,
    minor: u8,
    pub fn parse(data: []u8, data_pos: usize) Version {
        if (data_pos != 0) {
            unreachable;
        }
        return Version{ .major = data[0], .minor = data[1] };
    }
};

pub const LegacySessionId = extern struct {
    length: u8,
    session_id: [32]u8,
    pub fn parse(data: []u8, data_pos: usize) LegacySessionId {
        const legacy_session_id_length = data[data_pos];
        var buf: [32]u8 = undefined;
        @memcpy(&buf, data[data_pos + 1 .. data_pos + 1 + 32]);
        return LegacySessionId{
            .length = legacy_session_id_length,
            .session_id = buf,
        };
    }
};

pub const CipherSuite = extern struct {
    count: u16,
    cipher_suites: [64]u16,
    pub fn parse(data: []u8, _data_pos: usize) CipherSuite {
        var data_pos = _data_pos;
        const cipher_suites_count: u16 = (@as(u16, @intCast(data[data_pos])) << 8) + @as(u16, data[data_pos + 1]);
        data_pos += 2;
        var suite_buf: [64]u16 = undefined;
        for (0..cipher_suites_count / 2) |i| {
            suite_buf[i] = (@as(u16, @intCast(data[data_pos])) << 8) + @as(u16, data[data_pos + 1]);
            // std.debug.print("cipher suites: {x:0>2}{x:0>2} ({}).\n", .{ data[data_pos], data[data_pos + 1], cipher_suites_count / 2 });
            data_pos += 2;
        }
        return CipherSuite{ .count = cipher_suites_count, .cipher_suites = suite_buf };
    }
};

pub const legacyCompressionMethods = extern struct {
    length: u8 = 0x01,
    legacy_compression_methods: u8 = 0x00, // Every TLS1.3 ClientHello, this field MUST set 0 (1byte)
};

pub const Extensions = extern struct {
    length: u16,
    extensions: [1024 * 2]u8,

    pub fn init(extensions: anytype) Extensions {
        var buf: [1024 * 2]u8 = undefined;
        var buf_pos: usize = 0;
        inline for (extensions) |ex| {
            buf[buf_pos] = @as(u8, @intCast(@intFromEnum(ex.extension_type) & 0x1100));
            buf[buf_pos + 1] = @as(u8, @intCast(@intFromEnum(ex.extension_type) & 0x0011));
            buf[buf_pos + 2] = (ex.length[0]);
            buf[buf_pos + 3] = (ex.length[1]);
            buf[buf_pos + 4] = (ex.length[2]);
            buf_pos += 5;
            @memcpy(buf[buf_pos .. buf_pos + ex.extension.len], ex.extension);
            buf_pos += ex.extension.len;
        }
        return Extensions{
            .length = @intCast(buf_pos),
            .extensions = buf,
        };
    }

    pub fn parse(data: []u8, data_pos: usize) Extensions {
        const extensions_length = (@as(u16, @intCast(data[data_pos])) << 8) + @as(u16, data[data_pos + 1]);
        // std.debug.print("len: {}\n", .{extensions_length});
        var buf: [1024 * 2]u8 = undefined;
        @memcpy(buf[0..extensions_length], data[data_pos + 2 .. data_pos + 2 + extensions_length]);
        // std.debug.print("extentions: {} len({}).\n", .{ buf[0..extensions_length], extensions_length });
        return Extensions{ .length = extensions_length, .extensions = buf };
    }
};

// High level interface for each extensions.
pub const ExtensionField = struct {
    extension_type: ExtensionType,
    length: [3]u8,
    // extension: usize,
    extension: []u8,
};
