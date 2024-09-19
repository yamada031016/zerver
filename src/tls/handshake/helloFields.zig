const std = @import("std");
const tls = std.crypto.tls;
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
            buf[buf_pos] = @as(u8, @intCast(@intFromEnum(ex.extension_type) & 0xFF00));
            buf[buf_pos + 1] = @as(u8, @intCast(@intFromEnum(ex.extension_type) & 0x00FF));
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
        var buf: [1024 * 2]u8 = undefined;
        @memcpy(buf[0..extensions_length], data[data_pos + 2 .. data_pos + 2 + extensions_length]);
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

pub const ExtensionList = union(ExtensionType) {
    server_name: []const u8,
    max_fragment_length,
    status_request,
    supported_groups: []std.crypto.tls.NamedGroup,
    signature_algorithms: []std.crypto.tls.SignatureScheme,
    use_srtp,
    heartbeat,
    application_layer_protocol_negotiation: [][]const u8,
    signed_certificate_timestamp,
    client_certificate_type,
    server_certificate_type,
    padding,
    pre_shared_key,
    early_data,
    supported_versions: []std.crypto.tls.ProtocolVersion,
    cookie,
    psk_key_exchange_modes,
    certificate_authorities,
    oid_filters,
    post_handshake_auth,
    signature_algorithms_cert,
    key_share: KeyShare,

    pub const KeyShare = struct {
        group: std.crypto.tls.NamedGroup,
        key_exchange: [32]u8,
    };

    pub fn init(exs: Extensions) ![]ExtensionList {
        const data = exs.extensions;
        var ex_list: [32]ExtensionList = undefined;
        var ex_pos: usize = 0;
        var skip: usize = 0;
        for (0..exs.length) |i| {
            if (1 < skip) {
                skip -= 1;
                continue;
            }
            skip = 0;
            const ex_type = (@as(u16, @intCast(data[i])) << 8) + @as(u16, data[i + 1]);
            skip += 2;
            const len = (@as(u16, @intCast(data[i + skip])) << 8) + @as(u16, data[i + skip + 1]);
            skip += 2;
            var local_skip = skip;
            skip += len;
            switch (@as(std.crypto.tls.ExtensionType, @enumFromInt(ex_type))) {
                .server_name => {
                    _ = (@as(u16, @intCast(data[i + local_skip])) << 8) + @as(u16, data[i + local_skip + 1]); // name_list_len
                    local_skip += 2;
                    _ = data[i + local_skip]; // name_type
                    local_skip += 1;
                    const name_len = (@as(u16, @intCast(data[i + local_skip])) << 8) + @as(u16, data[i + local_skip + 1]);
                    local_skip += 2;
                    const server_name = data[i + local_skip .. i + local_skip + name_len];
                    ex_list[ex_pos] = ExtensionList{ .server_name = server_name };
                    ex_pos += 1;
                },
                .supported_groups => {
                    const sp_len = (@as(u16, @intCast(data[i + local_skip])) << 8) + @as(u16, data[i + local_skip + 1]);
                    local_skip += 2;
                    var sp_groups: [36]std.crypto.tls.NamedGroup = undefined;
                    var sp_pos: usize = 0;
                    var j: usize = 0;
                    while (j < sp_len) : (j += 2) {
                        const group = (@as(u16, @intCast(data[i + local_skip + j])) << 8) + @as(u16, data[i + local_skip + j + 1]);
                        sp_groups[sp_pos] = @enumFromInt(group);
                        sp_pos += 1;
                    }
                    ex_list[ex_pos] = ExtensionList{ .supported_groups = sp_groups[0..sp_pos] };
                    ex_pos += 1;
                },
                .supported_versions => {
                    const sv_len = data[i + local_skip];
                    local_skip += 1;
                    var versions: [8]std.crypto.tls.ProtocolVersion = undefined;
                    var version_pos: usize = 0;
                    var j: usize = 0;
                    while (j < sv_len) : (j += 2) {
                        const version = (@as(u16, @intCast(data[i + local_skip + j])) << 8) + @as(u16, data[i + local_skip + j + 1]);
                        versions[version_pos] = @enumFromInt(version);
                        version_pos += 1;
                    }
                    ex_list[ex_pos] = ExtensionList{ .supported_versions = versions[0..version_pos] };
                    ex_pos += 1;
                },
                .key_share => {
                    _ = (@as(u16, @intCast(data[i + local_skip])) << 8) + @as(u16, data[i + local_skip + 1]); // client key length
                    local_skip += 2;
                    const group = (@as(u16, @intCast(data[i + local_skip])) << 8) + @as(u16, data[i + local_skip + 1]);
                    local_skip += 2;
                    const key_len = (@as(u16, @intCast(data[i + local_skip])) << 8) + @as(u16, data[i + local_skip + 1]);
                    local_skip += 2;
                    var key: [32]u8 = undefined;
                    @memcpy(&key, data[i + local_skip .. i + local_skip + key_len]);
                    // const key = data[i + local_skip .. i + local_skip + key_len];
                    ex_list[ex_pos] = ExtensionList{ .key_share = KeyShare{ .group = @enumFromInt(group), .key_exchange = key } };
                    ex_pos += 1;
                },
                .application_layer_protocol_negotiation => {
                    const alpn_len = (@as(u16, @intCast(data[i + local_skip])) << 8) + @as(u16, data[i + local_skip + 1]);
                    local_skip += 2;
                    var alpns: [8][]const u8 = undefined;
                    var alpns_pos: usize = 0;
                    var pos: usize = 0;
                    while (pos < alpn_len) {
                        const alpn_proto_len = data[i + local_skip + pos];
                        pos += 1;
                        pos += alpn_proto_len;
                        alpns[alpns_pos] = data[i + local_skip + pos .. i + local_skip + pos + alpn_proto_len];
                        alpns_pos += 1;
                    }
                    ex_list[ex_pos] = ExtensionList{ .application_layer_protocol_negotiation = alpns[0..alpns_pos] };
                    ex_pos += 1;
                },
                // .max_fragment_length => {},
                // .status_request => {},
                .signature_algorithms => {
                    const ex_len = (@as(u16, @intCast(data[i + local_skip])) << 8) + @as(u16, data[i + local_skip + 1]);
                    local_skip += 2;
                    var sigs: [32]std.crypto.tls.SignatureScheme = undefined;
                    var sigs_pos: usize = 0;
                    for (0..ex_len / 2) |_| {
                        const signature_algorithm = (@as(u16, @intCast(data[i + local_skip])) << 8) + @as(u16, data[i + local_skip + 1]);
                        local_skip += 2;
                        sigs[sigs_pos] = @enumFromInt(signature_algorithm);
                        sigs_pos += 1;
                    }
                    ex_list[ex_pos] = ExtensionList{ .signature_algorithms = sigs[0..sigs_pos] };
                    ex_pos += 1;
                },
                // .use_srtp => {},
                // .heartbeat => {},
                // .signed_certificate_timestamp => {},
                // .client_certificate_type => {},
                // .server_certificate_type => {},
                // .padding => {},
                // .pre_shared_key => {},
                // .early_data => {},
                // .cookie => {},
                // .psk_key_exchange_modes => {},
                // .certificate_authorities => {},
                // .oid_filters => {},
                // .post_handshake_auth => {},
                // .signature_algorithms_cert => {},
                else => {},
            }
        }
        return try std.heap.page_allocator.dupe(ExtensionList, ex_list[0..ex_pos]);
    }

    pub fn toBytes(self: ExtensionList) ![]u8 {
        var buf: [128]u8 = undefined;
        var buf_pos: usize = 0;
        buf[buf_pos] = @intCast((@intFromEnum(self) & 0xFF00) >> 8);
        buf[buf_pos + 1] = @intCast(@intFromEnum(self) & 0x00FF);
        buf_pos += 2;
        switch (self) {
            .server_name => |e| {
                buf[buf_pos] = @intCast((e.len & 0xFF00) >> 8);
                buf[buf_pos + 1] = @intCast(e.len & 0x00FF);
                buf_pos += 2;
                @memcpy(buf[buf_pos..e.len], e);
                buf_pos += e.len;
            },
            .supported_groups => |e| {
                buf[buf_pos] = @intCast((e.len & 0xFF00) >> 8);
                buf[buf_pos + 1] = @intCast(e.len & 0x00FF);
                buf_pos += 2;
                for (e) |v| {
                    buf[buf_pos] = @intCast((@intFromEnum(v) & 0xFF00) >> 8);
                    buf[buf_pos + 1] = @intCast(@intFromEnum(v) & 0x00FF);
                    buf_pos += 2;
                }
            },
            .signature_algorithms => |e| {
                buf[buf_pos] = @intCast((e.len & 0xFF00) >> 8);
                buf[buf_pos + 1] = @intCast(e.len & 0x00FF);
                buf_pos += 2;
                for (e) |v| {
                    buf[buf_pos] = @intCast((@intFromEnum(v) & 0xFF00) >> 8);
                    buf[buf_pos + 1] = @intCast(@intFromEnum(v) & 0x00FF);
                    buf_pos += 2;
                }
            },
            .supported_versions => |e| {
                buf[buf_pos] = 0x00;
                buf[buf_pos + 1] = 0x02;
                buf_pos += 2;
                for (e) |v| {
                    buf[buf_pos] = @intCast((@intFromEnum(v) & 0xFF00) >> 8);
                    buf[buf_pos + 1] = @intCast(@intFromEnum(v) & 0x00FF);
                    buf_pos += 2;
                }
            },
            .key_share => |e| {
                buf[buf_pos] = @intCast(((4 + e.key_exchange.len) & 0xFF00) >> 8);
                buf[buf_pos + 1] = @intCast((4 + e.key_exchange.len) & 0x00FF);
                buf_pos += 2;
                buf[buf_pos] = @intCast((@intFromEnum(e.group) & 0xFF00) >> 8);
                buf[buf_pos + 1] = @intCast(@intFromEnum(e.group) & 0x00FF);
                buf_pos += 2;
                buf[buf_pos] = @intCast((e.key_exchange.len & 0xFF00) >> 8);
                buf[buf_pos + 1] = @intCast(e.key_exchange.len & 0x00FF);
                buf_pos += 2;
                @memcpy(buf[buf_pos .. buf_pos + e.key_exchange.len], &e.key_exchange);
                buf_pos += e.key_exchange.len;
            },
            else => unreachable,
        }
        return try std.heap.page_allocator.dupe(u8, buf[0..buf_pos]);
    }
};

test "parse extension fields" {
    var version = [_]tls.ProtocolVersion{.tls_1_3};
    var supported_versions = ExtensionList{ .supported_versions = &version };
    var expect_version_byte = [_]u8{ 0x00, 0x2B, 0x00, 0x02, 0x03, 0x04 };
    try std.testing.expectEqualSlices(u8, expect_version_byte[0..], try supported_versions.toBytes());

    var key_exchange: [32]u8 = undefined;
    std.crypto.random.bytes(&key_exchange);
    const _key_share = ExtensionList.KeyShare{ .group = tls.NamedGroup.x25519, .key_exchange = key_exchange };
    const key_share = ExtensionList{ .key_share = _key_share };
    var expect_key_share: [40]u8 = undefined;
    @memcpy(expect_key_share[0..4], &[_]u8{ 0x00, 0x33, 0x00, 0x24 });
    expect_key_share[4] = @intCast((@intFromEnum(_key_share.group) & 0xFF00) >> 8);
    expect_key_share[5] = @intCast((@intFromEnum(_key_share.group) & 0x00FF));
    expect_key_share[6] = @intCast((key_exchange.len & 0xFF00) >> 8);
    expect_key_share[7] = @intCast((key_exchange.len & 0x00FF));
    @memcpy(expect_key_share[8 .. 8 + 32], &key_exchange);
    try std.testing.expectEqualSlices(u8, &expect_key_share, try key_share.toBytes());
}
