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
            std.debug.print("cipher suites: {any}\n", .{@as(std.crypto.tls.CipherSuite, @enumFromInt(suite_buf[i]))});
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

    const KeyShare = struct {
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
            std.debug.print("{any}\n", .{@as(std.crypto.tls.ExtensionType, @enumFromInt(ex_type))});
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
                    std.debug.print("{s}\n", .{server_name});
                    ex_list[ex_pos] = ExtensionList{ .server_name = server_name };
                    ex_pos += 1;
                },
                .supported_groups => {
                    const sp_len = (@as(u16, @intCast(data[i + local_skip])) << 8) + @as(u16, data[i + local_skip + 1]);
                    std.debug.print("{any}\n", .{data[i .. i + local_skip + 20]});
                    std.debug.print("len: {}, sp_len: {}\n", .{ len, sp_len });
                    local_skip += 2;
                    var sp_groups: [36]std.crypto.tls.NamedGroup = undefined;
                    var sp_pos: usize = 0;
                    var j: usize = 0;
                    while (j < sp_len) : (j += 2) {
                        const group = (@as(u16, @intCast(data[i + local_skip + j])) << 8) + @as(u16, data[i + local_skip + j + 1]);
                        std.debug.print("supported_group: {any}\n", .{@as(std.crypto.tls.NamedGroup, @enumFromInt(group))});
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
                        std.debug.print("TLS version support: {any}\n", .{@as(std.crypto.tls.ProtocolVersion, @enumFromInt(version))});
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
                    std.debug.print("[{any}]{s}\n", .{ @as(std.crypto.tls.NamedGroup, @enumFromInt(group)), key });
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
                        std.debug.print("{s}\n", .{data[i + local_skip + pos .. i + local_skip + pos + alpn_proto_len]});
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
                        std.debug.print("signature algoritms: {any}\n", .{@as(std.crypto.tls.SignatureScheme, @enumFromInt(signature_algorithm))});
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
                else => {
                    std.debug.print("len({}), {any}\n", .{ len, data[i .. i + skip + len] });
                },
            }
        }
        return ex_list[0..ex_pos];
    }
};
