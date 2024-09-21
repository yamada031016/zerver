const std = @import("std");
const tls = std.crypto.tls;
const ch = @import("ClientHello.zig");
const ClientHello = ch.ClientHello;
const sh = @import("ServerHello.zig");
const ServerHello = sh.ServerHello;
const HandshakeType = std.crypto.tls.HandshakeType;
const ContentType = std.crypto.tls.ContentType;

pub const TLSHandshakeError = error{
    IllegalParameter,
};

pub const Handshake = union(HandshakeType) {
    client_hello: ClientHandshake,
    server_hello: ServerHandshake,
    new_session_ticket: ClientHandshake,
    end_of_early_data: ClientHandshake,
    encrypted_extensions: ClientHandshake,
    certificate: ClientHandshake,
    certificate_request: ClientHandshake,
    certificate_verify: ClientHandshake,
    finished: ClientHandshake,
    key_update: ClientHandshake,
    message_hash: ClientHandshake,

    const ClientHandshake = struct {
        handshake_type: HandshakeType,
        length: ?[3]u8 = null,
        message: ClientHello,
    };
    const ServerHandshake = struct {
        handshake_type: HandshakeType,
        length: ?[3]u8 = null,
        message: ServerHello,
    };
    pub fn fromBytes(data: []u8) !Handshake {
        const handshake_type: HandshakeType = @enumFromInt(data[0]);
        const length = [_]u8{ data[1], data[2], data[3] };
        switch (handshake_type) {
            .client_hello => {
                const client_hello = try ClientHello.parse(data[4..]);
                return Handshake{ .client_hello = .{
                    .handshake_type = handshake_type,
                    .length = length,
                    .message = client_hello,
                } };
            },
            .server_hello => {
                const client_hello = try ClientHello.parse(data[4..]);
                return Handshake{ .client_hello = .{
                    .handshake_type = handshake_type,
                    .length = length,
                    .message = client_hello,
                } };
            },
            else => unreachable,
        }
    }

    pub fn init(handshake_type: HandshakeType, data: anytype) Handshake {
        switch (handshake_type) {
            .client_hello => {
                return Handshake{ .client_hello = .{
                    .handshake_type = handshake_type,
                    .message = data,
                } };
            },
            .server_hello => {
                return Handshake{ .server_hello = .{
                    .handshake_type = handshake_type,
                    .message = data,
                } };
            },
            else => unreachable,
        }
    }
};

/// It is dummy packet for compatibility.
pub const ChangeCipherSpec = struct {
    message: u8 = 1,

    pub fn toBytes(self: *const ChangeCipherSpec) ![]u8 {
        var header: [5]u8 = undefined;
        header[0] = @intFromEnum(tls.ContentType.change_cipher_spec);
        const version = @intFromEnum(tls.ProtocolVersion.tls_1_2);
        header[1] = @intCast((version & 0xFF00) >> 8);
        header[2] = @intCast(version & 0x00FF);
        var packet: [1024 * 4]u8 = undefined;
        var packet_pos: usize = 0;
        @memcpy(packet[0..3], header[0..3]);
        packet_pos += 3;

        packet[packet_pos] = 0x0; // len
        packet[packet_pos + 1] = 0x1; // len
        packet_pos += 2;
        packet[packet_pos] = self.message;
        packet_pos += 1;

        return try std.heap.page_allocator.dupe(u8, packet[0..packet_pos]);
    }
};
