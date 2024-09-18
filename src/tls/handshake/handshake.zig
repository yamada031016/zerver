const std = @import("std");
const ch = @import("ClientHello.zig");
const RawClientHello = ch.RawClientHello;
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
        length: [3]u8,
        message: RawClientHello,
    };
    const ServerHandshake = struct {
        handshake_type: HandshakeType,
        length: [3]u8,
        message: ServerHello,
    };
    pub fn parse(data: []u8) !Handshake {
        const handshake_type: HandshakeType = @enumFromInt(data[0]);
        const length = [_]u8{ data[1], data[2], data[3] };
        switch (handshake_type) {
            .client_hello => {
                const client_hello = try RawClientHello.parse(data[4..]);
                return Handshake{ .client_hello = .{
                    .handshake_type = handshake_type,
                    .length = length,
                    .message = client_hello,
                } };
            },
            .server_hello => {
                const client_hello = try RawClientHello.parse(data[4..]);
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
                    .length = data.len,
                    .message = data,
                } };
            },
            .server_hello => {
                return Handshake{ .server_hello = .{
                    .handshake_type = handshake_type,
                    .length = data.len,
                    .message = data,
                } };
            },
            else => unreachable,
        }
    }
};
