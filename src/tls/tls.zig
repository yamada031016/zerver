const std = @import("std");
const tls = std.crypto.tls;
const HandshakeType = std.crypto.tls.HandshakeType;
const ContentType = std.crypto.tls.ContentType;
const Handshake = @import("handshake/content.zig").Handshake;

pub const TLSRecordLayer = struct {
    content_type: ContentType,
    version: u16 = 0x0303,
    length: u16,
    data: Handshake,

    pub fn init(content_type: ContentType, content: Handshake) TLSRecordLayer {
        return TLSRecordLayer{
            .content_type = content_type,
            .length = content.server_hello.length,
            .data = content,
        };
    }

    pub fn toBytes(self: *const TLSRecordLayer) ![]u8 {
        var header: [5]u8 = undefined;
        header[0] = @intFromEnum(tls.ContentType.handshake);
        const version = @intFromEnum(self.version);
        header[1] = @intCast((version & 0xFF00) >> 8);
        header[2] = @intCast(version & 0x00FF);
        var packet: [1024 * 4]u8 = undefined;
        var packet_pos: usize = 0;
        @memcpy(packet[0..3], header[0..3]);
        packet_pos += 3;
    }

    pub fn fromBytes(data: []u8) !TLSRecordLayer {
        const content_type: ContentType = @enumFromInt(data[0]);
        const version = (data[1] << 1) + data[2];
        const length = (data[3] << 1) + data[4];
        const handshake = try Handshake.fromBytes(data[5..]);

        return TLSRecordLayer{
            .content_type = content_type,
            .version = version,
            .length = length,
            .data = handshake,
        };
    }
};
