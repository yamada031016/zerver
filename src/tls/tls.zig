const std = @import("std");
const HandshakeType = std.crypto.tls.HandshakeType;
const ContentType = std.crypto.tls.ContentType;
const Handshake = @import("handshake/handshake.zig").Handshake;

pub const TLSRecordLayer = struct {
    content_type: ContentType,
    version: u16 = 0x0303,
    length: u16,
    data: Handshake,

    pub fn init(content_type: ContentType, content: Handshake) TLSRecordLayer {
        return TLSRecordLayer{
            .content_type = content_type,
            .length = content.len,
        };
    }

    pub fn parse(data: []u8) !TLSRecordLayer {
        const content_type: ContentType = @enumFromInt(data[0]);
        const version = (data[1] << 1) + data[2];
        const length = (data[3] << 1) + data[4];
        const handshake = try Handshake.parse(data[5..]);

        return TLSRecordLayer{
            .content_type = content_type,
            .version = version,
            .length = length,
            .data = handshake,
        };
    }
};
