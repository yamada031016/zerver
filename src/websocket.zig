const std = @import("std");
const net = std.Io.net;
const Allocator = std.mem.Allocator;

pub fn main(init: std.process.Init) !void {
    const allocator: std.mem.Allocator = init.gpa;
    var manager = try WebSocketManager.init(init.io, allocator, 5555);
    var ws = try manager.waitConnection();
    while (true) {
        try ws.sendData("Reload!");
        ws = try manager.waitConnection();
    }
}

pub const WebSocketManager = struct {
    var server: WebSocketServer = undefined;

    allocator: Allocator,
    io: std.Io,
    listener: std.Io.net.Server,

    pub fn init(io: std.Io, allocator: Allocator, port: u16) !WebSocketManager {
        const addr = try std.Io.net.IpAddress.parse("127.0.0.1", port);
        const listener = try net.IpAddress.listen(&addr, io, .{ .reuse_address = true });
        return .{
            .allocator = allocator,
            .io = io,
            .listener = listener,
        };
    }

    pub fn waitConnection(self: *WebSocketManager) !WebSocketServer {
        while (self.listener.accept(self.io)) |conn| {
            std.log.info("Accepted Connection from: {}", .{conn.address});
            return try self.handleStream(@constCast(&conn.stream));
        } else |err| {
            return err;
        }
    }

    pub fn connect(self: *WebSocketManager) !void {
        while (self.listener.accept(self.io)) |conn| {
            std.log.info("Accepted Connection from: {}", .{conn.address});
            server = try self.handleStream(@constCast(&conn.stream));
        } else |err| {
            return err;
        }
    }

    pub fn sendData(_: *WebSocketManager, data: []const u8) !void {
        try server.sendData(data);
    }

    fn handleStream(self: *WebSocketManager, stream: *std.net.Stream) !WebSocketServer {
        var recv_buf: [2048]u8 = undefined;
        var recv_total: usize = 0;

        const reader_wrap = stream.reader(self.io, &recv_buf);
        var reader = reader_wrap.interface;

        while (true) {
            const l = try reader.takeDelimiterInclusive('\n');
            recv_total += l.len;

            if (std.mem.eql(u8, l, "\r\n\r\n")) break;
        }

        const recv_slice = recv_buf[0..recv_total];
        var request = parseRequest: {
            var _req = std.StringHashMap([]const u8).init(self.allocator);
            defer _req.deinit();
            var tok_itr = std.mem.tokenizeAny(u8, recv_slice, "\r\n");
            var method = std.mem.tokenizeAny(u8, tok_itr.next().?, " ");
            if (method.next()) |m| {
                try _req.put(m, method.rest());
            }

            while (tok_itr.next()) |req_row| {
                var req_itr = std.mem.tokenizeAny(u8, req_row, ":");
                const header = req_itr.next().?;
                const content = req_itr.rest();
                try _req.put(header, content);
            }
            break :parseRequest try _req.clone();
        };
        defer request.deinit();

        if (request.contains("Upgrade") and request.contains("Connection") and request.contains("Sec-WebSocket-Key")) {
            if (std.mem.eql(u8, request.get("Upgrade").?, " websocket") and std.mem.eql(u8, request.get("Connection").?, " Upgrade")) {
                const key = request.get("Sec-WebSocket-Key").?;
                var a = WebSocketServer{
                    .allocator = self.allocator,
                    .io = self.io,
                    .stream = stream,
                    .key = key,
                };
                try a.handshakeWebSocketOpening();
                return a;
            }
        }
        unreachable;
    }
};

pub const WebSocketServer = struct {
    allocator: Allocator,
    io: std.Io,
    stream: *std.Io.net.Stream,
    key: []const u8,

    fn deinit(self: *const WebSocketServer) void {
        self.stream.close(self.io);
    }

    pub fn readLoop(self: *const WebSocketServer) !void {
        std.log.debug("start WebSocket connection!\n", .{});
        var buf: [128]u8 = undefined;
        var reader = self.stream.reader(self.io, &buf).interface;

        while (true) {
            const l = try reader.takeDelimiterInclusive('\n');
            const first_byte = l[0];
            const _fin = first_byte & 0b10000000;
            const _rsv1 = first_byte & 0b01000000;
            const _rsv2 = first_byte & 0b00100000;
            const _rsv3 = first_byte & 0b00010000;
            const _opcode = first_byte & 0b00001111;
            if (_opcode == 0x8) break; // connection close
            std.log.debug("header: {}:{}:{}:{}:{}\n", .{ _fin, _rsv1, _rsv2, _rsv3, _opcode });

            const second_byte = l[1];
            const _mask = second_byte & 0b10000000;
            std.log.debug("mask: {}\n", .{_mask});
            var payload_len: u64 = second_byte & 0b01111111;
            var mask_key_start: usize = 2;
            switch (payload_len) {
                //Big Endian
                126 => {
                    std.log.debug("126!\n", .{});
                    const expand_payload_len = ArrayToBytes: {
                        var tmp: u16 = 0;
                        for (l[2..4], 0..) |byte, i| {
                            tmp += byte << @intCast(1 - i);
                        }
                        break :ArrayToBytes tmp;
                    };
                    payload_len = @intCast(@byteSwap(@as(u16, @intCast(payload_len)) + expand_payload_len));
                    mask_key_start = 4;
                },
                127 => {
                    std.log.debug("127!\n", .{});
                    const expand_payload_len = ArrayToBytes: {
                        var tmp: u64 = 0;
                        for (l[2..9], 0..) |byte, i| {
                            tmp += byte << @intCast(8 - i);
                        }
                        break :ArrayToBytes tmp;
                    };
                    payload_len = @byteSwap(payload_len + expand_payload_len);
                    mask_key_start = 10;
                },
                else => {},
            }

            const masking_key = if (_mask == 128) l[mask_key_start .. mask_key_start + 4] else undefined;

            if (payload_len == 0)
                continue;

            if (_mask == 128) {
                const payload_start = mask_key_start + 4;
                const encoded_payload = l[payload_start..];
                var tmp: [128]u8 = undefined;
                std.log.debug("len: {}\n", .{encoded_payload.len});
                for (encoded_payload, 0..) |byte, i| {
                    tmp[i] = byte ^ masking_key[i % 4];
                }
                std.log.debug("payload: {s}\n", .{tmp[0..payload_len]});
            } else {
                const payload_start = mask_key_start;
                const encoded_payload = l[payload_start..];
                std.log.debug("nomask payload: {s}\n", .{encoded_payload});
            }
        }
    }

    pub fn sendData(self: *WebSocketServer, data: []const u8) !void {
        var buf: [128]u8 = undefined;
        buf[0] = 0b1000_0001;
        buf[1] = @intCast(data.len);
        @memcpy(buf[2 .. 2 + data.len], data[0..]);
        var writer = self.stream.writer(self.io, &buf);
        try writer.interface.writeAll(buf[0 .. 2 + data.len]);
        std.log.debug("Reload!\n", .{});
    }

    pub fn handshakeWebSocketOpening(self: *WebSocketServer) !void {
        const magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"; // specified at RFC 6455
        const raw_key = try std.fmt.allocPrint(self.allocator, "{s}{s}", .{ self.key[1..], magic }); // keyの1文字目に空白が入っているため除外
        defer self.allocator.free(raw_key);

        var out: [20]u8 = undefined; // 20 is digest_length
        std.crypto.hash.Sha1.hash(raw_key, &out, .{});

        const encoder = std.base64.Base64Encoder.init(std.base64.standard_alphabet_chars, '=');
        var buf: [128]u8 = undefined;
        const encoded_key = encoder.encode(&buf, &out);
        const res_template =
            \\HTTP/1.1 101 Switching Protocols
            \\Upgrade: websocket
            \\Connection: Upgrade
            \\Sec-WebSocket-Accept: {s}
            \\
            \\
        ;
        const res = try std.fmt.allocPrint(self.allocator, res_template, .{encoded_key});
        std.log.debug("{s}", .{res});
        var writer = self.stream.writer(self.io, &buf);
        try writer.interface.writeAll(res);
    }
};

pub const WebSocketFormat = extern struct {
    fin: u8 = 0b1000_0001,
    // fin: u1 = 1,
    // rsv1: u1 = 0,
    // rsv2: u1 = 0,
    // rsv3: u1 = 0,
    // opcode: u4 = 0x1, // text frame
    // mask:u1 = 0,
    // payload_len:u7,
    payload_len: u8,
    // extend_payload_len:?*ExPayloadLen = null,

    const ExPayloadLen = extern union {
        payload126: u16,
        payload127: u64,
    };

    pub fn init(payload: []const u8) WebSocketFormat {
        switch (payload.len) {
            126 => return .{
                .payload_len = 126,
            },
            127 => return .{
                .payload_len = 127,
            },
            else => |len| {
                std.log.debug("less than !", .{});
                return .{
                    .payload_len = @intCast(len),
                };
            },
        }
    }
};

test "WebSocketManager init" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    _ = try WebSocketManager.init(io, allocator, 5555);
}

test "WebSocketFormat init" {
    var payload: [10]u8 = undefined;
    const fmt = WebSocketFormat.init(&payload);
    try std.testing.expect(fmt.payload_len == 10);
}
