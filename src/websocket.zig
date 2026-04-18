const std = @import("std");
const net = std.Io.net;
const Allocator = std.mem.Allocator;

// refactor version
// pub fn newMain() !void {
//     var gpa = std.heap.GeneralPurposeAllocator(.{}){};
//     const allocator = gpa.allocator();
//
//     var server = try Server.init(allocator, 5555);
//     try server.run();
// }
//
// pub const Server = struct {
//     listener: std.Io.net.Server,
//     allocator: std.mem.Allocator,
//
//     pub fn init(allocator: std.mem.Allocator, port: u16) !Server {
//         const addr = try std.Io.net.Address.parseIp4("127.0.0.1", port);
//         const listener = try addr.listen(.{ .reuse_address = true });
//
//         return .{
//             .listener = listener,
//             .allocator = allocator,
//         };
//     }
//
//     pub fn run(self: *Server) !void {
//         while (true) {
//             const conn = try self.listener.accept();
//
//             _ = try std.Thread.spawn(.{}, handleClient, .{ self.allocator, conn });
//         }
//     }
// };
//
// fn handleClient(allocator: std.mem.Allocator, conn: std.Io.net.Stream) !void {
//     var connection = Connection.init(allocator, &conn);
//     connection.state = .Handshaking;
//
//     try connection.run();
// }
//
// pub const Connection = struct {
//     stream: *std.Io.net.Stream,
//     allocator: Allocator,
//
//     state: enum {
//         Handshaking,
//         Open,
//         Closing,
//         Closed,
//     },
//
//     read_buf: []u8,
//     write_buf: []u8,
//
//     pub fn run(self: *Connection) !void {
//         try self.handleHandshake();
//         try self.readLoop();
//     }
//
//     fn handshake(self: *Connection) !void {
//         var buf: [2048]u8 = undefined;
//         var reader = self.stream.reader();
//
//         var total: usize = 0;
//         while (true) {
//             const n = try reader.read(buf[total..]);
//             total += n;
//
//             if (std.mem.indexOf(u8, buf[0..total], "\r\n\r\n") != null) break;
//         }
//
//         const req = buf[0..total];
//
//         const key = try extractWebSocketKey(req);
//
//         const accept_key = try buildAcceptKey(self.allocator, key);
//         defer self.allocator.free(accept_key);
//
//         const response = try std.fmt.allocPrint(self.allocator,
//             \\HTTP/1.1 101 Switching Protocols\r
//             \\Upgrade: websocket\r
//             \\Connection: Upgrade\r
//             \\Sec-WebSocket-Accept: {s}\r
//             \\r
//         , .{accept_key});
//         defer self.allocator.free(response);
//
//         try self.stream.writeAll(response);
//     }
//
//     fn extractWebSocketKey(req: []const u8) ![]const u8 {
//         var it = std.mem.splitAny(u8, req, "\r\n");
//
//         while (it.next()) |line| {
//             if (std.mem.startsWith(u8, line, "Sec-WebSocket-Key:")) {
//                 return std.mem.trim(u8, line["Sec-WebSocket-Key:".len..], " ");
//             }
//         }
//         return error.InvalidHandshake;
//     }
//
//     fn buildAcceptKey(allocator: std.mem.Allocator, key: []const u8) ![]u8 {
//         const magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
//
//         const combined = try std.fmt.allocPrint(allocator, "{s}{s}", .{ key, magic });
//         defer allocator.free(combined);
//
//         var hash: [20]u8 = undefined;
//         std.crypto.hash.Sha1.hash(combined, &hash, .{});
//
//         return try std.base64.standard.Encoder.encodeAlloc(allocator, &hash);
//     }
//
//     fn sendText(self: *Connection, msg: []const u8) !void {
//         var buf: [10]u8 = undefined;
//
//         buf[0] = 0x81; // FIN + text
//         buf[1] = @intCast(msg.len);
//
//         try self.stream.writeAll(buf[0..2]);
//         try self.stream.writeAll(msg);
//     }
//
//     fn sendPong(self: *Connection) !void {
//         try self.stream.writeAll(&[_]u8{ 0x8A, 0x00 });
//     }
//
//     fn readLoop(self: *Connection) !void {
//         var reader = self.stream.reader();
//
//         self.state = .Open;
//
//         while (self.state == .Open) {
//             const frame = try readFrame(self.allocator, &reader.interface);
//             defer self.allocator.free(frame.payload);
//
//             switch (frame.opcode) {
//                 // text frame
//                 0x1 => {
//                     std.log.info("recv: {s}", .{frame.payload});
//
//                     // echo
//                     try self.sendText(frame.payload);
//                 },
//
//                 // close
//                 0x8 => {
//                     std.log.info("client requested close", .{});
//                     self.state = .Closing;
//
//                     // close frame返す（最小）
//                     try self.stream.writeAll(&[_]u8{ 0x88, 0x00 });
//
//                     self.state = .Closed;
//                     return;
//                 },
//
//                 // ping
//                 0x9 => {
//                     std.log.info("ping received", .{});
//                     try self.sendPong();
//                 },
//
//                 // pong
//                 0xA => {
//                     // 無視でOK
//                 },
//
//                 else => {
//                     std.log.warn("unsupported opcode: {}", .{frame.opcode});
//                     return error.UnsupportedFrame;
//                 },
//             }
//         }
//     }
// };
//
// const Frame = struct {
//     opcode: u4,
//     payload: []u8,
// };
//
// fn readFrame(allocator: std.mem.Allocator, reader: anytype) !Frame {
//     var header: [2]u8 = undefined;
//     try reader.readNoEof(&header);
//
//     const opcode = header[0] & 0x0F;
//     const masked = (header[1] & 0x80) != 0;
//     var len: usize = header[1] & 0x7F;
//
//     if (len == 126) {
//         var buf: [2]u8 = undefined;
//         try reader.readNoEof(&buf);
//         len = std.mem.readInt(u16, &buf, .big);
//     } else if (len == 127) {
//         var buf: [8]u8 = undefined;
//         try reader.readNoEof(&buf);
//         len = std.mem.readInt(u64, &buf, .big);
//     }
//
//     var mask: [4]u8 = undefined;
//     if (masked) {
//         try reader.readNoEof(&mask);
//     }
//
//     const payload = try allocator.alloc(u8, len);
//     try reader.readNoEof(payload);
//
//     if (masked) {
//         for (payload, 0..) |*b, i| {
//             b.* ^= mask[i % 4];
//         }
//     }
//
//     return Frame{
//         .opcode = @intCast(opcode),
//         .payload = payload,
//     };
// }
//
// test "extract websocket key" {
//     const req =
//         \\GET / HTTP/1.1\r
//         \\Host: localhost\r
//         \\Upgrade: websocket\r
//         \\Connection: Upgrade\r
//         \\Sec-WebSocket-Key: abc123==\r
//         \\\r
//     ;
//
//     const key = try Connection.extractWebSocketKey(req);
//     try std.testing.expectEqualStrings("abc123==", key);
// }
//
// test "build accept key RFC example" {
//     const allocator = std.testing.allocator;
//
//     const key = "dGhlIHNhbXBsZSBub25jZQ==";
//     const expected = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
//
//     const result = try Connection.buildAcceptKey(allocator, key);
//     defer allocator.free(result);
//
//     try std.testing.expectEqualStrings(expected, result);
// }
//
// test "read simple text frame" {
//     const allocator = std.testing.allocator;
//
//     // "hi"
//     const frame_bytes = [_]u8{ 0x81, 0x02, 'h', 'i' };
//
//     var stream = std.io.fixedBufferStream(&frame_bytes);
//     const reader = stream.reader();
//
//     const frame = try readFrame(allocator, reader);
//     defer allocator.free(frame.payload);
//
//     try std.testing.expect(frame.opcode == 1);
//     try std.testing.expectEqualStrings("hi", frame.payload);
// }
//
// test "websocket echo e2e" {
//     var gpa = std.heap.GeneralPurposeAllocator(.{}){};
//     const allocator = gpa.allocator();
//
//     const port: u16 = 5556;
//
//     // サーバ起動
//     var server = try Server.init(allocator, port);
//     _ = try std.Thread.spawn(.{}, server.run, .{&server});
//
//     std.time.sleep(100 * std.time.ns_per_ms); // 起動待ち
//
//     // クライアント接続
//     const addr = try std.net.Address.parseIp4("127.0.0.1", port);
//     var stream = try std.net.tcpConnectToAddress(addr);
//     defer stream.close();
//
//     // --- handshake ---
//     const req =
//         \\GET / HTTP/1.1\r
//         \\Host: localhost\r
//         \\Upgrade: websocket\r
//         \\Connection: Upgrade\r
//         \\Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r
//         \\\r
//     ;
//
//     try stream.writeAll(req);
//
//     var buf: [1024]u8 = undefined;
//     _ = try stream.read(&buf);
//
//     // --- frame送信 ---
//     // "hi" (masked)
//     const frame = [_]u8{
//         0x81,
//         0x82, // masked + len=2
//         0x12,       0x34,       0x56, 0x78, // mask
//         'h' ^ 0x12, 'i' ^ 0x34,
//     };
//
//     try stream.writeAll(&frame);
//
//     // --- echo受信 ---
//     var recv: [10]u8 = undefined;
//     const n = try stream.read(&recv);
//
//     // 0x81 0x02 'h' 'i'
//     try std.testing.expect(n >= 4);
//     try std.testing.expect(recv[0] == 0x81);
//     try std.testing.expect(recv[1] == 0x02);
//     try std.testing.expect(recv[2] == 'h');
//     try std.testing.expect(recv[3] == 'i');
// }

pub fn main(init: std.process.Init) !void {
    const allocator: std.mem.Allocator = init.gpa;
    var manager = try WebSocketManager.init(init.io, allocator, 5555);
    var ws = try manager.waitConnection();
    while (true) {
        try ws.sendData("Reload!");
        ws = try manager.waitConnection();
    }
}

pub const WebSocketRequestParser = struct {
    allocator: Allocator,

    pub fn parse(self: *WebSocketRequestParser, recv_slice: []const u8) !std.StringHashMap([]const u8) {
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
        return try _req.clone();
    }
};

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
            const ip4 = conn.socket.address.ip4;
            std.log.info("Accepted Connection from: {s}:{d}", .{ ip4.bytes, ip4.port });
            return try self.handleStream(@constCast(&conn.stream));
        } else |err| {
            return err;
        }
    }

    // Use for Thread.spawn.
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

    fn handleStream(self: *WebSocketManager, stream: *std.Io.net.Stream) !WebSocketServer {
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
        var parser = WebSocketRequestParser{ .allocator = self.allocator };
        var request = try parser.parse(recv_slice);
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
