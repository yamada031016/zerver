const std = @import("std");
const net = std.net;

pub fn main() !void {
    var manager = try WebSocketManager.init(5555);
    var ws = try manager.waitConnection();
    while (true) {
        try ws.sendData("Reload!");
        ws = try manager.waitConnection();
    }
}

pub const WebSocketManager = struct {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    var server: WebSocketServer = undefined;

    listener: std.net.Server,

    pub fn init(port: u16) !WebSocketManager {
        var self_port_addr = port;
        // avoid bug in Windows where
        // resolveIp() tries to force the argument to resolve to IPv6
        // https://github.com/ziglang/zig/issues/20530
        var self_addr = avoid: {
            switch (@import("builtin").os.tag) {
                .windows => {
                    break :avoid net.Address.initIp4(.{ 127, 0, 0, 1 }, self_port_addr);
                },
                else => break :avoid try net.Address.resolveIp("127.0.0.1", self_port_addr),
            }
        };
        const listener = listen: {
            while (true) {
                if (net.Address.listen(self_addr, .{})) |_listener| {
                    break :listen _listener;
                } else |err| {
                    switch (err) {
                        error.AddressInUse => {
                            std.log.info("port :{} is already in use.\n", .{self_port_addr});
                            self_port_addr += 1;
                            self_addr = avoid: {
                                switch (@import("builtin").os.tag) {
                                    .windows => {
                                        break :avoid net.Address.initIp4(.{ 127, 0, 0, 1 }, self_port_addr);
                                    },
                                    else => break :avoid try net.Address.resolveIp("127.0.0.1", self_port_addr),
                                }
                            };
                        },
                        else => std.log.err("{s}\n", .{@errorName(err)}),
                    }
                }
            }
        };
        return .{
            .listener = listener,
        };
    }

    pub fn waitConnection(self: *WebSocketManager) !WebSocketServer {
        while (self.listener.accept()) |conn| {
            std.log.info("Accepted Connection from: {}", .{conn.address});
            return try self.handleStream(@constCast(&conn.stream));
        } else |err| {
            return err;
        }
    }

    pub fn connect(self: *WebSocketManager) !void {
        while (self.listener.accept()) |conn| {
            std.log.info("Accepted Connection from: {}", .{conn.address});
            server = try self.handleStream(@constCast(&conn.stream));
        } else |err| {
            return err;
        }
    }

    pub fn sendData(_: *WebSocketManager, data: []const u8) !void {
        try server.sendData(data);
    }

    fn handleStream(_: *WebSocketManager, stream: *std.net.Stream) !WebSocketServer {
        var recv_buf: [2048]u8 = undefined;
        var recv_total: usize = 0;
        while (stream.read(recv_buf[0..])) |recv_len| {
            recv_total += recv_len;
            if (std.mem.containsAtLeast(u8, recv_buf[0..recv_total], 1, "\r\n\r\n"))
                break;
        } else |read_err| {
            return read_err;
        }
        const recv_slice = recv_buf[0..recv_total];
        var request = parseRequest: {
            var _req = std.StringHashMap([]const u8).init(std.heap.page_allocator);
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
    stream: *std.net.Stream,
    key: []const u8,

    fn deinit(self: *const WebSocketServer) void {
        self.stream.close();
    }

    pub fn readLoop(self: *const WebSocketServer) !void {
        std.log.debug("start WebSocket connection!\n", .{});
        var buf: [128]u8 = undefined;
        while (self.stream.read(&buf)) |_| {
            const first_byte = buf[0];
            const _fin = first_byte & 0b10000000;
            const _rsv1 = first_byte & 0b01000000;
            const _rsv2 = first_byte & 0b00100000;
            const _rsv3 = first_byte & 0b00010000;
            const _opcode = first_byte & 0b00001111;
            if (_opcode == 0x8) break; // connection close
            std.log.debug("header: {}:{}:{}:{}:{}\n", .{ _fin, _rsv1, _rsv2, _rsv3, _opcode });

            const second_byte = buf[1];
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
                        for (buf[2..4], 0..) |byte, i| {
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
                        for (buf[2..9], 0..) |byte, i| {
                            tmp += byte << @intCast(8 - i);
                        }
                        break :ArrayToBytes tmp;
                    };
                    payload_len = @byteSwap(payload_len + expand_payload_len);
                    mask_key_start = 10;
                },
                else => {},
            }

            const masking_key = if (_mask == 128) buf[mask_key_start .. mask_key_start + 4] else undefined;

            if (payload_len == 0)
                continue;

            if (_mask == 128) {
                const payload_start = mask_key_start + 4;
                const encoded_payload = buf[payload_start..];
                var tmp: [128]u8 = undefined;
                std.log.debug("len: {}\n", .{encoded_payload.len});
                for (encoded_payload, 0..) |byte, i| {
                    tmp[i] = byte ^ masking_key[i % 4];
                }
                std.log.debug("payload: {s}\n", .{tmp[0..payload_len]});
            } else {
                const payload_start = mask_key_start;
                const encoded_payload = buf[payload_start..];
                std.log.debug("nomask payload: {s}\n", .{encoded_payload});
            }
        } else |err| {
            std.log.err("Failed to accept connection: {}", .{err});
            return err;
        }
    }

    pub fn sendData(self: *WebSocketServer, data: []const u8) !void {
        var buf: [128]u8 = undefined;
        buf[0] = 0b1000_0001;
        buf[1] = @intCast(data.len);
        @memcpy(buf[2 .. 2 + data.len], data[0..]);
        try self.stream.writer().writeAll(buf[0 .. 2 + data.len]);
        std.log.debug("Reload!\n", .{});
    }

    pub fn handshakeWebSocketOpening(self: *WebSocketServer) !void {
        const magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"; // specified at RFC 6455
        const raw_key = try std.fmt.allocPrintZ(std.heap.page_allocator, "{s}{s}", .{ self.key[1..], magic }); // keyの1文字目に空白が入っているため除外
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
        const res = try std.fmt.allocPrintZ(std.heap.page_allocator, res_template, .{encoded_key});
        std.log.debug("{s}", .{res});
        try self.stream.writer().writeAll(res);
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
