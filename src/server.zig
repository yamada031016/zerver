const std = @import("std");
const net = std.Io.net;
const mem = std.mem;
const fs = std.fs;
const log = std.log;
const gzip = @import("gzip.zig");

const Mime = @import("mime.zig").Mime;

const ExecuteOptions = @import("main.zig").ExecuteOptions;

// these are to be used with the async/await functions.
const Request = struct {
    frame: anyframe,
    recieve: std.time.timestamp(),
};
var timer_queue: std.PriorityQueue(Request, void, cmp) = undefined;
fn cmp(context: void, a: Request, b: Request) std.math.Order {
    _ = context;
    return std.math.order(a.recieve, b.recieve);
}

pub const HTTPServer = struct {
    var self_port_addr: u16 = undefined;
    var self_ipaddr: []const u8 = undefined;

    io: std.Io,
    listener: net.Server,
    dir: std.Io.Dir,

    pub fn init(io: std.Io, exe_opt: ExecuteOptions) !HTTPServer {
        self_port_addr = exe_opt.port_number;
        self_ipaddr = exe_opt.ip_addr;
        const dir = try std.Io.Dir.cwd().openDir(io, exe_opt.dirname, .{});
        var self_addr = avoid: {
            switch (@import("builtin").os.tag) {
                .windows => {
                    const ipv4 = parse: {
                        var it = std.mem.tokenizeScalar(u8, self_ipaddr, '.');
                        var _ipv4: [4]u8 = undefined;
                        var _ipv4_pos: usize = 0;
                        while (it.next()) |i| {
                            _ipv4[_ipv4_pos] = try std.fmt.parseInt(u8, i, 10);
                            _ipv4_pos += 1;
                        }
                        break :parse _ipv4;
                    };
                    break :avoid net.IpAddress.initIp4(ipv4, self_port_addr);
                },
                else => break :avoid try net.IpAddress.resolve(io, self_ipaddr, self_port_addr),
            }
        };
        const listener = listen: {
            while (true) {
                if (net.IpAddress.listen(self_addr, io, .{})) |_listener| {
                    break :listen _listener;
                } else |err| {
                    switch (err) {
                        error.AddressInUse => {
                            log.info("port :{} is already in use.\n", .{self_port_addr});
                            self_port_addr += 1;
                            self_addr = avoid: {
                                switch (@import("builtin").os.tag) {
                                    .windows => {
                                        const ipv4 = parse: {
                                            var it = std.mem.tokenizeScalar(u8, self_ipaddr, '.');
                                            var _ipv4: [4]u8 = undefined;
                                            var _ipv4_pos: usize = 0;
                                            while (it.next()) |i| {
                                                _ipv4[_ipv4_pos] = try std.fmt.parseInt(u8, i, 10);
                                                _ipv4_pos += 1;
                                            }
                                            break :parse _ipv4;
                                        };
                                        break :avoid net.IpAddress.initIp4(ipv4, self_port_addr);
                                    },
                                    else => break :avoid try net.IpAddress.resolve(io, self_ipaddr, self_port_addr),
                                }
                            };
                        },
                        else => log.err("{s}\n", .{@errorName(err)}),
                    }
                }
            }
        };

        var _server = HTTPServer{
            .dir = dir,
            .listener = listener,
            .io = io,
        };
        _ = &_server;

        return _server;
    }

    pub fn deinit(self: *HTTPServer) void {
        self.dir.close(self.io);
        self.listener.deinit(self.io);
    }

    pub fn serve(self: @This()) !void {
        const uri = try std.fmt.allocPrint(std.heap.page_allocator, "http://{s}:{}", .{ self_ipaddr, self_port_addr });
        // make URL clickable to open.
        var stdout_buffer: [1024]u8 = undefined;
        var stdout_writer = std.Io.File.stdout().writer(self.io, &stdout_buffer);
        const stdout = &stdout_writer.interface;
        try stdout.print("listening on \x1B]8;;{s}\x1B\\{s}\x1B]8;;\x1B\\\npress Ctrl-C to quit...\n", .{ uri, uri });
        try stdout.flush();
        while (@constCast(&self.listener).accept(self.io)) |conn| {
            log.debug("Accepted Connection from: {}", .{conn.socket.address});
            @constCast(&self).handleStream(@constCast(&conn)) catch |err| {
                if (@errorReturnTrace()) |bt| {
                    log.err("Failed to serve client: {}: {}", .{ err, bt });
                } else {
                    log.err("Failed to serve client: {}", .{err});
                }
            };
            conn.close(self.io);
        } else |err| {
            log.err("Failed to accept connection: {}", .{err});
            return err;
        }
    }

    fn handleStream(self: *HTTPServer, stream: *net.Stream) !void {
        // var recv_buf: [2048]u8 = undefined;
        // var recv_total: usize = 0;
        //
        // var reader = stream.reader(self.io, &recv_buf);
        // while (reader.interface.takeDelimiterInclusive('\n')) |recv_line| {
        //     if (recv_line.len == 0)
        //         return ServeFileError.RecvHeaderEOF;
        //
        //     recv_total += recv_line.len;
        //     // const TLSRecordLayer = @import("tls/tls.zig").TLSRecordLayer;
        //     // const record = try TLSRecordLayer.fromBytes(recv_buf[0..recv_total]);
        //     // const server_hello = try @import("tls/handshake/ServerHello.zig").ServerHello.init(record.data.client_hello.message);
        //     // const change_cipher_spec = @import("tls/handshake/content.zig").ChangeCipherSpec{};
        //     //
        //     // const rawsh = try server_hello.toBytes();
        //     // const rawccs = try change_cipher_spec.toBytes();
        //     // const packet = try std.mem.concat(std.heap.page_allocator, u8, &[_][]u8{ rawsh, rawccs });
        //     // std.debug.print("{any}\n", .{packet});
        //     // try stream.writer().writeAll(packet);
        //
        //     if (mem.containsAtLeast(u8, recv_buf[0..recv_total], 1, "\r\n\r\n"))
        //         break;
        //
        //     if (recv_total >= recv_buf.len)
        //         return ServeFileError.RecvHeaderExceededBuffer;
        //
        //     log.debug(" <<<\n{s}", .{recv_line});
        //
        // } else |read_err| {
        //     return read_err;
        // }
        var recv_buf: [2048]u8 = undefined;
        var reader = stream.reader(self.io, &recv_buf);

        var header = std.ArrayList(u8){};
        defer header.deinit(std.heap.page_allocator);

        while (reader.interface.takeDelimiterInclusive('\n')) |line| {
            try header.appendSlice(std.heap.page_allocator,line);

            if (mem.containsAtLeast(u8, header.items, 1, "\r\n\r\n")) {
                break;
            }

            if (header.items.len >= recv_buf.len)
                return ServeFileError.RecvHeaderExceededBuffer;
        } else |err| switch (err) {
            error.EndOfStream => return ServeFileError.RecvHeaderEOF,
            else => return err,
        }

        // var request = parseRequest: {
        //     var _req = std.StringHashMap([]const u8).init(std.heap.page_allocator);
        //     defer _req.deinit();
        //     var tok_itr = mem.tokenizeAny(u8, recv_buf[0..recv_total], "\r\n");
        //     var method = mem.tokenizeAny(u8, tok_itr.next().?, " ");
        //     if (method.next()) |m| {
        //         try _req.put(m, method.rest());
        //     }
        //
        //     while (tok_itr.next()) |req_row| {
        //         var req_itr = mem.tokenizeAny(u8, req_row, ":");
        //         const header = req_itr.next().?;
        //         const content = req_itr.rest();
        //         try _req.put(header, content);
        //     }
        //     break :parseRequest try _req.clone();
        // };
        const recv_slice = header.items;

        var request = parseRequest: {
            var _req = std.StringHashMap([]const u8).init(std.heap.page_allocator);
            defer _req.deinit();

            var tok_itr = mem.tokenizeAny(u8, recv_slice, "\r\n");

            var method = mem.tokenizeAny(u8, tok_itr.next().?, " ");
            if (method.next()) |m| {
                try _req.put(m, method.rest());
            }

            while (tok_itr.next()) |req_row| {
                if (req_row.len == 0) continue;

                var req_itr = mem.tokenizeAny(u8, req_row, ":");
                const _header = req_itr.next().?;
                const content = req_itr.rest();
                try _req.put(_header, content);
            }

            break :parseRequest try _req.clone();
        };
        defer request.deinit();

        if (request.get("GET")) |val| {
            const file_path = try self.extractFileName(val);
            try self.sendFile(stream, file_path);
        }
    }

    fn extractFileName(_: *HTTPServer, recv: []const u8) ![]const u8 {
        var file_path: []const u8 = undefined;
        var tok_itr = mem.tokenizeAny(u8, recv, " ");

        const path = tok_itr.next() orelse "";
        if (path[0] != '/') {
            return ServeFileError.HeaderDidNotMatch;
        }

        if (mem.eql(u8, path, "/"))
            file_path = "index"
        else
            file_path = path[1..];

        const rest = tok_itr.rest();
        if (!mem.startsWith(u8, rest, "HTTP/1.1"))
            return ServeFileError.HeaderDidNotMatch;

        return file_path;
    }

    fn complementFileName(_: *HTTPServer, fileName: []const u8) ![]const u8 {
        var tmp_fileName = fileName;
        const file_ext = fs.path.extension(tmp_fileName);
        if (file_ext.len == 0) {
            // /空のとき.htmlを補完する
            var path_buf: [fs.max_path_bytes]u8 = undefined;
            tmp_fileName = try std.fmt.bufPrint(&path_buf, "{s}.html", .{tmp_fileName});
        }
        return try std.heap.page_allocator.dupe(u8, tmp_fileName);
    }

    fn openFile(self: *HTTPServer, stream: *net.Stream, filename: []const u8) ![]u8 {
        var body_file = self.dir.openFile(self.io, filename, .{}) catch {
            var writer_buffer: [1024]u8 = undefined;
            var writer = stream.writer(self.io, &writer_buffer);
            try writer.interface.writeAll(
                \\HTTP/1.1 404 Not Found
                \\Connection: close
                \\Content-Type: text/html; charset=UTF-8
                \\
                \\
                \\<h1>404 Not Found.</h1>
            );
            try writer.interface.flush();
            return ServeFileError.FileNotFound;
        };
        defer body_file.close(self.io);
        const file_len = try body_file.length(self.io);
        const buf = try std.heap.page_allocator.alloc(u8, file_len);
        var reader = body_file.reader(self.io, buf);
        const data = try reader.interface.allocRemaining(std.heap.page_allocator, .unlimited);
        const mime = Mime.asMime(filename);
        if (mime.shouldCompress()) {
            const compressed_file = try self.compress(data);
            return @constCast(compressed_file);
        } else {
            return try std.heap.page_allocator.dupe(u8, data);
        }
    }

    fn sendFile(self: *HTTPServer, stream: *net.Stream, fileName: []const u8) !void {
        const fullFileName = try self.complementFileName(fileName);
        const body_file = try self.openFile(stream, fullFileName);

        const mime = Mime.asMime(fullFileName);
        const shouldCompress = mime.shouldCompress();
        var writer_buffer: [1024]u8 = undefined;
        var writer = stream.writer(self.io, &writer_buffer);

        if (shouldCompress) {
            const http_head =
                \\HTTP/1.1 200 OK
                \\Connection: close
                \\Content-Type: {s}
                \\Content-Length: {}
                \\Content-Encoding: {s}
                \\
                \\
            ;

            log.debug(" >>>\n" ++ http_head, .{ mime.asText(), body_file.len, "gzip" });
            try writer.interface.print(http_head, .{ mime.asText(), body_file.len, "gzip" });
            try writer.interface.flush();
        } else {
            const http_head =
                \\HTTP/1.1 200 OK
                \\Connection: close
                \\Content-Type: {s}
                \\Content-Length: {}
                \\
                \\
            ;
            log.debug(" >>>\n" ++ http_head, .{ mime.asText(), body_file.len });
            try writer.interface.print(http_head, .{ mime.asText(), body_file.len });
            try writer.interface.flush();
        }

        var reader: std.Io.Reader = .fixed(body_file);
        // _ = try reader.stream(&writer.interface, .unlimited);
        // try writer.interface.flush();
        _=try reader.streamRemaining(&writer.interface);
        try writer.interface.flush();
    }

    fn compress(_: *HTTPServer, content: []u8) ![]const u8 {
        const in_stream: std.Io.Reader = .fixed(content);
        var writer = std.Io.Writer.Allocating.init(std.heap.page_allocator);
        try gzip.compress(in_stream, &writer.writer, .{});
        return try writer.toOwnedSlice();
    }
};

const ServeFileError = error{
    RecvHeaderEOF,
    RecvHeaderExceededBuffer,
    HeaderDidNotMatch,
    FileNotFound,
};

test "generate encoded key in handshake websocket" {
    const key = "dGhlIHNhbXBsZSBub25jZQ==";
    const magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"; // specified at RFC 6455
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    const raw_key = try std.fmt.allocPrintZ(allocator, "{s}{s}", .{ key, magic });
    var out: [20]u8 = undefined; // 20 is digest_length
    std.crypto.hash.Sha1.hash(raw_key, &out, .{});

    const encoder = std.base64.Base64Encoder.init(std.base64.standard_alphabet_chars, '=');
    var buf: [128]u8 = undefined;
    const encoded_key = encoder.encode(&buf, &out);
    try std.testing.expect(std.mem.eql(u8, encoded_key, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
}
