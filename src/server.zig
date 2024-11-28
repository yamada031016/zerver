const std = @import("std");
const net = std.net;
const mem = std.mem;
const fs = std.fs;
const log = std.log;

const Mime = @import("mime.zig").Mime;

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
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    var stdout = std.io.getStdOut().writer();

    var self_port_addr: u16 = undefined;
    var self_ipaddr: []const u8 = undefined;

    listener: net.Server,
    dir: fs.Dir,

    pub fn init(public_path: []const u8, ipaddr: []const u8, port_addr: u16) !HTTPServer {
        self_port_addr = port_addr;
        self_ipaddr = ipaddr;
        const dir = try fs.cwd().openDir(public_path, .{});
        var self_addr = try net.Address.resolveIp(self_ipaddr, self_port_addr);
        const listener = listen: {
            while (true) {
                if (net.Address.listen(self_addr, .{})) |_listener| {
                    break :listen _listener;
                } else |err| {
                    switch (err) {
                        error.AddressInUse => {
                            log.info("port :{} is already in use.\n", .{self_port_addr});
                            self_port_addr += 1;
                            self_addr = try net.Address.resolveIp(self_ipaddr, self_port_addr);
                        },
                        else => log.err("{s}\n", .{@errorName(err)}),
                    }
                }
            }
        };

        var _server = HTTPServer{
            .dir = dir,
            .listener = listener,
        };
        _ = &_server;

        return _server;
    }

    pub fn deinit(self: *HTTPServer) void {
        self.dir.close();
        self.listener.deinit();
        _ = gpa.deinit();
    }

    pub fn serve(self: @This()) !void {
        const uri = try std.fmt.allocPrint(std.heap.page_allocator, "http://{s}:{}", .{ self_ipaddr, self_port_addr });
        try stdout.print("listening on \x1B]8;;{s}\x1B\\{s}\x1B]8;;\x1B\\\npress Ctrl-C to quit...\n", .{ uri, uri });
        while (@constCast(&self.listener).accept()) |conn| {
            log.debug("Accepted Connection from: {}", .{conn.address});
            @constCast(&self).handleStream(@constCast(&conn.stream)) catch |err| {
                if (@errorReturnTrace()) |bt| {
                    log.err("Failed to serve client: {}: {}", .{ err, bt });
                } else {
                    log.err("Failed to serve client: {}", .{err});
                }
            };
            conn.stream.close();
        } else |err| {
            log.err("Failed to accept connection: {}", .{err});
            return err;
        }
    }

    fn handleStream(self: *HTTPServer, stream: *net.Stream) !void {
        var recv_buf: [2048]u8 = undefined;
        var recv_total: usize = 0;

        while (stream.read(recv_buf[0..])) |recv_len| {
            if (recv_len == 0)
                return ServeFileError.RecvHeaderEOF;

            recv_total += recv_len;
            // const TLSRecordLayer = @import("tls/tls.zig").TLSRecordLayer;
            // const record = try TLSRecordLayer.fromBytes(recv_buf[0..recv_total]);
            // const server_hello = try @import("tls/handshake/ServerHello.zig").ServerHello.init(record.data.client_hello.message);
            // const change_cipher_spec = @import("tls/handshake/content.zig").ChangeCipherSpec{};
            //
            // const rawsh = try server_hello.toBytes();
            // const rawccs = try change_cipher_spec.toBytes();
            // const packet = try std.mem.concat(std.heap.page_allocator, u8, &[_][]u8{ rawsh, rawccs });
            // std.debug.print("{any}\n", .{packet});
            // try stream.writer().writeAll(packet);

            if (mem.containsAtLeast(u8, recv_buf[0..recv_total], 1, "\r\n\r\n"))
                break;

            if (recv_total >= recv_buf.len)
                return ServeFileError.RecvHeaderExceededBuffer;
        } else |read_err| {
            return read_err;
        }

        const recv_slice = recv_buf[0..recv_total];
        log.debug(" <<<\n{s}", .{recv_slice});

        var request = parseRequest: {
            var _req = std.StringHashMap([]const u8).init(std.heap.page_allocator);
            defer _req.deinit();
            var tok_itr = mem.tokenizeAny(u8, recv_slice, "\r\n");
            var method = mem.tokenizeAny(u8, tok_itr.next().?, " ");
            if (method.next()) |m| {
                try _req.put(m, method.rest());
            }

            while (tok_itr.next()) |req_row| {
                var req_itr = mem.tokenizeAny(u8, req_row, ":");
                const header = req_itr.next().?;
                const content = req_itr.rest();
                try _req.put(header, content);
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

        // if (!mem.eql(u8, tok_itr.next() orelse "", "GET"))
        // return ServeFileError.HeaderDidNotMatch;

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
        var body_file = self.dir.openFile(filename, .{}) catch {
            try stream.writeAll(
                \\HTTP/1.1 404 Not Found
                \\Connection: close
                \\Content-Type: text/html; charset=UTF-8
                \\
                \\
                \\<h1>404 Not Found.</h1>
            );
            return ServeFileError.FileNotFound;
        };
        defer body_file.close();
        const file_len = try body_file.getEndPos();
        const buf = try allocator.alloc(u8, file_len);
        defer allocator.free(buf);
        _ = try body_file.readAll(buf);

        const mime = Mime.asMime(filename);
        if (mime.shouldCompress()) {
            const compressed_file = try self.compress(buf);
            return @constCast(compressed_file);
        } else {
            return try std.heap.page_allocator.dupe(u8, buf);
        }
    }

    fn sendFile(self: *HTTPServer, stream: *net.Stream, fileName: []const u8) !void {
        const fullFileName = try self.complementFileName(fileName);

        // log.debug("Opening {s}\n", .{file});
        // std.debug.print("hoge: {s}\n", .{file});

        // openFile()に渡す引数fileはなぜか""で上書きされて返ってくる...?
        // var body_file = self.dir.openFile(file, .{}) catch {
        //     try stream.writeAll(
        //         \\HTTP/1.1 404 Not Found
        //         \\Connection: close
        //         \\Content-Type: text/html; charset=UTF-8
        //         \\
        //         \\
        //         \\<h1>404 Not Found.</h1>
        //     );
        //     return ServeFileError.FileNotFound;
        // };
        // defer body_file.close();
        //
        // const file_len = try body_file.getEndPos();
        const body_file = try self.openFile(stream, fullFileName);

        const mime = Mime.asMime(fullFileName);
        const shouldCompress = mime.shouldCompress();

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
            try stream.writer().print(http_head, .{ mime.asText(), body_file.len, "gzip" });
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
            try stream.writer().print(http_head, .{ mime.asText(), body_file.len });
        }

        var send_total: usize = 0;
        var send_len: usize = 0;
        var bufferStream = std.io.fixedBufferStream(body_file);
        const reader = bufferStream.reader();
        while (true) {
            var buf: [1024 * 10]u8 = undefined;
            send_len = try reader.read(&buf);
            try stream.writer().writeAll(buf[0..send_len]);

            send_total += send_len;
            if (body_file.len <= send_total)
                break;
        }
    }

    fn compress(_: *HTTPServer, content: []u8) ![]const u8 {
        var compressed = std.ArrayList(u8).init(std.heap.page_allocator);
        var buf = std.io.fixedBufferStream(content);
        try std.compress.gzip.compress(buf.reader(), compressed.writer(), .{ .level = .fast }); // .fast equal .level4 at this time.
        return try compressed.toOwnedSlice();
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
