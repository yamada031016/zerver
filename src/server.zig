const std = @import("std");
const net = std.net;
const mem = std.mem;
const fs = std.fs;
const log = std.log;

const Mime = @import("mime.zig").Mime;

pub const HTTPServer = struct {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

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

        var _server = .{
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

    pub fn serve(self: *HTTPServer) !noreturn {
        log.info("listening on {s}:{}\npress Ctrl-C to quit...\n", .{ self_ipaddr, self_port_addr });
        while (self.listener.accept()) |conn| {
            const fork_pid = try std.posix.fork();
            if (fork_pid == 0) {
                // child process
                log.debug("Accepted Connection from: {}", .{conn.address});
                self.handleStream(@constCast(&conn.stream)) catch |err| {
                    if (@errorReturnTrace()) |bt| {
                        log.err("Failed to serve client: {}: {}", .{ err, bt });
                    } else {
                        log.err("Failed to serve client: {}", .{err});
                    }
                };
            } else {
                // parent process
                const wait_result = std.posix.waitpid(fork_pid, 0);
                if (wait_result.status != 0) {
                    log.err("終了コード: {}\n", .{wait_result.status});
                }
            }
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
            const TLSRecordLayer = @import("tls/tls.zig").TLSRecordLayer;
            const record = try TLSRecordLayer.parse(recv_buf[0..recv_total]);
            const server_hello = try @import("tls/handshake/ServerHello.zig").ServerHello.parse(record.data.client_hello.message);
            const stdout = std.io.getStdOut().writer();
            try stdout.print("{any}", .{server_hello});
            std.debug.print("record:{any}\n", .{record});
            for (record.data.client_hello.message.cipher_suite.cipher_suites) |suite| {
                switch (suite) {
                    0x1301...0x1307 => {
                        const cipher_suite: std.crypto.tls.CipherSuite = @enumFromInt(suite);
                        std.debug.print("suite: {any}\n", .{cipher_suite});
                    },
                    else => {
                        // std.debug.print("Not support suite: 0x{x}\n", .{suite});
                    },
                }
            }
            const data = record.data.client_hello.message.extensions.extensions;
            var skip: usize = 0;
            std.debug.print("len({}), {any}\n", .{ record.data.client_hello.message.extensions.length, data[0..100] });
            for (0..record.data.client_hello.message.extensions.length) |i| {
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
                    },
                    .supported_groups => {
                        const sp_len = (@as(u16, @intCast(data[i + local_skip])) << 8) + @as(u16, data[i + local_skip + 1]);
                        std.debug.print("{any}\n", .{data[i .. i + local_skip + 20]});
                        std.debug.print("len: {}, sp_len: {}\n", .{ len, sp_len });
                        local_skip += 2;
                        var j: usize = 0;
                        while (j < sp_len) : (j += 2) {
                            const group = (@as(u16, @intCast(data[i + local_skip + j])) << 8) + @as(u16, data[i + local_skip + j + 1]);
                            std.debug.print("supported_group: {any}\n", .{@as(std.crypto.tls.NamedGroup, @enumFromInt(group))});
                        }
                    },
                    .supported_versions => {
                        const sv_len = data[i + local_skip];
                        local_skip += 1;
                        var j: usize = 0;
                        while (j < sv_len) : (j += 2) {
                            const version = (@as(u16, @intCast(data[i + local_skip + j])) << 8) + @as(u16, data[i + local_skip + j + 1]);
                            std.debug.print("TLS version support: {any}\n", .{@as(std.crypto.tls.ProtocolVersion, @enumFromInt(version))});
                        }
                    },
                    .key_share => {
                        _ = (@as(u16, @intCast(data[i + local_skip])) << 8) + @as(u16, data[i + local_skip + 1]); // client key length
                        local_skip += 2;
                        const group = (@as(u16, @intCast(data[i + local_skip])) << 8) + @as(u16, data[i + local_skip + 1]);
                        local_skip += 2;
                        const key_len = (@as(u16, @intCast(data[i + local_skip])) << 8) + @as(u16, data[i + local_skip + 1]);
                        local_skip += 2;
                        const key = data[i + local_skip .. i + local_skip + key_len];
                        std.debug.print("[{any}]{s}\n", .{ @as(std.crypto.tls.NamedGroup, @enumFromInt(group)), key });
                    },
                    .application_layer_protocol_negotiation => {
                        const alpn_len = (@as(u16, @intCast(data[i + local_skip])) << 8) + @as(u16, data[i + local_skip + 1]);
                        local_skip += 2;
                        var pos: usize = 0;
                        while (pos < alpn_len) {
                            const alpn_proto_len = data[i + local_skip + pos];
                            pos += 1;
                            std.debug.print("{s}\n", .{data[i + local_skip + pos .. i + local_skip + pos + alpn_proto_len]});
                            pos += alpn_proto_len;
                        }
                    },
                    // .max_fragment_length => {},
                    // .status_request => {},
                    .signature_algorithms => {
                        const ex_len = (@as(u16, @intCast(data[i + local_skip])) << 8) + @as(u16, data[i + local_skip + 1]);
                        local_skip += 2;
                        for (0..ex_len / 2) |_| {
                            const signature_algorithm = (@as(u16, @intCast(data[i + local_skip])) << 8) + @as(u16, data[i + local_skip + 1]);
                            local_skip += 2;
                            std.debug.print("signature algoritms: {any}\n", .{@as(std.crypto.tls.SignatureScheme, @enumFromInt(signature_algorithm))});
                        }
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

    fn sendFile(self: *HTTPServer, stream: *net.Stream, fileName: []const u8) !void {
        const file = try self.complementFileName(fileName);

        // log.debug("Opening {s}\n", .{file});
        // std.debug.print("hoge: {s}\n", .{file});

        // openFile()に渡す引数fileはなぜか""で上書きされて返ってくる...?
        var body_file = self.dir.openFile(file, .{}) catch {
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

        const http_head =
            \\HTTP/1.1 200 OK
            \\Connection: close
            \\Content-Type: {s}
            \\Content-Length: {}
            \\
            \\
        ;

        const mime = Mime.asMime(file);

        log.debug(" >>>\n" ++ http_head, .{ mime.asText(), file_len });
        try stream.writer().print(http_head, .{ mime.asText(), file_len });

        var send_total: usize = 0;
        var send_len: usize = 0;
        while (true) {
            var buf: [2048 * 5]u8 = undefined;
            send_len = try body_file.read(&buf);
            if (send_len == 0)
                break;
            try stream.writer().writeAll(buf[0..send_len]);

            send_total += send_len;
        }
    }

    pub fn getPortNumber(_: *HTTPServer) u16 {
        return self_port_addr;
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
