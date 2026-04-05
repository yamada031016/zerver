const std = @import("std");
const net = std.Io.net;
const mem = std.mem;
const fs = std.fs;

const gzip = @import("gzip.zig");
const Mime = @import("mime.zig").Mime;

const Allocator = std.mem.Allocator;

pub const HTTPServer = struct {
    allocator: Allocator,
    io: std.Io,
    listener: net.Server,
    root_dir: std.Io.Dir,

    pub fn init(io: std.Io, allocator: Allocator, root_path: []const u8, addr: net.IpAddress) !HTTPServer {
        const dir = try std.Io.Dir.cwd().openDir(io, root_path, .{});
        const listener = try net.IpAddress.listen(addr, io, .{.reuse_address=true});

        return HTTPServer{
            .allocator = allocator,
            .io = io,
            .listener = listener,
            .root_dir = dir,
        };
    }

    pub fn deinit(self: *HTTPServer) void {
        self.root_dir.close(self.io);
        self.listener.deinit(self.io);
    }

    pub fn serve(self: *HTTPServer) !void {
        std.log.info("Server listening on http://{s}:{}", .{ self.listener.socket.address.ip4.bytes, self.listener.socket.address.getPort() });
        while (self.listener.accept(self.io)) |conn| {
            defer conn.close(self.io);

            self.handleConnection(@constCast(&conn)) catch |err| {
                std.log.err("connection error: {}", .{err});
            };
        } else |err| {
            return err;
        }
    }

    fn handleConnection(self: *HTTPServer, stream: *net.Stream) !void {
        var buffer: [4096]u8 = undefined;
        var reader = stream.reader(self.io, &buffer);

        const request = try RequestParser.parse(self.allocator, &reader.interface);

        const response = try self.handleRequest(request);
        try ResponseWriter.write(self.io, stream, response);
    }

    fn handleRequest(self: *HTTPServer, req: Request) !Response {
        const path = try FileHandler.resolvePath(self.allocator, req.path);

        const file_data = try FileHandler.readFile(
            self,
            path,
        );

        const mime = Mime.asMime(path);

        if (mime.shouldCompress()) {
            const compressed = try Compressor.compress(self.allocator, file_data);
            return Response.ok(mime.asText(), compressed, true);
        }

        return Response.ok(mime.asText(), file_data, false);
    }
};

pub const Request = struct {
    method: []const u8,
    path: []const u8,
    headers: std.StringHashMap([]const u8),

    pub fn deinit(self: *Request, allocator: Allocator) void {
        self.headers.deinit();
        allocator.free(self.method);
        allocator.free(self.path);
    }
};

pub const RequestParser = struct {
    pub fn parse(allocator: Allocator, reader: *std.Io.Reader) !Request {
        const line = try reader.takeDelimiterInclusive('\n');

        var tokens = mem.tokenizeAny(u8, line, " ");
        const method = try allocator.dupe(u8, tokens.next().?);
        const path = try allocator.dupe(u8, tokens.next().?);

        var headers = std.StringHashMap([]const u8).init(allocator);

        while (true) {
            const l = try reader.takeDelimiterInclusive('\n');

            if (mem.eql(u8, l, "\r\n")) break;

            var it = mem.tokenizeAny(u8, l, ":");
            const key = it.next().?;
            const value = mem.trim(u8, it.rest(), " \r\n");

            try headers.put(key, value);
        }

        return Request{
            .method = method,
            .path = path,
            .headers = headers,
        };
    }
};

pub const Response = struct {
    status: []const u8,
    mime: []const u8,
    body: []const u8,
    compressed: bool,

    pub fn ok(mime: []const u8, body: []const u8, compressed: bool) Response {
        return .{
            .status = "HTTP/1.1 200 OK",
            .mime = mime,
            .body = body,
            .compressed = compressed,
        };
    }
};

pub const ResponseWriter = struct {
    pub fn write(io: std.Io, stream: *net.Stream, res: Response) !void {
        var buf: [1024]u8 = undefined;
        var writer = stream.writer(io, &buf);

        if (res.compressed) {
            try writer.interface.print(
                "{s}\r\nContent-Type: {s}\r\nContent-Length: {}\r\nContent-Encoding: gzip\r\n\r\n",
                .{ res.status, res.mime, res.body.len },
            );
        } else {
            try writer.interface.print(
                "{s}\r\nContent-Type: {s}\r\nContent-Length: {}\r\n\r\n",
                .{ res.status, res.mime, res.body.len },
            );
        }

        var reader: std.Io.Reader = .fixed(res.body);
        _ = try reader.streamRemaining(&writer.interface);

        try writer.interface.flush();
    }
};

pub const FileHandler = struct {
    pub fn resolvePath(allocator: Allocator, path: []const u8) ![]const u8 {
        if (mem.eql(u8, path, "/")) {
            return allocator.dupe(u8, "index.html");
        }

        if (mem.startsWith(u8, path, "/")) {
            return allocator.dupe(u8, path[1..]);
        }

        return error.InvalidPath;
    }

    pub fn readFile(server: *HTTPServer, path: []const u8) ![]u8 {
        const file = server.root_dir.openFile(server.io, path, .{}) catch return error.FileNotFound;
        defer file.close(server.io);

        const len = try file.length(server.io);
        const buf = try server.allocator.alloc(u8, len);

        var reader = file.reader(server.io, buf);
        return try reader.interface.allocRemaining(server.allocator, .unlimited);
    }
};

pub const Compressor = struct {
    pub fn compress(allocator: Allocator, input: []const u8) ![]u8 {
        const in_stream: std.Io.Reader = .fixed(input);

        var writer = std.Io.Writer.Allocating.init(allocator);
        defer writer.deinit();

        try gzip.compress(in_stream, &writer.writer, .{});
        try writer.writer.flush();

        return try writer.toOwnedSlice();
    }
};

test "gzip roundtrip" {
    const allocator = std.testing.allocator;

    const input = "<h1>Hello</h1>";

    const compressed = try Compressor.compress(allocator, input);
    defer allocator.free(compressed);

    var writer = std.Io.Writer.Allocating.init(allocator);
    defer writer.deinit();

    const reader: std.Io.Reader = .fixed(compressed);
    try gzip.decompress(reader, &writer.writer);
    try writer.writer.flush();

    const output = try writer.toOwnedSlice();
    defer allocator.free(output);

    try std.testing.expectEqualStrings(input, output);
}


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
