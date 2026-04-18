const std = @import("std");
const HTTPServer = @import("server.zig").HTTPServer;

const Allocator = std.mem.Allocator;

pub const ExecuteOptions = struct {
    dirname: []const u8 = ".",
    ip_addr: []const u8 = "127.0.0.1",
    port_number: u16 = 8080,
};

pub fn main(init: std.process.Init) !void {
    const allocator: std.mem.Allocator = init.gpa;

    const result = try parseArgs(allocator, init.minimal.args);

    switch (result) {
        .help => {
            try printHelp(init.io);
            return;
        },
        .ok => |exe_opt| {
            var server = try HTTPServer.init(
                init.io,
                allocator,
                exe_opt.dirname,
                try std.Io.net.IpAddress.parse(exe_opt.ip_addr, exe_opt.port_number),
            );
            defer server.deinit();

            try server.serve();
        },
    }
}

const ParseResult = union(enum) {
    ok: ExecuteOptions,
    help,
};

fn parseArgs(allocator: Allocator, args: std.process.Args) !ParseResult {
    var opt = ExecuteOptions{};

    var args_iter = try args.iterateAllocator(allocator);

    var state: enum {
        none,
        dir,
        ip,
        port,
    } = .none;

    _ = args_iter.skip();

    while (args_iter.next()) |arg| {
        if (arg.len > 0 and arg[0] == '-') {
            switch (arg[1]) {
                'h' => return ParseResult.help,
                'd' => state = .dir,
                'i' => state = .ip,
                'p' => state = .port,
                else => return error.InvalidArgument,
            }

            continue;
        }

        switch (state) {
            .dir => opt.dirname = arg,
            .ip => opt.ip_addr = arg,
            .port => opt.port_number = try std.fmt.parseInt(u16, arg, 10),
            .none => return error.UnexpectedValue,
        }

        state = .none;
    }

    if (state != .none) return error.MissingValue;

    return ParseResult{ .ok = opt };
}

test "parse args" {
    const allocator = std.testing.allocator;

    const args_list = [_][*:0]const u8{
        "zerver",
        "-d",
        "public",
        "-p",
        "9000",
    };
    const args_vec: std.process.Args.Vector = &args_list;
    const args = std.process.Args{ .vector = args_vec };

    const opt = try parseArgs(allocator, args);

    try std.testing.expectEqualStrings("public", opt.ok.dirname);
    try std.testing.expect(opt.ok.port_number == 9000);
}

fn printHelp(io: std.Io) !void {
    var buffer: [1024]u8 = undefined;
    var writer = std.Io.File.stdout().writer(io, &buffer);

    const usage =
        \\Usage: zerver [options]
        \\
        \\Options:
        \\  -h        Show help
        \\  -d        Directory to serve
        \\  -i        IP address
        \\  -p        Port number
        \\
    ;

    try writer.interface.writeAll(usage);
    try writer.interface.flush();
}

const Error = error{
    InvalidArgument,
    UnexpectedValue,
    MissingValue,
    ShowHelp,
};
