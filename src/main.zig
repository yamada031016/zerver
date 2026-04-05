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

    const exe_opt = try parseArgs(allocator, init.minimal.args);

    var server = try HTTPServer.init(
        init.io,
        allocator,
        exe_opt.dirname,
        try std.Io.net.IpAddress.parse(exe_opt.ip_addr, exe_opt.port_number)
    );
    defer server.deinit();

    try server.serve();
}

fn parseArgs(allocator: Allocator,args: std.process.Args) !ExecuteOptions {
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
            state = switch (std.mem.eql(u8, arg, "-d")) {
                true => .dir,
                false => if (std.mem.eql(u8, arg, "-i")) .ip
                else if (std.mem.eql(u8, arg, "-p")) .port
                else if (std.mem.eql(u8, arg, "-h")) return error.ShowHelp
                else return error.InvalidArgument,
            };
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

    return opt;
}

test "parse args" {
    const allocator = std.testing.allocator;

    const args = [_][]const u8{
        "zerver",
        "-d",
        "public",
        "-p",
        "9000",
    };

    const opt = try parseArgs(allocator, &args);

    try std.testing.expectEqualStrings("public", opt.dirname);
    try std.testing.expect(opt.port_number == 9000);
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
