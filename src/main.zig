const std = @import("std");
const HTTPServer = @import("server.zig").HTTPServer;

const ExecuteOptions = struct {
    dirname: []const u8 = ".",
    ip_addr: []const u8 = "localhost",
    port_addr: u16 = 8000,
};

pub fn main() !void {
    var args = std.process.args();
    _ = args.next() orelse "zerver";
    var exe_opt = ExecuteOptions{};
    var selected_field: []const u8 = "";
    while (args.next()) |option| {
        if (std.mem.startsWith(u8, option, "-")) {
            if (std.mem.eql(u8, option, "-d")) {
                selected_field = "dirname";
            } else if (std.mem.eql(u8, option, "-i")) {
                selected_field = "ip_addr";
            } else if (std.mem.eql(u8, option, "-p")) {
                selected_field = "port_addr";
            } else if (std.mem.eql(u8, option, "-h")) {
                try help_message();
                if (args.inner.count != 2) {
                    std.log.err("-h option cannot specified with any other options.", .{});
                    std.process.exit(1);
                }
                std.process.exit(0);
            }
        } else {
            if (std.mem.eql(u8, selected_field, "dirname")) {
                exe_opt.dirname = option;
            } else if (std.mem.eql(u8, selected_field, "ip_addr")) {
                exe_opt.ip_addr = option;
            } else if (std.mem.eql(u8, selected_field, "port_addr")) {
                exe_opt.port_addr = try std.fmt.parseInt(u16, option, 10);
            }
            selected_field = "";
        }
    } else {
        if (selected_field.len != 0) {
            std.log.err("{s} did not specified.\n", .{selected_field});
        }
    }
    // const public_path = args.next() orelse {
    //     std.log.err("Usage: {s} <serve dir>", .{exe_name});
    //     return;
    // };

    // const port_addr: u16 = 8000;
    // const ip_addr = "0.0.0.0";
    var server = try HTTPServer.init(exe_opt.dirname, exe_opt.ip_addr, exe_opt.port_addr);
    defer server.deinit();

    // var act = std.posix.Sigaction{
    //     .handler = .{
    //         .handler = struct {
    //             fn wrapper(_: c_int) callconv(.C) void {
    //                 std.process.exit(0);
    //             }
    //         }.wrapper,
    //     },
    //     .mask = std.posix.empty_sigset,
    //     .flags = 0,
    // };
    // try std.posix.sigaction(std.posix.SIG.INT, &act, null);

    try server.serve();
}
fn help_message() !void {
    const stdout = std.io.getStdOut().writer();
    const usage =
        \\Usage: zerver [option] [value]
        \\
        \\Options:
        \\
        \\  -h          Show this help message.
        \\  -d          Specific directory path to serve
        \\  -i          Specific IP address.
        \\  -p          Specific port number.
        \\
    ;
    _ = try stdout.write(usage);
}
