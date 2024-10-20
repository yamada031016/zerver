const std = @import("std");
const HTTPServer = @import("server.zig").HTTPServer;

pub fn main() !void {
    var args = std.process.args();
    const exe_name = args.next() orelse "zerver";
    const public_path = args.next() orelse {
        std.log.err("Usage: {s} <serve dir>", .{exe_name});
        return;
    };

    const port_addr: u16 = 8000;
    const ip_addr = "0.0.0.0";
    var server = try HTTPServer.init(public_path, ip_addr, port_addr);
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
