const std = @import("std");

pub const Mime = enum {
    html,
    css,
    map,
    svg,
    jpg,
    png,
    wasm,
    js,
    tar,
    pdf,
    other,

    // zig fmt: off
    pub fn asMime(filePath: []const u8) Mime {
        const file_ext = extractFileExtension(filePath);
        return
            if (std.mem.eql(u8, file_ext, ".html")) .html
            else if (std.mem.eql(u8, file_ext, ".css")) .css
            else if (std.mem.eql(u8, file_ext, ".map")) .map
            else if (std.mem.eql(u8, file_ext, ".svg")) .svg
            else if (std.mem.eql(u8, file_ext, ".jpg")) .jpg
            else if (std.mem.eql(u8, file_ext, ".png")) .png
            else if (std.mem.eql(u8, file_ext, ".wasm")) .wasm
            else if (std.mem.eql(u8, file_ext, ".js")) .js
            else if (std.mem.eql(u8, file_ext, ".tar")) .tar
            else if (std.mem.eql(u8, file_ext, ".pdf")) .pdf
            else unreachable;
    }
// zig fmt: on
    pub fn asText(self: *const Mime) []const u8 {
        return switch (self.*) {
            .html => "text/html",
            .css => "text/css",
            .map => "application/json",
            .svg => "image/svg+xml",
            .jpg => "image/jpg",
            .png => "image/png",
            .wasm => "application/wasm",
            .js => "text/javascript",
            .tar => "application/x-tar",
            .pdf => "application/pdf",
            .other => "text/plain",
        };
    }
    pub fn shouldCompress(self: *const Mime) bool {
        switch (self.*) {
            .html, .css, .map, .js => return true,
            .svg, .jpg, .png, .wasm, .tar, .pdf, .other => return false,
        }
    }

    fn extractFileExtension(filePath: []const u8) []const u8 {
        var file_ext = std.fs.path.extension(filePath);
        if (file_ext.len == 0) {
            // complement file extension. ex) path = /filename
            file_ext = ".html";
        }
        return file_ext;
    }
};
