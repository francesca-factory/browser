// Copyright (C) 2023-2024  Lightpanda (Selecy SAS)
//
// Francis Bouvier <francis@lightpanda.io>
// Pierre Tachoire <pierre@lightpanda.io>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Mime = struct {
    content_type: ContentType,
    params: []const u8 = "",
    charset: ?[]const u8 = null,
    arena: std.heap.ArenaAllocator,

    pub const ContentTypeEnum = enum {
        text_xml,
        text_html,
        text_plain,
        image_gif,
        image_jpeg,
        image_png,
        image_webp,
        image_bmp,
        image_ico,
        image_svg_xml,
        application_pdf,
        application_zip,
        application_json,
        audio_wave,
        audio_ogg,
        audio_mpeg,
        video_mp4,
        video_webm,
        other,
    };

    pub const ContentType = union(ContentTypeEnum) {
        text_xml: void,
        text_html: void,
        text_plain: void,
        image_gif: void,
        image_jpeg: void,
        image_png: void,
        image_webp: void,
        image_bmp: void,
        image_ico: void,
        image_svg_xml: void,
        application_pdf: void,
        application_zip: void,
        application_json: void,
        audio_wave: void,
        audio_ogg: void,
        audio_mpeg: void,
        video_mp4: void,
        video_webm: void,
        other: struct { type: []const u8, sub_type: []const u8 },
    };

    // MIME sniffing signature table according to WHATWG spec
    // https://mimesniff.spec.whatwg.org/
    const SniffSequence = struct {
        pattern: []const u8,
        mask: ?[]const u8 = null,
        offset: usize = 0,
        mime_type: ContentTypeEnum,
    };

    const sniffSequences = [_]SniffSequence{
        // Image formats
        .{ .pattern = "\xFF\xD8\xFF", .mime_type = .image_jpeg }, // JPEG
        .{ .pattern = "GIF87a", .mime_type = .image_gif }, // GIF
        .{ .pattern = "GIF89a", .mime_type = .image_gif }, // GIF
        .{ .pattern = "\x89PNG\r\n\x1A\n", .mime_type = .image_png }, // PNG
        .{ .pattern = "RIFF????WEBPVP8 ", .mask = "RIFF    WEBPVP8 ", .mime_type = .image_webp }, // WebP
        .{ .pattern = "BM", .mime_type = .image_bmp }, // BMP
        .{ .pattern = "\x00\x00\x01\x00", .mime_type = .image_ico }, // ICO

        // PDF
        .{ .pattern = "%PDF-", .mime_type = .application_pdf },

        // ZIP-based formats
        .{ .pattern = "PK\x03\x04", .mime_type = .application_zip },

        // Audio formats
        .{ .pattern = "RIFF????WAVE", .mask = "RIFF    WAVE", .mime_type = .audio_wave }, // WAV
        .{ .pattern = "OggS", .mime_type = .audio_ogg }, // OGG
        .{ .pattern = "ID3", .mime_type = .audio_mpeg }, // MP3 with ID3 tag

        // Video formats
        .{ .pattern = "\x00\x00\x00\x18ftypmp42", .offset = 4, .mime_type = .video_mp4 }, // MP4
        .{ .pattern = "\x1A\x45\xDF\xA3", .mime_type = .video_webm }, // WebM

        // XML formats - look for <?xml at the start
        .{ .pattern = "<?xml", .mime_type = .text_xml },
    };

    // Sniff the MIME type from content bytes
    pub fn sniff(content: []const u8) ContentTypeEnum {
        // First check for binary signatures
        for (sniffSequences) |seq| {
            if (content.len < seq.pattern.len + seq.offset) continue;

            var matches = true;
            for (seq.pattern, 0..) |byte, i| {
                if (seq.mask) |mask| {
                    // If mask bit is 0, we don't care about this byte
                    if (mask[i] == ' ') continue;
                }
                if (content[seq.offset + i] != byte) {
                    matches = false;
                    break;
                }
            }
            if (matches) return seq.mime_type;
        }

        // Check for HTML
        // Look for HTML tags near the beginning
        if (content.len >= 14) {
            const sample = content[0..std.math.min(512, content.len)];
            const lower_sample = toLowerSample(sample);

            // Check for HTML doctype or common tags
            if (std.mem.indexOf(u8, lower_sample, "<!doctype html") != null or
                std.mem.indexOf(u8, lower_sample, "<html") != null or
                std.mem.indexOf(u8, lower_sample, "<head") != null or
                std.mem.indexOf(u8, lower_sample, "<title") != null or
                std.mem.indexOf(u8, lower_sample, "<body") != null or
                std.mem.indexOf(u8, lower_sample, "<script") != null)
            {
                return .text_html;
            }
        }

        // Check for JSON
        if (content.len >= 2) {
            const trimmed = std.mem.trim(u8, content, &std.ascii.whitespace);
            if (trimmed.len > 0 and (trimmed[0] == '{' or trimmed[0] == '[')) {
                // Simple JSON detection - starts with { or [
                return .application_json;
            }
        }

        // If we've made it here, check if it's text content
        if (isTextContent(content)) {
            return .text_plain;
        }

        // Default to text/plain if nothing else matches
        return .text_plain;
    }

    // Helper function to create a lowercase sample for HTML detection
    fn toLowerSample(sample: []const u8) []const u8 {
        var buf: [512]u8 = undefined;
        const len = std.math.min(sample.len, buf.len);
        for (sample[0..len], 0..) |c, i| {
            buf[i] = std.ascii.toLower(c);
        }
        return buf[0..len];
    }

    // Check if content appears to be text
    fn isTextContent(content: []const u8) bool {
        // Check a sample of the content for binary data
        const sample_size = std.math.min(content.len, 512);
        var binary_count: usize = 0;

        for (content[0..sample_size]) |byte| {
            // Count control characters that aren't common in text
            if ((byte < 32 and byte != '\t' and byte != '\n' and byte != '\r') or byte == 127) {
                binary_count += 1;
            }
        }

        // If more than 10% of the sample is binary, it's probably not text
        return binary_count < (sample_size / 10);
    }

    // Create a Mime instance from content bytes
    pub fn fromBytes(allocator: Allocator, content: []const u8) !Mime {
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();

        const content_type = sniff(content);
        const charset = if (content_type == .text_html or content_type == .text_plain or content_type == .text_xml)
            "utf-8"
        else
            null;

        return .{
            .arena = arena,
            .content_type = switch (content_type) {
                .text_html => .{ .text_html = {} },
                .text_plain => .{ .text_plain = {} },
                .text_xml => .{ .text_xml = {} },
                .image_gif => .{ .image_gif = {} },
                .image_jpeg => .{ .image_jpeg = {} },
                .image_png => .{ .image_png = {} },
                .image_webp => .{ .image_webp = {} },
                .image_bmp => .{ .image_bmp = {} },
                .image_ico => .{ .image_ico = {} },
                .image_svg_xml => .{ .image_svg_xml = {} },
                .application_pdf => .{ .application_pdf = {} },
                .application_zip => .{ .application_zip = {} },
                .application_json => .{ .application_json = {} },
                .audio_wave => .{ .audio_wave = {} },
                .audio_ogg => .{ .audio_ogg = {} },
                .audio_mpeg => .{ .audio_mpeg = {} },
                .video_mp4 => .{ .video_mp4 = {} },
                .video_webm => .{ .video_webm = {} },
                .other => .{ .other = .{ .type = "application", .sub_type = "octet-stream" } },
            },
            .charset = charset,
        };
    }

    pub fn parse(allocator: Allocator, input: []const u8) !Mime {
        if (input.len > 255) {
            return error.TooBig;
        }

        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();

        var trimmed = trim(input);

        const content_type, const type_len = try parseContentType(trimmed);
        if (type_len >= trimmed.len) {
            return .{ .arena = arena, .content_type = content_type };
        }

        const params = trimLeft(trimmed[type_len..]);

        var charset: ?[]const u8 = null;

        var it = std.mem.splitScalar(u8, params, ';');
        while (it.next()) |attr| {
            const i = std.mem.indexOfScalarPos(u8, attr, 0, '=') orelse return error.Invalid;
            const name = trimLeft(attr[0..i]);

            const value = trimRight(attr[i + 1 ..]);
            if (value.len == 0) {
                return error.Invalid;
            }

            switch (name.len) {
                7 => if (isCaseEqual("charset", name)) {
                    charset = try parseValue(arena.allocator(), value);
                },
                else => {},
            }
        }

        return .{
            .arena = arena,
            .params = params,
            .charset = charset,
            .content_type = content_type,
        };
    }

    pub fn deinit(self: *Mime) void {
        self.arena.deinit();
    }

    pub fn isHTML(self: *const Mime) bool {
        return self.content_type == .text_html;
    }

    // Returns the string representation of the MIME type
    pub fn toString(self: *const Mime, allocator: Allocator) ![]const u8 {
        var buf = std.ArrayList(u8).init(allocator);
        defer buf.deinit();

        switch (self.content_type) {
            .text_html => try buf.appendSlice("text/html"),
            .text_plain => try buf.appendSlice("text/plain"),
            .text_xml => try buf.appendSlice("text/xml"),
            .image_gif => try buf.appendSlice("image/gif"),
            .image_jpeg => try buf.appendSlice("image/jpeg"),
            .image_png => try buf.appendSlice("image/png"),
            .image_webp => try buf.appendSlice("image/webp"),
            .image_bmp => try buf.appendSlice("image/bmp"),
            .image_ico => try buf.appendSlice("image/x-icon"),
            .image_svg_xml => try buf.appendSlice("image/svg+xml"),
            .application_pdf => try buf.appendSlice("application/pdf"),
            .application_zip => try buf.appendSlice("application/zip"),
            .application_json => try buf.appendSlice("application/json"),
            .audio_wave => try buf.appendSlice("audio/wave"),
            .audio_ogg => try buf.appendSlice("audio/ogg"),
            .audio_mpeg => try buf.appendSlice("audio/mpeg"),
            .video_mp4 => try buf.appendSlice("video/mp4"),
            .video_webm => try buf.appendSlice("video/webm"),
            .other => |o| {
                try buf.appendSlice(o.type);
                try buf.append('/');
                try buf.appendSlice(o.sub_type);
            },
        }

        if (self.charset) |cs| {
            try buf.appendSlice("; charset=");
            try buf.appendSlice(cs);
        }

        return buf.toOwnedSlice();
    }

    fn parseContentType(value: []const u8) !struct { ContentType, usize } {
        const separator = std.mem.indexOfScalarPos(u8, value, 0, '/') orelse {
            return error.Invalid;
        };
        const end = std.mem.indexOfScalarPos(u8, value, separator, ';') orelse blk: {
            break :blk value.len;
        };

        const main_type = value[0..separator];
        const sub_type = trimRight(value[separator + 1 .. end]);

        if (parseCommonContentType(main_type, sub_type)) |content_type| {
            return .{ content_type, end + 1 };
        }

        if (main_type.len == 0) {
            return error.Invalid;
        }
        if (validType(main_type) == false) {
            return error.Invalid;
        }

        if (sub_type.len == 0) {
            return error.Invalid;
        }
        if (validType(sub_type) == false) {
            return error.Invalid;
        }

        const content_type = ContentType{ .other = .{
            .type = main_type,
            .sub_type = sub_type,
        } };

        return .{ content_type, end + 1 };
    }

    fn parseCommonContentType(main_type: []const u8, sub_type: []const u8) ?ContentType {
        switch (main_type.len) {
            4 => if (isCaseEqual("text", main_type)) {
                switch (sub_type.len) {
                    3 => if (isCaseEqual("xml", sub_type)) {
                        return .{ .text_xml = {} };
                    },
                    4 => if (isCaseEqual("html", sub_type)) {
                        return .{ .text_html = {} };
                    },
                    5 => if (isCaseEqual("plain", sub_type)) {
                        return .{ .text_plain = {} };
                    },
                    else => {},
                }
            },
            5 => if (isCaseEqual("image", main_type)) {
                switch (sub_type.len) {
                    3 => if (isCaseEqual("gif", sub_type)) {
                        return .{ .image_gif = {} };
                    } else if (isCaseEqual("png", sub_type)) {
                        return .{ .image_png = {} };
                    } else if (isCaseEqual("bmp", sub_type)) {
                        return .{ .image_bmp = {} };
                    },
                    4 => if (isCaseEqual("jpeg", sub_type)) {
                        return .{ .image_jpeg = {} };
                    } else if (isCaseEqual("webp", sub_type)) {
                        return .{ .image_webp = {} };
                    },
                    7 => if (isCaseEqual("svg+xml", sub_type)) {
                        return .{ .image_svg_xml = {} };
                    },
                    else => {},
                }
            } else if (isCaseEqual("audio", main_type)) {
                switch (sub_type.len) {
                    3 => if (isCaseEqual("ogg", sub_type)) {
                        return .{ .audio_ogg = {} };
                    },
                    4 => if (isCaseEqual("wave", sub_type)) {
                        return .{ .audio_wave = {} };
                    },
                    4 => if (isCaseEqual("mpeg", sub_type)) {
                        return .{ .audio_mpeg = {} };
                    },
                    else => {},
                }
            } else if (isCaseEqual("video", main_type)) {
                switch (sub_type.len) {
                    3 => if (isCaseEqual("mp4", sub_type)) {
                        return .{ .video_mp4 = {} };
                    },
                    4 => if (isCaseEqual("webm", sub_type)) {
                        return .{ .video_webm = {} };
                    },
                    else => {},
                }
            },
            11 => if (isCaseEqual("application", main_type)) {
                switch (sub_type.len) {
                    3 => if (isCaseEqual("pdf", sub_type)) {
                        return .{ .application_pdf = {} };
                    } else if (isCaseEqual("zip", sub_type)) {
                        return .{ .application_zip = {} };
                    },
                    4 => if (isCaseEqual("json", sub_type)) {
                        return .{ .application_json = {} };
                    },
                    else => {},
                }
            },
            else => {},
        }
        return null;
    }

    const T_SPECIAL = blk: {
        var v = [_]bool{false} ** 256;
        for ("()<>@,;:\\\"/[]?=") |b| {
            v[b] = true;
        }
        break :blk v;
    };

    fn parseValue(allocator: Allocator, value: []const u8) ![]const u8 {
        if (value[0] != '"') {
            return value;
        }

        // 1 to skip the opening quote
        var value_pos: usize = 1;
        var unescaped_len: usize = 0;
        const last = value.len - 1;

        while (value_pos < value.len) {
            switch (value[value_pos]) {
                '"' => break,
                '\\' => {
                    if (value_pos == last) {
                        return error.Invalid;
                    }
                    const next = value[value_pos + 1];
                    if (T_SPECIAL[next] == false) {
                        return error.Invalid;
                    }
                    value_pos += 2;
                },
                else => value_pos += 1,
            }
            unescaped_len += 1;
        }

        if (unescaped_len == 0) {
            return error.Invalid;
        }

        value_pos = 1;
        const owned = try allocator.alloc(u8, unescaped_len);
        for (0..unescaped_len) |i| {
            switch (value[value_pos]) {
                '"' => break,
                '\\' => {
                    owned[i] = value[value_pos + 1];
                    value_pos += 2;
                },
                else => |c| {
                    owned[i] = c;
                    value_pos += 1;
                },
            }
        }
        return owned;
    }

    const VALID_CODEPOINTS = blk: {
        var v: [256]bool = undefined;
        for (0..256) |i| {
            v[i] = std.ascii.isAlphanumeric(i);
        }
        for ("!#$%&\\*+-.^'_`|~") |b| {
            v[b] = true;
        }
        break :blk v;
    };

    fn validType(value: []const u8) bool {
        for (value) |b| {
            if (VALID_CODEPOINTS[b] == false) {
                return false;
            }
        }
        return true;
    }

    fn trim(s: []const u8) []const u8 {
        return std.mem.trim(u8, s, &std.ascii.whitespace);
    }

    fn trimLeft(s: []const u8) []const u8 {
        return std.mem.trimLeft(u8, s, &std.ascii.whitespace);
    }

    fn trimRight(s: []const u8) []const u8 {
        return std.mem.trimRight(u8, s, &std.ascii.whitespace);
    }

    fn isCaseEqual(comptime target: anytype, value: []const u8) bool {
        // - 8 beause we don't care about the sentinel
        const bit_len = @bitSizeOf(@TypeOf(target.*)) - 8;
        const byte_len = bit_len / 8;

        const T = @Type(.{ .int = .{
            .bits = bit_len,
            .signedness = .unsigned,
        } });

        const bit_target: T = @bitCast(@as(*const [byte_len]u8, target).*);

        if (@as(T, @bitCast(value[0..byte_len].*)) == bit_target) {
            return true;
        }
        return std.ascii.eqlIgnoreCase(value, target);
    }
};

const testing = std.testing;
test "Mime: invalid " {
    const invalids = [_][]const u8{
        "",
        "text",
        "text /html",
        "text/ html",
        "text / html",
        "text/html other",
        "text/html; x",
        "text/html; x=",
        "text/html; x=  ",
        "text/html; = ",
        "text/html;=",
        "text/html; charset=\"\"",
        "text/html; charset=\"",
        "text/html; charset=\"\\",
        "text/html; charset=\"\\a\"", // invalid to escape non special characters
    };

    for (invalids) |invalid| {
        try testing.expectError(error.Invalid, Mime.parse(undefined, invalid));
    }
}

test "Mime: parse common" {
    try expect(.{ .content_type = .{ .text_xml = {} } }, "text/xml");
    try expect(.{ .content_type = .{ .text_html = {} } }, "text/html");
    try expect(.{ .content_type = .{ .text_plain = {} } }, "text/plain");

    try expect(.{ .content_type = .{ .text_xml = {} } }, "text/xml;");
    try expect(.{ .content_type = .{ .text_html = {} } }, "text/html;");
    try expect(.{ .content_type = .{ .text_plain = {} } }, "text/plain;");

    try expect(.{ .content_type = .{ .text_xml = {} } }, "  \ttext/xml");
    try expect(.{ .content_type = .{ .text_html = {} } }, "text/html   ");
    try expect(.{ .content_type = .{ .text_plain = {} } }, "text/plain \t\t");

    try expect(.{ .content_type = .{ .text_xml = {} } }, "TEXT/xml");
    try expect(.{ .content_type = .{ .text_html = {} } }, "text/Html");
    try expect(.{ .content_type = .{ .text_plain = {} } }, "TEXT/PLAIN");

    try expect(.{ .content_type = .{ .text_xml = {} } }, " TeXT/xml");
    try expect(.{ .content_type = .{ .text_html = {} } }, "teXt/HtML  ;");
    try expect(.{ .content_type = .{ .text_plain = {} } }, "tExT/PlAiN;");
}

test "Mime: parse uncommon" {
    const text_javascript = Expectation{
        .content_type = .{ .other = .{ .type = "text", .sub_type = "javascript" } },
    };
    try expect(text_javascript, "text/javascript");
    try expect(text_javascript, "text/javascript;");
    try expect(text_javascript, "  text/javascript\t  ");
    try expect(text_javascript, "  text/javascript\t  ;");

    try expect(
        .{ .content_type = .{ .other = .{ .type = "Text", .sub_type = "Javascript" } } },
        "Text/Javascript",
    );
}

test "Mime: parse charset" {
    try expect(.{
        .content_type = .{ .text_xml = {} },
        .charset = "utf-8",
        .params = "charset=utf-8",
    }, "text/xml; charset=utf-8");

    try expect(.{
        .content_type = .{ .text_xml = {} },
        .charset = "utf-8",
        .params = "charset=\"utf-8\"",
    }, "text/xml;charset=\"utf-8\"");

    try expect(.{
        .content_type = .{ .text_xml = {} },
        .charset = "\\ \" ",
        .params = "charset=\"\\\\ \\\" \"",
    }, "text/xml;charset=\"\\\\ \\\" \"   ");
}

test "Mime: isHTML" {
    const isHTML = struct {
        fn isHTML(expected: bool, input: []const u8) !void {
            var mime = try Mime.parse(testing.allocator, input);
            defer mime.deinit();
            try testing.expectEqual(expected, mime.isHTML());
        }
    }.isHTML;
    try isHTML(true, "text/html");
    try isHTML(true, "text/html;");
    try isHTML(true, "text/html; charset=utf-8");
    try isHTML(false, "text/htm"); // htm not html
    try isHTML(false, "text/plain");
    try isHTML(false, "over/9000");
}

test "Mime: sniff HTML content" {
    const html_samples = [_][]const u8{
        "<!DOCTYPE html><html><head><title>Test</title></head><body>Hello</body></html>",
        "<html><body>Simple HTML</body></html>",
        "  <html lang=\"en\"><head><meta charset=\"UTF-8\"></head><body></body></html>",
    };

    for (html_samples) |sample| {
        try testing.expectEqual(Mime.ContentTypeEnum.text_html, Mime.sniff(sample));
    }
}

test "Mime: sniff image content" {
    // JPEG signature
    const jpeg_bytes = "\xFF\xD8\xFF\xE0\x00\x10\x4A\x46\x49\x46";
    try testing.expectEqual(Mime.ContentTypeEnum.image_jpeg, Mime.sniff(jpeg_bytes));

    // PNG signature
    const png_bytes = "\x89PNG\r\n\x1A\n\x00\x00\x00\x0DIHDR";
    try testing.expectEqual(Mime.ContentTypeEnum.image_png, Mime.sniff(png_bytes));

    // GIF signature
    const gif_bytes = "GIF89a\x2A\x00\x2A\x00\x91\x00\x00";
    try testing.expectEqual(Mime.ContentTypeEnum.image_gif, Mime.sniff(gif_bytes));
}

test "Mime: sniff PDF content" {
    const pdf_bytes = "%PDF-1.5\n%¥±ë\n";
    try testing.expectEqual(Mime.ContentTypeEnum.application_pdf, Mime.sniff(pdf_bytes));
}

test "Mime: sniff JSON content" {
    const json_samples = [_][]const u8{
        "{\"name\":\"test\",\"value\":123}",
        "  [1, 2, 3, 4]  ",
        "{\n  \"test\": true\n}",
    };

    for (json_samples) |sample| {
        try testing.expectEqual(Mime.ContentTypeEnum.application_json, Mime.sniff(sample));
    }
}

test "Mime: sniff text content" {
    const text_samples = [_][]const u8{
        "This is just plain text content with no special formatting.",
        "Line 1\nLine 2\nLine 3",
        "Text with some symbols: !@#$%^&*()",
    };

    for (text_samples) |sample| {
        try testing.expectEqual(Mime.ContentTypeEnum.text_plain, Mime.sniff(sample));
    }
}

test "Mime: fromBytes constructor" {
    // Test HTML detection
    {
        const html = "<!DOCTYPE html><html><body>Test</body></html>";
        var mime = try Mime.fromBytes(testing.allocator, html);
        defer mime.deinit();
        try testing.expectEqual(true, mime.isHTML());
        try testing.expectEqualStrings("utf-8", mime.charset.?);
    }

    // Test PNG detection
    {
        const png = "\x89PNG\r\n\x1A\n\x00\x00\x00\x0DIHDR";
        var mime = try Mime.fromBytes(testing.allocator, png);
        defer mime.deinit();
        try testing.expectEqual(Mime.ContentTypeEnum.image_png, std.meta.activeTag(mime.content_type));
        try testing.expectEqual(null, mime.charset);
    }
}

test "Mime: toString" {
    {
        var mime = try Mime.parse(testing.allocator, "text/html; charset=utf-8");
        defer mime.deinit();
        const str = try mime.toString(testing.allocator);
        defer testing.allocator.free(str);
        try testing.expectEqualStrings("text/html; charset=utf-8", str);
    }

    {
        var mime = try Mime.fromBytes(testing.allocator, "\x89PNG\r\n\x1A\n");
        defer mime.deinit();
        const str = try mime.toString(testing.allocator);
        defer testing.allocator.free(str);
        try testing.expectEqualStrings("image/png", str);
    }
}

const Expectation = struct {
    content_type: Mime.ContentType,
    params: []const u8 = "",
    charset: ?[]const u8 = null,
};

fn expect(expected: Expectation, input: []const u8) !void {
    var actual = try Mime.parse(testing.allocator, input);
    defer actual.deinit();

    try testing.expectEqual(
        std.meta.activeTag(expected.content_type),
        std.meta.activeTag(actual.content_type),
    );

    switch (expected.content_type) {
        .other => |e| {
            const a = actual.content_type.other;
            try testing.expectEqualStrings(e.type, a.type);
            try testing.expectEqualStrings(e.sub_type, a.sub_type);
        },
        else => {}, // already asserted above
    }

    try testing.expectEqualStrings(expected.params, actual.params);

    if (expected.charset) |ec| {
        try testing.expectEqualStrings(ec, actual.charset.?);
    } else {
        try testing.expectEqual(null, actual.charset);
    }
}
