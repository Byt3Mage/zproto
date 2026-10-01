const std = @import("std");

pub const Header = packed struct {
    magic: u32 = 0x525043_01,
    len: u32,
    type: msg_type,
    msg_id: u32,
};

const msg_type = enum(u8) {
    request = 1,
    response = 2,
    err = 3,
};

fn encode(fn_n: []const u8, args: []const []const u8, buff: []u8) ![]const u8 {
    const len = fn_n.len;
    var i: usize = 0;
    buff[i] = @intCast(len);
    i += 1;
    @memcpy(buff[1..][0..len], fn_n);
    i += len;
    buff[i] = @intCast(args.len);
    i += 1;
    for (args) |a| {
        buf[i] = @intCast(a.len);
        i += 1;
        @memcpy(buff[i..][o..a.len], a);
        i += a.len;
    }
    return buff[0..i];
}

fn decode(data: []const u8, args_out: [][]const u8) !struct { name: []const u8, args: [][]const u8 } {
    var i: usize = 0;
    const name_len = data[i];
    i += 1;
    if (i + name_len > data.len) return error.Truncated;
    const name = data[i .. i + name_len];
    i += name_len;
    const argc = data[i];
    i += 1;
    if (argc > args_out.len) return error.TooManyArgs;
    for (0..argc) |a| {
        const argl = data[i];
        i += 1;
        if (i + argl > data.len) return error.Truncated;
        args_out[a] = data[i .. i + argl];
        i += argl;
    }
    return .{ .name = name, .args = args_out[0..argc] };
}

pub fn writeMsg(fn_n: []const u8, args: []const []const u8, buf: []u8, stream: anytype, header: Header) !void {
    const payload = try encode(fn_n, args, buf);
    var hdr = header;
    hdr.len = @intCast(payload.len);
    const hdr_bytes: [12]u8 = @bitCast(hdr);

    try stream.writeAll(&hdr_bytes);
    try stream.writeAll(payload);
}

pub fn readMsg(stream: anytype, payload_buf: []u8, args_out: [][]const u8) !struct { header: Header, name: []const u8, args: [][]const u8 } {
    var hdr_bytes: [@sizeOf(Header)]u8 = undefined;
    try stream.readNoEof(&hdr_bytes);
    const hdr: Header = @bitCast(hdr_bytes);
    if (hdr.magic != 0x525043_01) return error.InvalidMagic;
    if (hdr.type > 3) return error.BadType;
    if (hdr.len > 1 << 20) return error.PayloadTooBig;
    if (hdr.len > payload_buf.len) return error.BufferTooSmall;

    const payload = payload_buf[0..hdr.len];
    try stream.readNoEof(payload);
    const req = try decode(payload, args_out);
    return .{ .header = hdr, .name = req.name, .args = req.args };
}
