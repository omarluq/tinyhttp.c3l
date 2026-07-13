// A C3 port of picohttpparser by Kazuho Oku et al.
// Upstream: https://github.com/h2o/picohttpparser
//
// Copyright (c) 2009-2014 Kazuho Oku, Tokuhiro Matsuno, Daisuke Murase,
//                         Shigeo Mitsunari
//
// The original software is licensed under either the MIT License or the Perl
// license. This port preserves that notice.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
//
// Notes on the port:
//   * `char` is unsigned 8-bit in C3, so the original `(unsigned char)` casts
//     are unnecessary.
//   * The SSE4.2 `findchar_fast` fast paths are omitted; the portable scalar
//     loops (the `#else` branches of the original) are ported verbatim. This
//     keeps the parser correct across every target in the manifest.
//   * Tokens are returned as `char[]` slices into the caller's buffer rather
//     than as (pointer, length) pairs.

module tinyhttp::parser;

// Returned by the parse_* functions in place of a byte count.
const int PARTIAL = -2; // input is incomplete; call again with more data
const int INVALID = -1; // input is malformed

<* A single HTTP header.

   `name` has length 0 when the line is a continuation (obs-fold) of the
   previous header's value. *>
struct Header
{
    char[] name;
    char[] value;
}

// Populated by `parse_request` on success.
struct RequestHead
{
    char[]   method;
    char[]   path;
    int      minor_version;
    Header[] headers; // sub-slice of the caller-provided header buffer that was filled
}

// Populated by `parse_response` on success.
struct ResponseHead
{
    int      minor_version;
    int      status;
    char[]   msg;
    Header[] headers; // sub-slice of the caller-provided header buffer that was filled
}

// RFC 7230 token characters ("tchar"). Mirrors the original `token_char_map`.
const bool[256] IS_TOKEN_CHAR @private = {
    ['0'..'9'] = true,
    ['A'..'Z'] = true,
    ['a'..'z'] = true,
    ['!'] = true, ['#'] = true, ['$'] = true, ['%'] = true, ['&'] = true,
    ['\''] = true, ['*'] = true, ['+'] = true, ['-'] = true, ['.'] = true,
    ['^'] = true, ['_'] = true, ['`'] = true, ['|'] = true, ['~'] = true,
};

macro bool is_printable_ascii(char c) @private => c >= 0x20 && c <= 0x7e;

// Fast slowloris countermeasure: scans for the terminating CRLFCRLF so we can
// bail on incomplete input without re-parsing everything. Returns the position
// just past the double line break, or null (setting *ret) if not yet complete.
fn char* is_complete(char* buf, char* buf_end, usz last_len, int* ret) @private
{
    int ret_cnt = 0;
    buf = last_len < 3 ? buf : buf + last_len - 3;

    while (true)
    {
        if (buf == buf_end) { *ret = PARTIAL; return null; }
        if (*buf == '\r')
        {
            buf++;
            if (buf == buf_end) { *ret = PARTIAL; return null; }
            if (*buf++ != '\n') { *ret = INVALID; return null; }
            ret_cnt++;
        }
        else if (*buf == '\n')
        {
            buf++;
            ret_cnt++;
        }
        else
        {
            buf++;
            ret_cnt = 0;
        }
        if (ret_cnt == 2) return buf;
    }
}

// Reads up to (and consuming) the end of line, returning the token before the
// CR/LF as a slice. Bytes 0x00-0x1F (except HTAB) and 0x7F terminate the line.
fn char* get_token_to_eol(char* buf, char* buf_end, char[]* token, int* ret) @private
{
    char* token_start = buf;

    // Scan to the first line-ending control character.
    while (true)
    {
        if (buf == buf_end) { *ret = PARTIAL; return null; }
        char c = *buf;
        if ((c < 0x20 && c != '\t') || c == 0x7f) break;
        buf++;
    }

    usz token_len;
    if (*buf == '\r')
    {
        buf++;
        if (buf == buf_end) { *ret = PARTIAL; return null; }
        if (*buf++ != '\n') { *ret = INVALID; return null; }
        token_len = (usz)(buf - 2 - token_start);
    }
    else if (*buf == '\n')
    {
        token_len = (usz)(buf - token_start);
        buf++;
    }
    else
    {
        *ret = INVALID;
        return null;
    }
    *token = token_start[:token_len];
    return buf;
}

// Parses a token that ends at `next_char` (the delimiter is left unconsumed).
fn char* parse_token(char* buf, char* buf_end, char[]* token, char next_char, int* ret) @private
{
    char* buf_start = buf;
    if (buf == buf_end) { *ret = PARTIAL; return null; }
    while (true)
    {
        if (*buf == next_char) break;
        if (!IS_TOKEN_CHAR[*buf]) { *ret = INVALID; return null; }
        buf++;
        if (buf == buf_end) { *ret = PARTIAL; return null; }
    }
    *token = buf_start[:(usz)(buf - buf_start)];
    return buf;
}

// Parses "HTTP/1.<minor>" leaving buf just past the minor version digit.
fn char* parse_http_version(char* buf, char* buf_end, int* minor_version, int* ret) @private
{
    // We want at least [HTTP/1.<two chars>] to try to parse.
    if (buf_end - buf < 9) { *ret = PARTIAL; return null; }
    if (*buf++ != 'H') { *ret = INVALID; return null; }
    if (*buf++ != 'T') { *ret = INVALID; return null; }
    if (*buf++ != 'T') { *ret = INVALID; return null; }
    if (*buf++ != 'P') { *ret = INVALID; return null; }
    if (*buf++ != '/') { *ret = INVALID; return null; }
    if (*buf++ != '1') { *ret = INVALID; return null; }
    if (*buf++ != '.') { *ret = INVALID; return null; }
    char c = *buf;
    if (c < '0' || c > '9') { *ret = INVALID; return null; }
    *minor_version = (int)(c - '0');
    buf++;
    return buf;
}

fn char* parse_headers_impl(char* buf, char* buf_end, Header[] headers, usz* num_headers, usz max_headers, int* ret) @private
{
    while (true)
    {
        usz n = *num_headers;
        if (buf == buf_end) { *ret = PARTIAL; return null; }
        if (*buf == '\r')
        {
            buf++;
            if (buf == buf_end) { *ret = PARTIAL; return null; }
            if (*buf++ != '\n') { *ret = INVALID; return null; }
            break;
        }
        else if (*buf == '\n')
        {
            buf++;
            break;
        }
        if (n == max_headers) { *ret = INVALID; return null; }
        if (!(n != 0 && (*buf == ' ' || *buf == '\t')))
        {
            // Parsing a name; do not discard SP before the colon, see
            // http://www.mozilla.org/security/announce/2006/mfsa2006-33.html
            char[] name;
            buf = parse_token(buf, buf_end, &name, ':', ret);
            if (buf == null) return null;
            if (name.len == 0) { *ret = INVALID; return null; }
            headers[n].name = name;
            buf++; // skip ':'
            while (true)
            {
                if (buf == buf_end) { *ret = PARTIAL; return null; }
                if (!(*buf == ' ' || *buf == '\t')) break;
                buf++;
            }
        }
        else
        {
            // Continuation line of a multiline header.
            headers[n].name = {};
        }
        char[] value;
        buf = get_token_to_eol(buf, buf_end, &value, ret);
        if (buf == null) return null;
        // Remove trailing SPs and HTABs.
        usz vend = value.len;
        while (vend != 0)
        {
            char c = value[vend - 1];
            if (c != ' ' && c != '\t') break;
            vend--;
        }
        headers[n].value = value[:vend];
        *num_headers = n + 1;
    }
    return buf;
}

fn char* parse_request_impl(char* buf, char* buf_end, RequestHead* req, Header[] headers, usz* num_headers, usz max_headers, int* ret) @private
{
    // Skip the first empty line (some clients add CRLF after POST content).
    if (buf == buf_end) { *ret = PARTIAL; return null; }
    if (*buf == '\r')
    {
        buf++;
        if (buf == buf_end) { *ret = PARTIAL; return null; }
        if (*buf++ != '\n') { *ret = INVALID; return null; }
    }
    else if (*buf == '\n')
    {
        buf++;
    }

    // Method. Written straight into the output as it is parsed, matching the
    // original (outputs after a negative return are undefined either way).
    buf = parse_token(buf, buf_end, &req.method, ' ', ret);
    if (buf == null) return null;
    do
    {
        buf++;
        if (buf == buf_end) { *ret = PARTIAL; return null; }
    }
    while (*buf == ' ');

    // Path (the original ADVANCE_TOKEN macro, scalar version).
    char* tok_start = buf;
    while (true)
    {
        if (*buf == ' ') break;
        if (!is_printable_ascii(*buf))
        {
            if (*buf < 0x20 || *buf == 0x7f) { *ret = INVALID; return null; }
        }
        buf++;
        if (buf == buf_end) { *ret = PARTIAL; return null; }
    }
    req.path = tok_start[:(usz)(buf - tok_start)];
    do
    {
        buf++;
        if (buf == buf_end) { *ret = PARTIAL; return null; }
    }
    while (*buf == ' ');

    if (req.method.len == 0 || req.path.len == 0) { *ret = INVALID; return null; }

    buf = parse_http_version(buf, buf_end, &req.minor_version, ret);
    if (buf == null) return null;

    if (*buf == '\r')
    {
        buf++;
        if (buf == buf_end) { *ret = PARTIAL; return null; }
        if (*buf++ != '\n') { *ret = INVALID; return null; }
    }
    else if (*buf == '\n')
    {
        buf++;
    }
    else
    {
        *ret = INVALID;
        return null;
    }

    return parse_headers_impl(buf, buf_end, headers, num_headers, max_headers, ret);
}

fn char* parse_response_impl(char* buf, char* buf_end, ResponseHead* resp, Header[] headers, usz* num_headers, usz max_headers, int* ret) @private
{
    // Parse "HTTP/1.x". Fields are written into the output as parsed, matching
    // the original (outputs after a negative return are undefined either way).
    buf = parse_http_version(buf, buf_end, &resp.minor_version, ret);
    if (buf == null) return null;

    // Skip space(s).
    if (*buf != ' ') { *ret = INVALID; return null; }
    do
    {
        buf++;
        if (buf == buf_end) { *ret = PARTIAL; return null; }
    }
    while (*buf == ' ');

    // Status code: we want at least three digits plus one more char.
    if (buf_end - buf < 4) { *ret = PARTIAL; return null; }
    char d0 = *buf;
    if (d0 < '0' || d0 > '9') { *ret = INVALID; return null; }
    resp.status = 100 * (int)(d0 - '0');
    buf++;
    char d1 = *buf;
    if (d1 < '0' || d1 > '9') { *ret = INVALID; return null; }
    resp.status += 10 * (int)(d1 - '0');
    buf++;
    char d2 = *buf;
    if (d2 < '0' || d2 > '9') { *ret = INVALID; return null; }
    resp.status += (int)(d2 - '0');
    buf++;

    // Message, including the preceding space.
    buf = get_token_to_eol(buf, buf_end, &resp.msg, ret);
    if (buf == null) return null;
    if (resp.msg.len == 0)
    {
        // ok
    }
    else if (resp.msg[0] == ' ')
    {
        // Remove preceding spaces. A successful get_token_to_eol guarantees a
        // non-space char before the end of buffer.
        usz off = 0;
        while (off < resp.msg.len && resp.msg[off] == ' ') off++;
        resp.msg = resp.msg[off:resp.msg.len - off];
    }
    else
    {
        // Garbage after the status code.
        *ret = INVALID;
        return null;
    }

    return parse_headers_impl(buf, buf_end, headers, num_headers, max_headers, ret);
}

<* Parse an HTTP request.

   @param buf : "the request bytes received so far"
   @param req : "filled in on success"
   @param headers : "caller-provided storage; its length is the header capacity"
   @param last_len : "length of the buffer at the previous call (0 on the first), used for the incremental slowloris check"
   @return "number of bytes consumed on success, or PARTIAL / INVALID" *>
fn int parse_request(char[] buf, RequestHead* req, Header[] headers, usz last_len)
{
    char* start = buf.ptr;
    char* end = start + buf.len;
    usz max_headers = headers.len;
    usz num_headers = 0;
    int r;

    *req = {};
    req.minor_version = -1;

    if (last_len != 0 && is_complete(start, end, last_len, &r) == null) return r;

    char* p = parse_request_impl(start, end, req, headers, &num_headers, max_headers, &r);
    if (p == null) return r;

    req.headers = headers[:num_headers];
    return (int)(p - start);
}

<* Parse an HTTP response. See `parse_request` for the parameter conventions. *>
fn int parse_response(char[] buf, ResponseHead* resp, Header[] headers, usz last_len)
{
    char* start = buf.ptr;
    char* end = start + buf.len;
    usz max_headers = headers.len;
    usz num_headers = 0;
    int r;

    *resp = {};
    resp.minor_version = -1;

    if (last_len != 0 && is_complete(start, end, last_len, &r) == null) return r;

    char* p = parse_response_impl(start, end, resp, headers, &num_headers, max_headers, &r);
    if (p == null) return r;

    resp.headers = headers[:num_headers];
    return (int)(p - start);
}

<* Parse a bare block of HTTP headers (e.g. trailers).

   @param buf : "the header bytes received so far"
   @param headers : "caller-provided storage; its length is the header capacity"
   @param num_headers : "set to the number of headers parsed"
   @param last_len : "length of the buffer at the previous call (0 on the first)"
   @return "number of bytes consumed on success, or PARTIAL / INVALID" *>
fn int parse_headers(char[] buf, Header[] headers, usz* num_headers, usz last_len)
{
    char* start = buf.ptr;
    char* end = start + buf.len;
    usz max_headers = headers.len;
    int r;

    *num_headers = 0;

    if (last_len != 0 && is_complete(start, end, last_len, &r) == null) return r;

    char* p = parse_headers_impl(start, end, headers, num_headers, max_headers, &r);
    if (p == null) return r;

    return (int)(p - start);
}
