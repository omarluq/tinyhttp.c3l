// An idiomatic C3 reimplementation of h2o/picohttpparser's HTTP/1.x parsing.
// Upstream: https://github.com/h2o/picohttpparser
//
// Copyright (c) 2009-2014 Kazuho Oku, Tokuhiro Matsuno, Daisuke Murase,
//                         Shigeo Mitsunari
//
// The original software is licensed under either the MIT License or the Perl
// license. This reimplementation preserves that notice.
//
// This is NOT a line-by-line port: it walks the input with a slice-based
// `Reader` cursor and signals progress with optionals (`!` propagates the
// INCOMPLETE / MALFORMED faults). Observable behaviour — including the slowloris
// completeness check — matches the original, with one deliberate deviation:
// obs-fold continuation lines are rejected as MALFORMED (RFC 7230 §3.2.4
// deprecates them). `char` is unsigned 8-bit in C3, so the original
// `(unsigned char)` casts are unnecessary.

module httpparser;

<* Faults thrown by the parse_* functions:
   - INCOMPLETE: the input is a valid prefix; call again with more bytes.
   - MALFORMED:  the input is invalid. *>
faultdef INCOMPLETE, MALFORMED;

<* A single HTTP header: a name slice and a value slice into the caller's
   buffer. *>
struct Header
{
    char[] name;
    char[] value;
}

<* Populated by `parse_request` on success. *>
struct Request
{
    char[]   method;
    char[]   path;
    int      minor_version;
    Header[] headers;   // sub-slice of the caller's header buffer that was filled
}

<* Populated by `parse_response` on success. *>
struct Response
{
    int      minor_version;
    int      status;
    char[]   msg;
    Header[] headers;   // sub-slice of the caller's header buffer that was filled
}

// RFC 7230 token characters ("tchar").
const bool[256] IS_TOKEN_CHAR @private = {
    ['0'..'9'] = true,
    ['A'..'Z'] = true,
    ['a'..'z'] = true,
    ['!'] = true, ['#'] = true, ['$'] = true, ['%'] = true, ['&'] = true,
    ['\''] = true, ['*'] = true, ['+'] = true, ['-'] = true, ['.'] = true,
    ['^'] = true, ['_'] = true, ['`'] = true, ['|'] = true, ['~'] = true,
};

// ---- cursor ----------------------------------------------------------------

// A forward cursor over the input buffer. Its methods return optionals: `!`
// propagates INCOMPLETE (ran off the end) or MALFORMED (bad byte) to the caller.
struct Reader @private
{
    char[] buf;
    usz    pos;
}

// Current byte without advancing; INCOMPLETE at end of input.
fn char? Reader.peek(&self)
{
    if (self.pos >= self.buf.len) return INCOMPLETE~;
    return self.buf[self.pos];
}

// Consume and return the current byte.
fn char? Reader.next(&self)
{
    char c = self.peek()!;
    self.pos++;
    return c;
}

// Consume a byte that must equal `c`.
fn void? Reader.expect(&self, char c)
{
    if (self.next()! != c) return MALFORMED~;
}

// Skip a run of byte `c`.
fn void? Reader.skip(&self, char c)
{
    while (self.peek()! == c) self.pos++;
}

// Skip a run of SP / HTAB (optional whitespace).
fn void? Reader.skip_ws(&self)
{
    while (true)
    {
        char c = self.peek()!;
        if (c != ' ' && c != '\t') break;
        self.pos++;
    }
}

// Consume a required line ending (CRLF or bare LF).
fn void? Reader.eol(&self)
{
    if (!self.at_eol()!) return MALFORMED~;
}

// If positioned at a line ending, consume it and return true; else false.
fn bool? Reader.at_eol(&self)
{
    switch (self.peek()!)
    {
        case '\r': self.pos++; self.expect('\n')!; return true;
        case '\n': self.pos++; return true;
        default:   return false;
    }
}

// A tchar token ending at (but not consuming) `delim`.
fn char[]? Reader.token(&self, char delim)
{
    usz start = self.pos;
    for (char c = self.peek()!; c != delim; c = self.peek()!)
    {
        if (!IS_TOKEN_CHAR[c]) return MALFORMED~;
        self.pos++;
    }
    return self.buf[start:self.pos - start];
}

// A request-target ending at (but not consuming) SP. Rejects controls and DEL;
// bytes with the high bit set are allowed.
fn char[]? Reader.target(&self)
{
    usz start = self.pos;
    for (char c = self.peek()!; c != ' '; c = self.peek()!)
    {
        if (c < 0x20 || c == 0x7f) return MALFORMED~;
        self.pos++;
    }
    return self.buf[start:self.pos - start];
}

// The text up to the end of line; consumes the CR/LF. A control byte other than
// HTAB / CR / LF ends the scan and is rejected as MALFORMED.
fn char[]? Reader.line(&self)
{
    usz start = self.pos;
    for (char c = self.peek()!; !((c < 0x20 && c != '\t') || c == 0x7f); c = self.peek()!)
    {
        self.pos++;
    }
    usz end = self.pos;
    self.eol()!;
    return self.buf[start:end - start];
}

// A single decimal digit's value.
fn int? Reader.digit(&self)
{
    char c = self.next()!;
    if (c < '0' || c > '9') return MALFORMED~;
    return (int)(c - '0');
}

// "HTTP/1.<minor>" -> the minor version.
fn int? Reader.http_version(&self)
{
    // We want at least "HTTP/1.x" plus a lookahead byte before trying.
    if (self.buf.len - self.pos < 9) return INCOMPLETE~;
    if (!mem::equals(self.buf[self.pos:7], (char[])"HTTP/1.")) return MALFORMED~;
    self.pos += 7;
    return self.digit()!;
}

// ---- structural parsers ----------------------------------------------------

// Parse a header block into `out`, setting `*count`; `out.len` is the capacity.
fn void? Reader.header_block(&self, Header[] out, usz* count)
{
    while (true)
    {
        usz n = *count;
        if (self.at_eol()!) return;                 // blank line terminates
        if (n == out.len) return MALFORMED~;        // no room

        char c = self.peek()!;
        if (n != 0 && (c == ' ' || c == '\t')) return MALFORMED~;   // obs-fold continuation rejected (RFC 7230 §3.2.4)

        // Do not discard SP before the colon, see
        // http://www.mozilla.org/security/announce/2006/mfsa2006-33.html
        char[] name = self.token(':')!;
        if (name.len == 0) return MALFORMED~;
        out[n].name = name;
        self.pos++;                             // skip ':'
        self.skip_ws()!;

        // Value: trailing SP/HTAB trimmed (leading already consumed by skip_ws).
        char[] value = self.line()!;
        usz vend = value.len;
        while (vend != 0 && (value[vend - 1] == ' ' || value[vend - 1] == '\t')) vend--;
        out[n].value = value[:vend];
        *count = n + 1;
    }
}

fn void? Reader.request(&self, Request* req, Header[] headers, usz* count)
{
    self.at_eol()!;                                  // skip a leading blank line
    req.method = self.token(' ')!;
    self.skip(' ')!;
    req.path = self.target()!;
    self.skip(' ')!;
    if (req.method.len == 0 || req.path.len == 0) return MALFORMED~;
    req.minor_version = self.http_version()!;
    self.eol()!;
    self.header_block(headers, count)!;
}

fn void? Reader.response(&self, Response* resp, Header[] headers, usz* count)
{
    resp.minor_version = self.http_version()!;
    self.expect(' ')!;
    self.skip(' ')!;
    // Status code: three digits plus at least one more byte.
    if (self.buf.len - self.pos < 4) return INCOMPLETE~;
    int d0 = self.digit()!;
    int d1 = self.digit()!;
    int d2 = self.digit()!;
    resp.status = 100 * d0 + 10 * d1 + d2;

    // Message, including any preceding space; strip the leading spaces.
    char[] msg = self.line()!;
    if (msg.len != 0 && msg[0] != ' ') return MALFORMED~;
    usz off = 0;
    while (off < msg.len && msg[off] == ' ') off++;
    resp.msg = msg[off:msg.len - off];

    self.header_block(headers, count)!;
}

// Slowloris countermeasure: scan (from just before the previously-seen tail) for
// the terminating CRLFCRLF, so an incomplete message fails fast without a full
// parse. Succeeds if complete, throws INCOMPLETE otherwise.
fn void? check_complete(char[] buf, usz last_len) @private
{
    Reader r = { .buf = buf, .pos = last_len < 3 ? 0 : last_len - 3 };
    int run = 0;
    while (run < 2)
    {
        switch (r.next()!)
        {
            case '\r': r.expect('\n')!; run++;
            case '\n': run++;
            default:   run = 0;
        }
    }
}

// ---- public API ------------------------------------------------------------

<* Parse an HTTP request.
   @param buf : "the request bytes received so far"
   @param req : "filled in on success"
   @param headers : "caller storage; its length is the header capacity"
   @param last_len : "length of buf at the previous call (0 on the first)"
   @return "number of bytes consumed"
   @return? INCOMPLETE : "need more input"
   @return? MALFORMED : "invalid input" *>
fn usz? parse_request(char[] buf, Request* req, Header[] headers, usz last_len)
{
    *req = {};
    req.minor_version = -1;
    if (last_len != 0) check_complete(buf, last_len)!;

    usz count = 0;
    Reader r = { .buf = buf };
    r.request(req, headers, &count)!;
    req.headers = headers[:count];
    return r.pos;
}

<* Parse an HTTP response. See `parse_request` for the parameter conventions. *>
fn usz? parse_response(char[] buf, Response* resp, Header[] headers, usz last_len)
{
    *resp = {};
    resp.minor_version = -1;
    if (last_len != 0) check_complete(buf, last_len)!;

    usz count = 0;
    Reader r = { .buf = buf };
    r.response(resp, headers, &count)!;
    resp.headers = headers[:count];
    return r.pos;
}

<* Parse a bare block of HTTP headers (e.g. trailers).
   See `parse_request` for the shared parameter conventions.
   @param [&out] num_headers : "set to the number of headers parsed" *>
fn usz? parse_headers(char[] buf, Header[] headers, usz* num_headers, usz last_len)
{
    *num_headers = 0;
    if (last_len != 0) check_complete(buf, last_len)!;

    Reader r = { .buf = buf };
    r.header_block(headers, num_headers)!;
    return r.pos;
}
