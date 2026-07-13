// Tests for the picohttpparser C3 port. Mirrors cases from the upstream
// picotest suite (t/00picohttpparser.c).
module tinyhttp::parser;

// Compare a parsed slice against an expected string.
fn bool seq(char[] a, String b) @local
{
    if (a.len != b.len) return false;
    foreach (i, c : a) if (c != b[i]) return false;
    return true;
}

// Copy an immutable string into a mutable stack buffer (for chunked tests).
macro char[] fill(char[] storage, String s) @local
{
    storage[:s.len] = s[:s.len];
    return storage[:s.len];
}

// ---- parse_request ---------------------------------------------------------

fn void test_request_simple() @test
{
    String req = "GET / HTTP/1.0\r\n\r\n";
    RequestHead r;
    Header[8] hdrs;
    int rc = parse_request(req, &r, hdrs[..], 0);
    assert(rc == (int)req.len);
    assert(seq(r.method, "GET"));
    assert(seq(r.path, "/"));
    assert(r.minor_version == 0);
    assert(r.headers.len == 0);
}

fn void test_request_headers() @test
{
    String req = "GET /hi HTTP/1.1\r\nHost: example.com\r\nCookie: \r\n\r\n";
    RequestHead r;
    Header[8] hdrs;
    int rc = parse_request(req, &r, hdrs[..], 0);
    assert(rc == (int)req.len);
    assert(seq(r.method, "GET"));
    assert(seq(r.path, "/hi"));
    assert(r.minor_version == 1);
    assert(r.headers.len == 2);
    assert(seq(r.headers[0].name, "Host"));
    assert(seq(r.headers[0].value, "example.com"));
    assert(seq(r.headers[1].name, "Cookie"));
    assert(r.headers[1].value.len == 0);
}

fn void test_request_multiple_spaces() @test
{
    // Multiple spaces between tokens are allowed.
    String req = "GET   /   HTTP/1.0\r\n\r\n";
    RequestHead r;
    Header[4] hdrs;
    int rc = parse_request(req, &r, hdrs[..], 0);
    assert(rc == (int)req.len);
    assert(seq(r.method, "GET"));
    assert(seq(r.path, "/"));
}

fn void test_request_trailing_ws_trim() @test
{
    // Trailing SP/HTAB in a value are stripped; internal ones kept.
    String req = "GET / HTTP/1.0\r\nH: a b  \t \r\n\r\n";
    RequestHead r;
    Header[4] hdrs;
    int rc = parse_request(req, &r, hdrs[..], 0);
    assert(rc == (int)req.len);
    assert(r.headers.len == 1);
    assert(seq(r.headers[0].name, "H"));
    assert(seq(r.headers[0].value, "a b"));
}

fn void test_request_multiline_continuation() @test
{
    // Obs-fold continuation line has a zero-length header name.
    String req = "GET / HTTP/1.0\r\nFoo: ab\r\n bc\r\n\r\n";
    RequestHead r;
    Header[4] hdrs;
    int rc = parse_request(req, &r, hdrs[..], 0);
    assert(rc == (int)req.len);
    assert(r.headers.len == 2);
    assert(seq(r.headers[0].name, "Foo"));
    assert(seq(r.headers[0].value, "ab"));
    assert(r.headers[1].name.len == 0);
    // Obs-fold preserves the leading whitespace of the continuation line;
    // only trailing whitespace is trimmed (matches upstream picohttpparser).
    assert(seq(r.headers[1].value, " bc"));
}

fn void test_request_partial() @test
{
    String req = "GET / HTTP/1.0\r\n\r";
    RequestHead r;
    Header[4] hdrs;
    assert(parse_request(req, &r, hdrs[..], 0) == PARTIAL);

    assert(parse_request("", &r, hdrs[..], 0) == PARTIAL);
    assert(parse_request("G", &r, hdrs[..], 0) == PARTIAL);
    assert(parse_request("GET / HTTP/1.0\r\nHost: x", &r, hdrs[..], 0) == PARTIAL);
}

fn void test_request_invalid() @test
{
    RequestHead r;
    Header[4] hdrs;
    // Bad HTTP version token.
    assert(parse_request("GET / HTXP/1.0\r\n\r\n", &r, hdrs[..], 0) == INVALID);
    // Empty header name.
    assert(parse_request("GET / HTTP/1.0\r\n: v\r\n\r\n", &r, hdrs[..], 0) == INVALID);
    // Too many headers for the (size-1) capacity.
    Header[1] one;
    assert(parse_request("GET / HTTP/1.0\r\nA: b\r\nC: d\r\n\r\n", &r, one[..], 0) == INVALID);
}

fn void test_request_slowloris() @test
{
    // last_len != 0 triggers the incremental completeness check.
    RequestHead r;
    Header[4] hdrs;
    // Not complete yet.
    String p = "GET / HTTP/1.0\r\nHost: x\r\n";
    assert(parse_request(p, &r, hdrs[..], p.len) == PARTIAL);
    // Complete; is_complete finds CRLFCRLF and full parse proceeds.
    String c = "GET / HTTP/1.0\r\n\r\n";
    assert(parse_request(c, &r, hdrs[..], c.len - 1) == (int)c.len);
}

// ---- parse_response --------------------------------------------------------

fn void test_response_simple() @test
{
    String resp = "HTTP/1.1 200 OK\r\n\r\n";
    ResponseHead r;
    Header[8] hdrs;
    int rc = parse_response(resp, &r, hdrs[..], 0);
    assert(rc == (int)resp.len);
    assert(r.minor_version == 1);
    assert(r.status == 200);
    assert(seq(r.msg, "OK"));
    assert(r.headers.len == 0);
}

fn void test_response_headers_and_long_msg() @test
{
    String resp = "HTTP/1.0 500 Internal Server Error\r\nX-Y: z\r\n\r\n";
    ResponseHead r;
    Header[8] hdrs;
    int rc = parse_response(resp, &r, hdrs[..], 0);
    assert(rc == (int)resp.len);
    assert(r.status == 500);
    assert(seq(r.msg, "Internal Server Error"));
    assert(r.headers.len == 1);
    assert(seq(r.headers[0].name, "X-Y"));
    assert(seq(r.headers[0].value, "z"));
}

fn void test_response_empty_msg() @test
{
    String resp = "HTTP/1.1 200 \r\n\r\n";
    ResponseHead r;
    Header[4] hdrs;
    int rc = parse_response(resp, &r, hdrs[..], 0);
    assert(rc == (int)resp.len);
    assert(r.status == 200);
    assert(r.msg.len == 0);
}

fn void test_response_partial_and_invalid() @test
{
    ResponseHead r;
    Header[4] hdrs;
    assert(parse_response("HTTP/1.1 200 OK\r\n", &r, hdrs[..], 0) == PARTIAL);
    assert(parse_response("HTTP/1.1 2", &r, hdrs[..], 0) == PARTIAL);
    // Non-digit status.
    assert(parse_response("HTTP/1.1 2x0 OK\r\n\r\n", &r, hdrs[..], 0) == INVALID);
    // Garbage right after the status code (no space, not EOL).
    assert(parse_response("HTTP/1.1 200X\r\n\r\n", &r, hdrs[..], 0) == INVALID);
}

// ---- parse_headers ---------------------------------------------------------

fn void test_headers_only() @test
{
    String h = "Host: example.com\r\nAccept: */*\r\n\r\n";
    Header[8] hdrs;
    usz n;
    int rc = parse_headers(h, hdrs[..], &n, 0);
    assert(rc == (int)h.len);
    assert(n == 2);
    assert(seq(hdrs[0].name, "Host"));
    assert(seq(hdrs[0].value, "example.com"));
    assert(seq(hdrs[1].name, "Accept"));
    assert(seq(hdrs[1].value, "*/*"));
}

// ---- decode_chunked --------------------------------------------------------

fn void test_chunked_simple() @test
{
    char[64] store;
    char[] buf = fill(&store, "3\r\nabc\r\n0\r\n\r\n");
    usz bufsz = buf.len;
    ChunkedDecoder dec;
    sz r = decode_chunked(&dec, buf, &bufsz);
    assert(r == 2);          // the trailing CRLF after the last chunk
    assert(bufsz == 3);
    assert(seq(store[:3], "abc"));
}

fn void test_chunked_multiple_and_hex_size() @test
{
    // Two chunks, second uses an upper-case hex size and a chunk extension.
    char[128] store;
    char[] buf = fill(&store, "3\r\nabc\r\nA;ext=1\r\n0123456789\r\n0\r\n\r\n");
    usz bufsz = buf.len;
    ChunkedDecoder dec;
    sz r = decode_chunked(&dec, buf, &bufsz);
    assert(r == 2);
    assert(bufsz == 13);
    assert(seq(store[:13], "abc0123456789"));
}

fn void test_chunked_partial_then_complete() @test
{
    ChunkedDecoder dec;

    char[64] s1;
    char[] b1 = fill(&s1, "3\r\nab");
    usz z1 = b1.len;
    sz r1 = decode_chunked(&dec, b1, &z1);
    assert(r1 == PARTIAL);
    assert(z1 == 2);
    assert(seq(s1[:2], "ab"));
    assert(decode_chunked_is_in_data(&dec));

    char[64] s2;
    char[] b2 = fill(&s2, "c\r\n0\r\n\r\n");
    usz z2 = b2.len;
    sz r2 = decode_chunked(&dec, b2, &z2);
    assert(r2 == 2);
    assert(z2 == 1);
    assert(seq(s2[:1], "c"));
    assert(!decode_chunked_is_in_data(&dec));
}

fn void test_chunked_consume_trailer() @test
{
    char[64] store;
    char[] buf = fill(&store, "0\r\nFoo: bar\r\n\r\n");
    usz bufsz = buf.len;
    ChunkedDecoder dec;
    dec.consume_trailer = true;
    sz r = decode_chunked(&dec, buf, &bufsz);
    assert(r == 0);
    assert(bufsz == 0);
}

fn void test_chunked_invalid() @test
{
    char[64] store;
    char[] buf = fill(&store, "z\r\n");   // 'z' is not a hex digit
    usz bufsz = buf.len;
    ChunkedDecoder dec;
    assert(decode_chunked(&dec, buf, &bufsz) == INVALID);
}

// ---- internal helpers ------------------------------------------------------

fn void test_decode_hex() @test
{
    assert(decode_hex('0') == 0);
    assert(decode_hex('9') == 9);
    assert(decode_hex('a') == 10);
    assert(decode_hex('F') == 15);
    assert(decode_hex('g') == -1);
    assert(decode_hex(' ') == -1);
}

fn void test_is_printable_ascii() @test
{
    assert(is_printable_ascii(' '));
    assert(is_printable_ascii('~'));
    assert(!is_printable_ascii('\t'));
    assert(!is_printable_ascii(0x1f));
    assert(!is_printable_ascii(0x7f));
    assert(!is_printable_ascii(0x80));
}
