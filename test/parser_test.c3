// Tests for the parser. Mirrors cases from the upstream picotest suite
// (t/00picohttpparser.c).
module httpparser;

// Compare a parsed slice against an expected string.
fn bool seq(char[] a, String b) @local => a == (char[])b;

// Copy an immutable string into a mutable stack buffer (for chunked tests).
macro char[] fill(char[] storage, String s) @local
{
    storage[:s.len] = s[:s.len];
    return storage[:s.len];
}

// Assert a parse succeeded, consuming exactly `n` bytes.
macro @assert_ok(#call, usz n) @local { assert(#call!! == n); }

// Assert a parse threw the fault `want`.
macro @assert_fault(#call, fault want) @local
{
    if (catch err = #call) { assert(err == want); }
    else { assert(false, "expected a fault"); }
}

// ---- parse_request ---------------------------------------------------------

fn void test_request_simple() @test
{
    String req = "GET / HTTP/1.0\r\n\r\n";
    Request r;
    Header[8] hdrs;
    @assert_ok(parse_request(req, &r, hdrs[..], 0), req.len);
    assert(seq(r.method, "GET"));
    assert(seq(r.path, "/"));
    assert(r.minor_version == 0);
    assert(r.headers.len == 0);
}

fn void test_request_headers() @test
{
    String req = "GET /hi HTTP/1.1\r\nHost: example.com\r\nCookie: \r\n\r\n";
    Request r;
    Header[8] hdrs;
    @assert_ok(parse_request(req, &r, hdrs[..], 0), req.len);
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
    String req = "GET   /   HTTP/1.0\r\n\r\n";
    Request r;
    Header[4] hdrs;
    @assert_ok(parse_request(req, &r, hdrs[..], 0), req.len);
    assert(seq(r.method, "GET"));
    assert(seq(r.path, "/"));
}

fn void test_request_trailing_ws_trim() @test
{
    // Trailing SP/HTAB in a value are stripped; internal ones kept.
    String req = "GET / HTTP/1.0\r\nH: a b  \t \r\n\r\n";
    Request r;
    Header[4] hdrs;
    @assert_ok(parse_request(req, &r, hdrs[..], 0), req.len);
    assert(r.headers.len == 1);
    assert(seq(r.headers[0].name, "H"));
    assert(seq(r.headers[0].value, "a b"));
}

fn void test_request_multiline_continuation() @test
{
    // #8: obs-fold continuation lines are rejected as MALFORMED (RFC 7230 §3.2.4).
    String req = "GET / HTTP/1.0\r\nFoo: ab\r\n bc\r\n\r\n";
    Request r;
    Header[4] hdrs;
    @assert_fault(parse_request(req, &r, hdrs[..], 0), MALFORMED);
}

fn void test_request_partial() @test
{
    Request r;
    Header[4] hdrs;
    @assert_fault(parse_request("GET / HTTP/1.0\r\n\r", &r, hdrs[..], 0), INCOMPLETE);
    @assert_fault(parse_request("", &r, hdrs[..], 0), INCOMPLETE);
    @assert_fault(parse_request("G", &r, hdrs[..], 0), INCOMPLETE);
    @assert_fault(parse_request("GET / HTTP/1.0\r\nHost: x", &r, hdrs[..], 0), INCOMPLETE);
}

fn void test_request_invalid() @test
{
    Request r;
    Header[4] hdrs;
    @assert_fault(parse_request("GET / HTXP/1.0\r\n\r\n", &r, hdrs[..], 0), MALFORMED);   // bad version
    @assert_fault(parse_request("GET / HTTP/1.0\r\n: v\r\n\r\n", &r, hdrs[..], 0), MALFORMED); // empty name
    Header[1] one;
    @assert_fault(parse_request("GET / HTTP/1.0\r\nA: b\r\nC: d\r\n\r\n", &r, one[..], 0), MALFORMED); // too many
}

fn void test_request_target_high_bit_and_controls() @test
{
    // #24: target() rejects controls (< 0x20) and DEL (0x7f) but accepts bytes
    // with the high bit set. Guards the simplified control-byte check.
    Request r;
    Header[4] hdrs;

    // High-bit byte in the request-target is allowed.
    String ok = "GET /\x80\xff HTTP/1.0\r\n\r\n";
    @assert_ok(parse_request(ok, &r, hdrs[..], 0), ok.len);
    assert(seq(r.path, "/\x80\xff"));

    // DEL (0x7f) in the target is rejected.
    @assert_fault(parse_request("GET /\x7f HTTP/1.0\r\n\r\n", &r, hdrs[..], 0), MALFORMED);
    // A control byte (0x1f) in the target is rejected.
    @assert_fault(parse_request("GET /\x1f HTTP/1.0\r\n\r\n", &r, hdrs[..], 0), MALFORMED);
}

fn void test_request_slowloris() @test
{
    Request r;
    Header[4] hdrs;
    // last_len != 0 triggers the incremental completeness check.
    String p = "GET / HTTP/1.0\r\nHost: x\r\n";
    @assert_fault(parse_request(p, &r, hdrs[..], p.len), INCOMPLETE);
    // Complete; is_complete finds CRLFCRLF and the full parse proceeds.
    String c = "GET / HTTP/1.0\r\n\r\n";
    @assert_ok(parse_request(c, &r, hdrs[..], c.len - 1), c.len);
}

// ---- parse_response --------------------------------------------------------

fn void test_response_simple() @test
{
    String resp = "HTTP/1.1 200 OK\r\n\r\n";
    Response r;
    Header[8] hdrs;
    @assert_ok(parse_response(resp, &r, hdrs[..], 0), resp.len);
    assert(r.minor_version == 1);
    assert(r.status == 200);
    assert(seq(r.msg, "OK"));
    assert(r.headers.len == 0);
}

fn void test_response_headers_and_long_msg() @test
{
    String resp = "HTTP/1.0 500 Internal Server Error\r\nX-Y: z\r\n\r\n";
    Response r;
    Header[8] hdrs;
    @assert_ok(parse_response(resp, &r, hdrs[..], 0), resp.len);
    assert(r.status == 500);
    assert(seq(r.msg, "Internal Server Error"));
    assert(r.headers.len == 1);
    assert(seq(r.headers[0].name, "X-Y"));
    assert(seq(r.headers[0].value, "z"));
}

fn void test_response_empty_msg() @test
{
    String resp = "HTTP/1.1 200 \r\n\r\n";
    Response r;
    Header[4] hdrs;
    @assert_ok(parse_response(resp, &r, hdrs[..], 0), resp.len);
    assert(r.status == 200);
    assert(r.msg.len == 0);
}

fn void test_response_partial_and_invalid() @test
{
    Response r;
    Header[4] hdrs;
    @assert_fault(parse_response("HTTP/1.1 200 OK\r\n", &r, hdrs[..], 0), INCOMPLETE);
    @assert_fault(parse_response("HTTP/1.1 2", &r, hdrs[..], 0), INCOMPLETE);
    @assert_fault(parse_response("HTTP/1.1 2x0 OK\r\n\r\n", &r, hdrs[..], 0), MALFORMED);  // non-digit
    @assert_fault(parse_response("HTTP/1.1 200X\r\n\r\n", &r, hdrs[..], 0), MALFORMED);    // garbage
}

// ---- parse_headers ---------------------------------------------------------

fn void test_headers_only() @test
{
    String h = "Host: example.com\r\nAccept: */*\r\n\r\n";
    Header[8] hdrs;
    usz n;
    @assert_ok(parse_headers(h, hdrs[..], &n, 0), h.len);
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
    @assert_ok(decode_chunked(&dec, buf, &bufsz), 2);   // trailing CRLF left over
    assert(bufsz == 3);
    assert(seq(store[:3], "abc"));
}

fn void test_chunked_multiple_and_hex_size() @test
{
    // Two chunks; the second uses an upper-case hex size and a chunk extension.
    char[128] store;
    char[] buf = fill(&store, "3\r\nabc\r\nA;ext=1\r\n0123456789\r\n0\r\n\r\n");
    usz bufsz = buf.len;
    ChunkedDecoder dec;
    @assert_ok(decode_chunked(&dec, buf, &bufsz), 2);
    assert(bufsz == 13);
    assert(seq(store[:13], "abc0123456789"));
}

fn void test_chunked_partial_then_complete() @test
{
    ChunkedDecoder dec;

    char[64] s1;
    char[] b1 = fill(&s1, "3\r\nab");
    usz z1 = b1.len;
    @assert_fault(decode_chunked(&dec, b1, &z1), INCOMPLETE);
    assert(z1 == 2);
    assert(seq(s1[:2], "ab"));
    assert(decode_chunked_is_in_data(&dec));

    char[64] s2;
    char[] b2 = fill(&s2, "c\r\n0\r\n\r\n");
    usz z2 = b2.len;
    @assert_ok(decode_chunked(&dec, b2, &z2), 2);
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
    @assert_ok(decode_chunked(&dec, buf, &bufsz), 0);
    assert(bufsz == 0);
}

fn void test_chunked_bare_lf_size_line() @test
{
    // A lenient origin may terminate the chunk-size/ext line with a bare LF.
    // This must be accepted, matching at_eol/upstream picohttpparser.
    char[64] store;
    char[] buf = fill(&store, "3\nabc\r\n0\n\r\n");
    usz bufsz = buf.len;
    ChunkedDecoder dec;
    @assert_ok(decode_chunked(&dec, buf, &bufsz), 2);   // trailing CRLF left over
    assert(bufsz == 3);
    assert(seq(store[:3], "abc"));
}

fn void test_chunked_invalid() @test
{
    char[64] store;
    char[] buf = fill(&store, "z\r\n");   // 'z' is not a hex digit
    usz bufsz = buf.len;
    ChunkedDecoder dec;
    @assert_fault(decode_chunked(&dec, buf, &bufsz), MALFORMED);
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

fn void test_decode_hex_boundaries() @test
{
    // #16: decode_hex via is_xdigit/from_hex. Every hex digit maps to its value,
    // and bytes just outside each hex range return the -1 sentinel.
    for (int i = 0; i <= 9; i++) assert(decode_hex('0' + i) == i);
    for (int i = 0; i < 6; i++)
    {
        assert(decode_hex('a' + i) == 10 + i);
        assert(decode_hex('A' + i) == 10 + i);
    }
    // Just outside the digit / hex-letter ranges: still the -1 sentinel.
    assert(decode_hex('/') == -1);   // '0' - 1
    assert(decode_hex(':') == -1);   // '9' + 1
    assert(decode_hex('@') == -1);   // 'A' - 1
    assert(decode_hex('G') == -1);   // 'F' + 1
    assert(decode_hex('`') == -1);   // 'a' - 1
    assert(decode_hex('g') == -1);   // 'f' + 1
    assert(decode_hex(0x80) == -1);  // high-bit byte
}
