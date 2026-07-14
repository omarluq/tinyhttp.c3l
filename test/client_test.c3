// Tests for the HTTP client core, driven by an in-process mock Conn (no network).
module tinyhttp;
import std::io;
import std::net::url;
import std::time;

// A Conn that serves canned response bytes and records what was written.
struct MockConn (Conn)
{
    char[] to_read;
    usz    read_pos;
    DString written;
    bool   synth;        // synthetic large-body mode (no real source buffer)
    usz    synth_left;   // remaining synthetic bytes to serve
}

fn sz? MockConn.read(&self, char[] buf) @dynamic
{
    if (self.synth)
    {
        if (self.synth_left == 0) return 0;                    // EOF
        usz n = self.synth_left < buf.len ? self.synth_left : buf.len;
        buf[:n] = 'x';                                         // filler byte
        self.synth_left -= n;
        return (sz)n;
    }
    usz avail = self.to_read.len - self.read_pos;
    if (avail == 0) return 0;                       // EOF
    usz n = avail < buf.len ? avail : buf.len;
    buf[:n] = self.to_read[self.read_pos:n];
    self.read_pos += n;
    return (sz)n;
}

fn sz? MockConn.write(&self, char[] buf) @dynamic
{
    self.written.append_bytes(buf);
    return (sz)buf.len;
}

fn void? MockConn.close(&self) @dynamic {}

// #12: MockConn must forward read_byte/write_byte to satisfy Conn : InStream, OutStream.
fn char? MockConn.read_byte(&self) @dynamic => io::read_byte_using_read(self);
fn void? MockConn.write_byte(&self, char c) @dynamic => io::write_byte_using_write(self, c);

fn MockConn mock(String response) @local
{
    MockConn m;
    m.to_read = (char[])response;
    m.written = dstring::new(mem);
    return m;
}

// Serve `total` synthetic bytes without allocating a real source buffer.
fn MockConn mock_synth(usz total) @local
{
    MockConn m;
    m.synth = true;
    m.synth_left = total;
    m.written = dstring::new(mem);
    return m;
}

// ---- tests -----------------------------------------------------------------

fn void test_send_content_length() @test
{
    MockConn m = mock("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Test: yes\r\n\r\nhello");
    defer m.written.free();

    Response resp = send(mem, &m, GET, "example.com", "/")!!;
    defer resp.free();

    assert(resp.status == 200);
    assert(resp.ok());
    assert(resp.minor_version == 1);
    assert(resp.body == "hello");
    assert(resp.header("X-Test") == "yes");
    assert(resp.header("x-test") == "yes");         // case-insensitive
    assert(resp.header("Nope").len == 0);

    String req = m.written.str_view();
    assert(req.contains("GET / HTTP/1.1\r\n"));
    assert(req.contains("Host: example.com\r\n"));
    assert(req.contains("Connection: close\r\n"));
}

fn void test_send_chunked() @test
{
    MockConn m = mock("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n5\r\nhello\r\n0\r\n\r\n");
    defer m.written.free();

    Response resp = send(mem, &m, GET, "x", "/")!!;
    defer resp.free();

    assert(resp.status == 200);
    assert(resp.body == "abchello");
}

fn void test_send_read_to_eof() @test
{
    // No Content-Length and not chunked: body is everything until EOF.
    MockConn m = mock("HTTP/1.0 200 OK\r\n\r\nplain body bytes");
    defer m.written.free();

    Response resp = send(mem, &m, GET, "x", "/")!!;
    defer resp.free();

    assert(resp.minor_version == 0);
    assert(resp.body == "plain body bytes");
}

fn void test_send_post_body() @test
{
    MockConn m = mock("HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok");
    defer m.written.free();

    Header[1] hdrs = { { .name = "Content-Type", .value = "application/json" } };
    Response resp = send(mem, &m, POST, "api.x", "/items", hdrs[..], "{}")!!;
    defer resp.free();

    assert(resp.status == 201);
    assert(resp.body == "ok");

    String req = m.written.str_view();
    assert(req.contains("POST /items HTTP/1.1\r\n"));
    assert(req.contains("Content-Type: application/json\r\n"));
    assert(req.contains("Content-Length: 2\r\n"));   // auto-added for the body
    assert(req.contains("\r\n\r\n{}"));               // blank line then body
}

fn void test_send_malformed() @test
{
    MockConn m = mock("not http at all");
    defer m.written.free();

    if (try resp = send(mem, &m, GET, "x", "/"))
    {
        resp.free();
        assert(false, "expected MALFORMED_RESPONSE");
    }
}

fn void test_default_user_agent() @test
{
    MockConn m = mock("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    defer m.written.free();
    Response resp = send(mem, &m, GET, "x", "/")!!;
    defer resp.free();
    assert(m.written.str_view().contains("User-Agent: tinyhttp/0.1\r\n"));
}

fn void test_user_agent_override() @test
{
    MockConn m = mock("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    defer m.written.free();
    Header[1] hdrs = { { .name = "User-Agent", .value = "custom/9" } };
    Response resp = send(mem, &m, GET, "x", "/", hdrs[..])!!;
    defer resp.free();
    String req = m.written.str_view();
    assert(req.contains("User-Agent: custom/9\r\n"));
    assert(!req.contains("tinyhttp/0.1"));    // ours not added when overridden
}

fn void test_builder() @test
{
    RequestBuilder b = request(POST, "http://x/y");
    b.header("A", "1").header("B", "2").body("data").timeout(3 * time::SEC);
    assert(b.method == POST);
    assert(b.url == "http://x/y");
    assert(b._count == 2);
    assert(b._headers[0].name == "A");
    assert(b._headers[1].value == "2");
    assert(b._body == "data");
    assert(b._timeout == 3 * time::SEC);
}

// ---- regression tests ------------------------------------------------------

// #1: the request-target re-encodes the path (percent-escapes survive) and a
// decoded CRLF cannot smuggle a literal newline into the request line.
fn void test_request_target_reencodes_path() @test
{
    Url u; String host_hdr; String target;
    make_request_target("http://h/a%20b", &u, &host_hdr, &target)!!;
    assert(target == "/a%20b");

    make_request_target("http://h/a%0D%0AEvil:%20x", &u, &host_hdr, &target)!!;
    assert(!target.contains("\r") && !target.contains("\n"));
}

// #2: the Host header carries a non-default port but omits the default :80.
fn void test_host_header_includes_port() @test
{
    Url u; String host_hdr; String target;
    make_request_target("http://example.com:8080/", &u, &host_hdr, &target)!!;
    assert(host_hdr == "example.com:8080");

    make_request_target("http://example.com/", &u, &host_hdr, &target)!!;
    assert(host_hdr == "example.com");
}

// #3: a caller-supplied Host suppresses the auto Host (exactly one Host line).
fn void test_duplicate_host_rejected() @test
{
    MockConn m = mock("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    defer m.written.free();

    Header[1] h = { { .name = "Host", .value = "override.com" } };
    Response resp = send(mem, &m, GET, "real.com", "/", h[..])!!;
    defer resp.free();

    String req = m.written.str_view();
    assert(req.contains("Host: override.com\r\n"));
    assert(!req.contains("Host: real.com"));
}

// #5: a caller header value containing CR/LF faults INVALID_HEADER.
fn void test_crlf_header_rejected() @test
{
    MockConn m = mock("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    defer m.written.free();

    Header[1] h = { { .name = "X", .value = "a\r\nEvil: 1" } };
    if (try resp = send(mem, &m, GET, "x", "/", h[..]))
    {
        resp.free();
        assert(false, "expected INVALID_HEADER");
    }
}

// #6: a response larger than MAX_RESPONSE_BYTES faults RESPONSE_TOO_LARGE.
fn void test_response_size_cap() @test
{
    MockConn m = mock_synth(MAX_RESPONSE_BYTES + 4096);
    defer m.written.free();

    if (try resp = send(mem, &m, GET, "x", "/"))
    {
        resp.free();
        assert(false, "expected RESPONSE_TOO_LARGE");
    }
}

// #7: a Transfer-Encoding list (last token "chunked") still de-chunks the body.
fn void test_transfer_encoding_list_chunked() @test
{
    MockConn m = mock("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n");
    defer m.written.free();

    Response resp = send(mem, &m, GET, "x", "/")!!;
    defer resp.free();

    assert(resp.body == "abc");
}

// #9 (builder side): more than MAX_HEADERS headers faults TOO_MANY_HEADERS.
fn void test_builder_header_overflow() @test
{
    RequestBuilder b = request(GET, "http://x/y");
    for (usz i = 0; i < MAX_HEADERS + 1; i++) b.header("K", "v");
    if (try resp = b.send(mem))
    {
        resp.free();
        assert(false, "expected TOO_MANY_HEADERS");
    }
}

// #9 (client side): default_headers + per-call headers over MAX_HEADERS faults
// TOO_MANY_HEADERS via append_headers.
fn void test_client_header_overflow() @test
{
    Header[20] defaults;
    for (usz i = 0; i < 20; i++) defaults[i] = { .name = "D", .value = "v" };
    Header[20] extra;
    for (usz i = 0; i < 20; i++) extra[i] = { .name = "E", .value = "v" };

    Client c = client(mem, "http://x", defaults[..]);
    if (try resp = c.request(GET, "/", extra[..]))
    {
        resp.free();
        assert(false, "expected TOO_MANY_HEADERS");
    }
}

// #4: per-call headers override same-named defaults (case-insensitive) at the
// merge-helper level, with no network. A default with a per-call override is
// dropped; non-overridden defaults and all overrides survive exactly once.
fn void test_header_override_merge() @test
{
    Header[3] defaults = {
        { .name = "User-Agent", .value = "default/1" },
        { .name = "Accept",     .value = "*/*" },
        { .name = "X-Keep",     .value = "yes" },
    };
    Header[2] overrides = {
        { .name = "user-agent", .value = "custom/9" },   // overrides default (case-insensitive)
        { .name = "X-New",      .value = "1" },
    };
    Header[MAX_HEADERS] merged;
    usz m = merge_headers(merged[..], defaults[..], overrides[..])!!;
    Header[] result = merged[:m];
    assert(m == 4);                                   // Accept + X-Keep + user-agent + X-New
    assert(find_header(result, "User-Agent") == "custom/9");   // override wins, default dropped
    assert(find_header(result, "Accept") == "*/*");
    assert(find_header(result, "X-Keep") == "yes");
    assert(find_header(result, "X-New") == "1");
    usz ua = 0;
    foreach (h : result) if (ci_eq(h.name, "User-Agent")) ua++;
    assert(ua == 1);                                  // exactly one User-Agent on the wire
}

// #14: has_header distinguishes present-but-empty from absent, which the
// empty-string sentinel of header() cannot. No network, no allocation to free
// (headers slice a stack array).
fn void test_response_has_header() @test
{
    Header[2] hs = {
        { .name = "X-Empty", .value = "" },
        { .name = "X-Val",   .value = "v" },
    };
    Response r = { .headers = hs[..] };
    assert(r.has_header("X-Empty"));           // present but empty -> true
    assert(r.has_header("x-val"));             // case-insensitive
    assert(!r.has_header("X-Absent"));         // absent -> false
    assert(r.header("X-Empty").len == 0);      // header() cannot distinguish absent from empty
    assert(r.header("X-Absent").len == 0);
}

// Count non-overlapping occurrences of `needle` in `hay`.
fn usz count_occurrences(String hay, String needle) @local
{
    if (needle.len == 0 || hay.len < needle.len) return 0;
    usz n = 0;
    for (usz i = 0; i + needle.len <= hay.len; i++)
    {
        if (hay[i:needle.len] == needle) n++;
    }
    return n;
}

// R1: a caller Connection: keep-alive is dropped; only the always-emitted
// Connection: close reaches the wire.
fn void test_caller_keep_alive_suppressed() @test
{
    MockConn m = mock("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    defer m.written.free();

    Header[1] h = { { .name = "Connection", .value = "keep-alive" } };
    Response resp = send(mem, &m, GET, "x", "/", h[..])!!;
    defer resp.free();

    String req = m.written.str_view();
    assert(req.contains("Connection: close\r\n"));
    assert(!req.contains("keep-alive"));
}

// R2: HEAD carries no body even when headers advertise Content-Length; the
// bodiless short-circuit succeeds instead of faulting INCOMPLETE_RESPONSE.
fn void test_head_bodiless() @test
{
    MockConn m = mock("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n");
    defer m.written.free();

    Response resp = send(mem, &m, HEAD, "x", "/")!!;
    defer resp.free();

    assert(resp.status == 200);
    assert(resp.body.len == 0);
}

// R2: a 204 No Content response is bodiless.
fn void test_status_204_bodiless() @test
{
    MockConn m = mock("HTTP/1.1 204 No Content\r\n\r\n");
    defer m.written.free();

    Response resp = send(mem, &m, GET, "x", "/")!!;
    defer resp.free();

    assert(resp.status == 204);
    assert(resp.body.len == 0);
}

// R2: a 304 Not Modified response is bodiless.
fn void test_status_304_bodiless() @test
{
    MockConn m = mock("HTTP/1.1 304 Not Modified\r\n\r\n");
    defer m.written.free();

    Response resp = send(mem, &m, GET, "x", "/")!!;
    defer resp.free();

    assert(resp.status == 304);
    assert(resp.body.len == 0);
}

// R2: a Content-Length larger than the bytes actually received faults
// INCOMPLETE_RESPONSE.
fn void test_short_content_length_faults() @test
{
    MockConn m = mock("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort");
    defer m.written.free();

    if (try resp = send(mem, &m, GET, "x", "/"))
    {
        resp.free();
        assert(false, "expected INCOMPLETE_RESPONSE");
    }
}

// R4: a present-but-empty caller Host suppresses the auto Host, so exactly one
// Host line reaches the wire and the send host arg is not added on top.
fn void test_empty_host_not_duplicated() @test
{
    MockConn m = mock("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    defer m.written.free();

    Header[1] h = { { .name = "Host", .value = "" } };
    Response resp = send(mem, &m, GET, "x", "/", h[..])!!;
    defer resp.free();

    String req = m.written.str_view();
    assert(count_occurrences(req, "Host:") == 1);
    assert(!req.contains("Host: x"));
}

// R5: two separate Transfer-Encoding lines are one comma list; the final
// transfer-coding across all of them is chunked, so the body de-chunks.
fn void test_multi_line_transfer_encoding_chunked() @test
{
    MockConn m = mock("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n");
    defer m.written.free();

    Response resp = send(mem, &m, GET, "x", "/")!!;
    defer resp.free();

    assert(resp.body == "abc");
}
