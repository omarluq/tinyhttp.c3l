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

fn void test_send_100_continue() @test
{
    // A 1xx interim response must be discarded; the real >=200 response is returned.
    MockConn m = mock("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Real: yes\r\n\r\nhello");
    defer m.written.free();

    Response resp = send(mem, &m, GET, "x", "/")!!;
    defer resp.free();

    assert(resp.status == 200);
    assert(resp.body == "hello");
    assert(resp.header("X-Real") == "yes");
}

fn void test_send_103_early_hints() @test
{
    // 103 Early Hints (carries headers, no body) is interim: skip it, keep the final response.
    MockConn m = mock("HTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    defer m.written.free();

    Response resp = send(mem, &m, GET, "x", "/")!!;
    defer resp.free();

    assert(resp.status == 200);
    assert(resp.body == "ok");
    assert(resp.header("Link").len == 0);            // interim headers are not surfaced
}

fn void test_send_multiple_interim() @test
{
    // Several stacked 1xx blocks ahead of the real response are all discarded.
    MockConn m = mock("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 201 Created\r\nContent-Length: 4\r\n\r\ndone");
    defer m.written.free();

    Response resp = send(mem, &m, POST, "x", "/", body: "{}")!!;
    defer resp.free();

    assert(resp.status == 201);
    assert(resp.body == "done");
}

fn void test_send_101_not_skipped() @test
{
    // 101 Switching Protocols is a real (bodiless) response, NOT an interim to discard.
    MockConn m = mock("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n");
    defer m.written.free();

    Response resp = send(mem, &m, GET, "x", "/")!!;
    defer resp.free();

    assert(resp.status == 101);
    assert(resp.body.len == 0);
    assert(resp.header("Upgrade") == "websocket");
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
    RequestTarget rt = make_request_target("http://h/a%20b")!!;
    assert(rt.target == "/a%20b");

    rt = make_request_target("http://h/a%0D%0AEvil:%20x")!!;
    assert(!rt.target.contains("\r") && !rt.target.contains("\n"));
}

// #2: the Host header carries a non-default port but omits the default :80.
fn void test_host_header_includes_port() @test
{
    RequestTarget rt = make_request_target("http://example.com:8080/")!!;
    assert(rt.host_hdr == "example.com:8080");

    rt = make_request_target("http://example.com/")!!;
    assert(rt.host_hdr == "example.com");
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

// Rank 1: a DECLARED Content-Length over the cap is rejected from the header
// alone, before it sizes the buffer, so an over-declaration cannot force a giant
// allocation. The mock sends a 1-byte body but claims ~1 GB.
fn void test_content_length_declared_cap() @test
{
    MockConn m = mock("HTTP/1.1 200 OK\r\nContent-Length: 999999999\r\n\r\nx");
    defer m.written.free();

    Response? r = send(mem, &m, GET, "x", "/");
    if (catch err = r)
    {
        assert(err == RESPONSE_TOO_LARGE);
        return;
    }
    r.free();
    assert(false, "over-cap Content-Length should be rejected");
}

// Issue #2: two Content-Length fields with DIFFERING values are unrecoverable
// (RFC 7230 §3.3.3 rule 4). Framing on the first value alone would read 10 bytes
// and buffer the rest as leftover — a response-smuggling primitive — so this
// must fault MALFORMED_RESPONSE rather than succeed.
fn void test_conflicting_content_length_rejected() @test
{
    MockConn m = mock("HTTP/1.1 200 OK\r\nContent-Length: 10\r\nContent-Length: 9999\r\n\r\n0123456789the rest is smuggled");
    defer m.written.free();

    Response? r = send(mem, &m, GET, "x", "/");
    if (catch err = r)
    {
        assert(err == MALFORMED_RESPONSE);
        return;
    }
    r.free();
    assert(false, "conflicting Content-Length values should fault MALFORMED_RESPONSE");
}

// Issue #2: identical duplicate Content-Length fields agree, so framing proceeds
// on the shared value (RFC allows identical duplicates).
fn void test_duplicate_identical_content_length_ok() @test
{
    MockConn m = mock("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello");
    defer m.written.free();

    Response resp = send(mem, &m, GET, "x", "/")!!;
    defer resp.free();

    assert(resp.status == 200);
    assert(resp.body == "hello");
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

// ---- Increment 4: keep-alive / connection reuse ----------------------------

// A Conn that serves a SEQUENCE of canned responses over one connection, one per
// request/response cycle, to exercise keep-alive reuse. A write that follows a read
// advances to the next canned response, mimicking a server answering the next
// request on a persistent connection. The precise reader must stop exactly at each
// response boundary (never reading to EOF) for the following response to line up.
struct SeqConn (Conn)
{
    String[] responses;
    usz      idx;        // response currently being served
    usz      read_pos;   // read offset within responses[idx]
    bool     any_read;   // have we served bytes from the current response yet?
    DString  written;
}

fn sz? SeqConn.read(&self, char[] buf) @dynamic
{
    if (self.idx >= self.responses.len) return 0;          // no more responses: EOF
    char[] cur = (char[])self.responses[self.idx];
    usz avail = cur.len - self.read_pos;
    if (avail == 0) return 0;                              // current response drained
    usz n = avail < buf.len ? avail : buf.len;
    buf[:n] = cur[self.read_pos:n];
    self.read_pos += n;
    self.any_read = true;
    return (sz)n;
}

fn sz? SeqConn.write(&self, char[] buf) @dynamic
{
    // A write after the current response has been read starts the next
    // request/response cycle: advance to the next canned response.
    if (self.any_read)
    {
        self.idx++;
        self.read_pos = 0;
        self.any_read = false;
    }
    self.written.append_bytes(buf);
    return (sz)buf.len;
}

fn void? SeqConn.close(&self) @dynamic {}
fn char? SeqConn.read_byte(&self) @dynamic => io::read_byte_using_read(self);
fn void? SeqConn.write_byte(&self, char c) @dynamic => io::write_byte_using_write(self, c);

// K1: pool_key composes "scheme|host|port"; http and https never share a bucket.
fn void test_pool_key() @test
{
    assert(pool_key("http", "example.com", 80) == "http|example.com|80");
    assert(pool_key("https", "example.com", 443) == "https|example.com|443");
    assert(pool_key("http", "x", 8080) == "http|x|8080");
    assert(pool_key("http", "x", 80) != pool_key("https", "x", 80));
}

// K2: conn_has_token is a case-insensitive, comma-delimited token scan (not a
// substring match), and empty values never match.
fn void test_conn_has_token() @test
{
    assert(conn_has_token("close", "close"));
    assert(conn_has_token("keep-alive, close", "close"));
    assert(conn_has_token("keep-alive, close", "keep-alive"));
    assert(conn_has_token("CLOSE", "close"));                 // case-insensitive value
    assert(conn_has_token("Keep-Alive", "keep-alive"));
    assert(!conn_has_token("keep-alive", "close"));
    assert(!conn_has_token("closer", "close"));               // token boundary, not substring
    assert(!conn_has_token("", "close"));                     // empty value never matches
}

// K3: has_connection_close scans every Connection header (case-insensitive name)
// via the token scanner, distinguishing keep-alive from close.
fn void test_has_connection_close() @test
{
    Header[2] with_close = {
        { .name = "Connection", .value = "close" },
        { .name = "X",          .value = "y" },
    };
    assert(has_connection_close(with_close[..]));

    Header[1] keep = { { .name = "Connection", .value = "keep-alive" } };
    assert(!has_connection_close(keep[..]));

    Header[1] none = { { .name = "X", .value = "y" } };
    assert(!has_connection_close(none[..]));

    Header[1] list = { { .name = "connection", .value = "keep-alive, close" } };
    assert(has_connection_close(list[..]));                   // ci name + token scan
}

// K4: checkout on an uninitialized pool misses with POOL_EMPTY (never a crash),
// and free on an uninitialized pool is a no-op.
fn void test_pool_checkout_empty() @test
{
    ConnPool pool = { .allocator = mem };
    if (catch e = pool.checkout("http|x|80"))
    {
        assert(e == POOL_EMPTY);
    }
    else
    {
        assert(false, "expected POOL_EMPTY from an uninitialized pool");
    }
    pool.free();                                              // never inited -> no-op, no leak
}

// K5: checkin then checkout returns the same idle conn (LIFO); a second checkout
// on the drained bucket misses. free reclaims the returned conn and the owned key.
fn void test_pool_checkin_checkout_lifo() @test
{
    ConnPool pool = { .allocator = mem };
    MockConn* m = alloc::new(mem, MockConn);
    IdleConn ic = { .conn = (Conn)m, .mem = m };

    pool.checkin("http|x|80", ic);
    IdleConn got = pool.checkout("http|x|80")!!;
    assert(got.mem == (void*)m);                             // same concrete conn back

    if (catch e = pool.checkout("http|x|80"))
    {
        assert(e == POOL_EMPTY);                             // bucket now empty
    }
    else
    {
        assert(false, "expected POOL_EMPTY after the only idle conn was taken");
    }

    pool.checkin("http|x|80", got);                          // return it so free reclaims it
    pool.free();
}

// K6: a Content-Length response over HTTP/1.1 with no Connection: close and no
// trailing bytes is framed precisely and marked reusable.
fn void test_read_response_reusable_content_length() @test
{
    MockConn m = mock("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
    defer m.written.free();

    bool reusable;
    Response resp = read_response(mem, &m, GET, false, &reusable)!!;
    defer resp.free();

    assert(resp.body == "hello");
    assert(reusable);
}

// K7: a chunked response over HTTP/1.1 is framed precisely and marked reusable.
fn void test_read_response_reusable_chunked() @test
{
    MockConn m = mock("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n");
    defer m.written.free();

    bool reusable;
    Response resp = read_response(mem, &m, GET, false, &reusable)!!;
    defer resp.free();

    assert(resp.body == "abc");
    assert(reusable);
}

// K8: a response advertising Connection: close is not reusable even though its
// body is precisely delimited.
fn void test_read_response_not_reusable_connection_close() @test
{
    MockConn m = mock("HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc");
    defer m.written.free();

    bool reusable;
    Response resp = read_response(mem, &m, GET, false, &reusable)!!;
    defer resp.free();

    assert(resp.body == "abc");
    assert(!reusable);                                       // server asked to close
}

// K9: a close-delimited HTTP/1.0 body (read to EOF) is never reusable.
fn void test_read_response_not_reusable_read_to_eof() @test
{
    MockConn m = mock("HTTP/1.0 200 OK\r\n\r\nplain body");
    defer m.written.free();

    bool reusable;
    Response resp = read_response(mem, &m, GET, false, &reusable)!!;
    defer resp.free();

    assert(resp.body == "plain body");
    assert(!reusable);                                       // boundary is the close itself
}

// K10: pipelined trailing bytes (a second response already in the buffer) are
// dropped, and their presence makes the connection non-reusable (leftover > 0).
fn void test_read_response_leftover_not_reusable() @test
{
    MockConn m = mock("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloHTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nworld");
    defer m.written.free();

    bool reusable;
    Response resp = read_response(mem, &m, GET, false, &reusable)!!;
    defer resp.free();

    assert(resp.body == "hello");                            // only the first body; trailer dropped
    assert(!reusable);                                       // unframed trailing bytes remain
}

// K11: two responses served over ONE connection prove reuse. do_exchange on a
// fresh conn then on the same conn (reused:true) reads each body precisely without
// hitting EOF, and both connections are marked reusable.
fn void test_keep_alive_two_responses_one_conn() @test
{
    String[2] resps = {
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nworld",
    };
    SeqConn m;
    m.responses = resps[..];
    m.written = dstring::new(mem);
    defer m.written.free();

    bool ru1;
    Response r1 = do_exchange(mem, &m, GET, "x", "/", {}, {}, false, &ru1)!!;
    defer r1.free();
    assert(r1.body == "hello");
    assert(ru1);

    bool ru2;
    Response r2 = do_exchange(mem, &m, GET, "x", "/", {}, {}, true, &ru2)!!;
    defer r2.free();
    assert(r2.body == "world");
    assert(ru2);

    String req = m.written.str_view();
    assert(count_occurrences(req, "GET / HTTP/1.1\r\n") == 2);   // both cycles on one conn
    assert(!req.contains("Connection: close"));                 // persistent path
}

// K12: Client.request reuses a pooled connection. Seeding the pool with a mock
// under the key request() computes lets both requests ride the same conn (no real
// dial); the recorded writes prove two request/response cycles over one socket.
fn void test_client_pool_reuse() @test
{
    String[2] resps = {
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nworld",
    };
    SeqConn* m = alloc::new(mem, SeqConn);
    m.responses = resps[..];
    m.written = dstring::new(mem);

    Client c = client(mem, "http://x");
    c.pool.checkin(pool_key("http", "x", 80), { .conn = (Conn)m, .mem = m });

    Response r1 = c.request(GET, "/")!!;
    defer r1.free();
    assert(r1.body == "hello");

    Response r2 = c.request(GET, "/")!!;
    defer r2.free();
    assert(r2.body == "world");

    assert(count_occurrences(m.written.str_view(), "GET / HTTP/1.1\r\n") == 2);

    m.written.free();     // free the DString before close frees the conn struct (m.mem)
    c.close();            // drains the pool: closes + frees the pooled conn and its key
}

// K13: a reused idle conn found dead (first read is EOF) surfaces STALE_CONNECTION
// so the caller can retry; the fault carries the internal retry signal.
fn void test_stale_connection_detected() @test
{
    MockConn m = mock("");                                   // closed idle socket
    defer m.written.free();

    bool reusable;
    Response? r = do_exchange(mem, &m, GET, "x", "/", {}, {}, true, &reusable);
    if (try resp = r)
    {
        resp.free();
        assert(false, "expected STALE_CONNECTION on a dead reused conn");
    }
    if (catch e = r) assert(e == STALE_CONNECTION);
}

// K14: the stale-retry path in miniature: a reused idle conn is found dead
// (STALE_CONNECTION), then the same request on a FRESH conn (reused:false) succeeds
// and can never observe STALE.
fn void test_stale_then_fresh_retry() @test
{
    MockConn dead = mock("");
    defer dead.written.free();

    bool ru1;
    Response? stale = do_exchange(mem, &dead, GET, "x", "/", {}, {}, true, &ru1);
    if (try resp = stale)
    {
        resp.free();
        assert(false, "expected STALE_CONNECTION from the dead idle conn");
    }
    if (catch e = stale) assert(e == STALE_CONNECTION);

    MockConn fresh = mock("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi");
    defer fresh.written.free();

    bool ru2;
    Response resp = do_exchange(mem, &fresh, GET, "x", "/", {}, {}, false, &ru2)!!;
    defer resp.free();
    assert(resp.body == "hi");
    assert(ru2);
    assert(fresh.written.str_view().contains("GET / HTTP/1.1\r\n"));
    assert(!fresh.written.str_view().contains("Connection: close"));   // persistent path
}
