// Tests for the HTTP client core, driven by an in-process mock Conn (no network).
module tinyhttp;
import std::time;

// A Conn that serves canned response bytes and records what was written.
struct MockConn (Conn)
{
    char[] to_read;
    usz    read_pos;
    DString written;
}

fn sz? MockConn.read(&self, char[] buf) @dynamic
{
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

fn MockConn mock(String response) @local
{
    MockConn m;
    m.to_read = (char[])response;
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
    RequestBuilder b = request(POST, "http://x/y")
        .header("A", "1")
        .header("B", "2")
        .body("data")
        .timeout(3 * time::SEC);
    assert(b.method == POST);
    assert(b.url == "http://x/y");
    assert(b._count == 2);
    assert(b._headers[0].name == "A");
    assert(b._headers[1].value == "2");
    assert(b._body == "data");
    assert(b._timeout == 3 * time::SEC);
}
