// HTTP method + request serialization over a Conn.

module tinyhttp;

// Each method carries its on-the-wire name (e.g. GET.name == "GET").
enum Method : char (String name)
{
    GET     { "GET" },
    HEAD    { "HEAD" },
    POST    { "POST" },
    PUT     { "PUT" },
    PATCH   { "PATCH" },
    DELETE  { "DELETE" },
    OPTIONS { "OPTIONS" },
}

// Write the whole buffer, looping over short writes.
fn void? write_all(Conn conn, char[] data) @private
{
    usz off = 0;
    while (off < data.len)
    {
        sz n = conn.write(data[off..])!;
        if (n <= 0) return WRITE_FAILED~;
        off += (usz)n;
    }
}

<* Serialize an HTTP/1.1 request and write it to `conn`. Adds Host and
   Connection: close, and Content-Length for a body unless the caller set one. *>
fn void? write_request(Allocator allocator, Conn conn, Method method, String host, String path, Header[] headers, char[] body) @private
{
    DString req = dstring::new(allocator);
    defer req.free();

    req.appendf("%s %s HTTP/1.1\r\n", method.name, path)!;
    req.appendf("Host: %s\r\n", host)!;
    req.append_string("Connection: close\r\n");

    bool has_content_length = false;
    foreach (h : headers)
    {
        req.appendf("%s: %s\r\n", (String)h.name, (String)h.value)!;
        if (ci_eq(h.name, "Content-Length")) has_content_length = true;
    }
    if (body.len != 0 && !has_content_length) req.appendf("Content-Length: %d\r\n", body.len)!;

    req.append_string("\r\n");
    if (body.len != 0) req.append_bytes(body);

    write_all(conn, req.str_view())!;
}
