// HTTP method, request serialization, and the fluent request builder.

module tinyhttp;
import std::time;
import std::io;

const String USER_AGENT @private = "tinyhttp/0.1";
const usz    MAX_HEADERS @private = 32;   // capacity of the builder / merged-header arrays

<* Each method carries its on-the-wire name (e.g. GET.name == "GET"). *>
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

<* Serialize an HTTP/1.1 request and write it to `conn`. Host, a default
   User-Agent, and Content-Length for a body are each added only if the caller
   did not already supply them; Connection: close is always sent (the read path
   reads to EOF and needs it). Caller header names/values containing CR or LF
   fault with INVALID_HEADER. *>
fn void? write_request(Allocator allocator, Conn conn, Method method, String host, String path, Header[] headers, char[] body) @private
{
    DString req = dstring::new_with_capacity(allocator, 256);
    defer req.free();

    req.appendf("%s %s HTTP/1.1\r\n", method.name, path)!;
    if (find_header(headers, "Host").len == 0) req.appendf("Host: %s\r\n", host)!;
    req.append_string("Connection: close\r\n");
    if (find_header(headers, "User-Agent").len == 0) req.appendf("User-Agent: %s\r\n", USER_AGENT)!;

    bool has_content_length = false;
    foreach (h : headers)
    {
        String hname = (String)h.name;
        String hvalue = (String)h.value;
        if (hname.contains("\r") || hname.contains("\n") || hvalue.contains("\r") || hvalue.contains("\n")) return INVALID_HEADER~;
        req.appendf("%s: %s\r\n", hname, hvalue)!;
        if (ci_eq(h.name, "Content-Length")) has_content_length = true;
    }
    if (body.len != 0 && !has_content_length) req.appendf("Content-Length: %d\r\n", body.len)!;

    req.append_string("\r\n");

    io::write_all(conn, req.str_view())!;
    if (body.len != 0) io::write_all(conn, body)!;
}

// ---- fluent builder --------------------------------------------------------

<* A fluent request builder. Chain `header` / `body` / `timeout`, then `send`.
   Holds up to MAX_HEADERS headers inline; supplying more marks the builder
   overflowed and `send` faults with TOO_MANY_HEADERS. *>
struct RequestBuilder
{
    Method   method;
    String   url;
    char[]   _body;
    Duration _timeout;
    Header[MAX_HEADERS] _headers;
    usz      _count;
    bool     _overflow;
}

<* Begin a `method` request to `url` (must be http://). *>
fn RequestBuilder request(Method method, String url) => { .method = method, .url = url };

<* Append a header. Returns the builder for chaining. Beyond MAX_HEADERS the
   builder is marked overflowed and `send` will fault. *>
fn RequestBuilder* RequestBuilder.header(&self, String name, String value)
{
    if (self._count < MAX_HEADERS)
    {
        self._headers[self._count] = { .name = (char[])name, .value = (char[])value };
        self._count++;
    }
    else
    {
        self._overflow = true;
    }
    return self;
}

<* Set the request body. Returns the builder for chaining. *>
fn RequestBuilder* RequestBuilder.body(&self, char[] body)
{
    self._body = body;
    return self;
}

<* Set the connection timeout (0 = none). Returns the builder for chaining. *>
fn RequestBuilder* RequestBuilder.timeout(&self, Duration timeout)
{
    self._timeout = timeout;
    return self;
}

<* Open a connection, send the request, and read the response. Faults with
   TOO_MANY_HEADERS if more than MAX_HEADERS headers were supplied. *>
fn Response? RequestBuilder.send(self, Allocator allocator = tmem)
{
    if (self._overflow) return TOO_MANY_HEADERS~;
    return request_url(self.method, self.url, self._headers[:self._count], self._body, self._timeout, allocator);
}
