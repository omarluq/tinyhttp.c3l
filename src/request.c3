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

<* True for methods safe to auto-retry after a mid-flight write failure. POST and
   PATCH are excluded: a partial write may have reached a server that already began
   processing, so a transparent resend could execute them twice. *>
fn bool Method.is_idempotent(self) => self != POST && self != PATCH;

fn bool has_crlf(String s) @private => s.contains_char('\r') || s.contains_char('\n');

<* Serialize an HTTP/1.1 request and write it to `conn`. Host, a default
   User-Agent, and Content-Length for a body are each added only if the caller
   did not already supply them. Connection: close is sent when `close` is true
   (the default, used by the one-shot send() path) OR when the caller supplied a
   Connection header carrying the close token; the pooled/Client path passes
   close:false so the HTTP/1.1 connection stays persistent unless the caller asks
   to close. Caller header names/values containing CR or LF fault with
   INVALID_HEADER. *>
fn void? write_request(Conn conn, Method method, String host, String path, Header[] headers, char[] body, bool close = true) @private
{
    DString req = dstring::temp_with_capacity(256);
    defer req.free();

    req.append_string(method.name);
    req.append_char(' ');
    req.append_string(path);
    req.append_string(" HTTP/1.1\r\n");
    if (!has_header(headers, "Host"))
    {
        req.append_string("Host: ");
        req.append_string(host);
        req.append_string("\r\n");
    }
    if (close || has_connection_close(headers)) req.append_string("Connection: close\r\n");
    if (!has_header(headers, "User-Agent"))
    {
        req.append_string("User-Agent: ");
        req.append_string(USER_AGENT);
        req.append_string("\r\n");
    }

    bool has_content_length = false;
    foreach (&h : headers)
    {
        String hname = (String)h.name;
        String hvalue = (String)h.value;
        if (has_crlf(hname) || has_crlf(hvalue)) return INVALID_HEADER~;
        if (ci_eq(h.name, "Connection")) continue;
        req.append_string(hname);
        req.append_string(": ");
        req.append_string(hvalue);
        req.append_string("\r\n");
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
    Method    method;
    String    url;
    char[]    _body;
    Duration  _timeout;
    TlsConfig _tls;
    Header[MAX_HEADERS] _headers;
    usz       _count;
    bool      _overflow;
}

<* Begin a `method` request to `url` (must be http:// or https://). Returns an
   UNSENT RequestBuilder: chain `.header()` / `.body()` / `.timeout()` / `.tls()`,
   then call `.send()` to execute — unlike `Client.request` / `request_url`, no
   I/O happens here. *>
fn RequestBuilder new_request(Method method, String url) => { .method = method, .url = url };

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

<* Set the TLS configuration used for an https:// URL (ignored for http://).
   Returns the builder for chaining. *>
fn RequestBuilder* RequestBuilder.tls(&self, TlsConfig tls)
{
    self._tls = tls;
    return self;
}

<* Open a connection, send the request, and read the response. Faults with
   TOO_MANY_HEADERS if more than MAX_HEADERS headers were supplied. *>
fn Response? RequestBuilder.send(&self, Allocator allocator = tmem)
{
    if (self._overflow) return TOO_MANY_HEADERS~;
    return request_url(self.method, self.url, self._headers[:self._count], self._body, self._timeout, allocator, tls: self._tls);
}
