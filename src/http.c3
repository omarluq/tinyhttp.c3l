// tinyhttp HTTP/1.1 client core: send a request over a Conn and read the
// response back through the parser. Increment 1 is blocking and uses
// "Connection: close" (read the whole response, then parse).

module tinyhttp;
import httpparser;
import std::io;
import std::net::url;
import std::time;

faultdef
    UNSUPPORTED_SCHEME,   // only http:// so far
    CONNECT_FAILED,       // could not reach the peer
    TIMEOUT,              // connect timed out
    DNS_FAILED,           // host name / address resolution failed
    INVALID_HEADER,       // caller header name/value contains CR or LF
    TOO_MANY_HEADERS,     // more headers supplied than MAX_HEADERS
    RESPONSE_TOO_LARGE,   // response exceeded MAX_RESPONSE_BYTES
    MALFORMED_RESPONSE;   // response could not be parsed

const usz MAX_RESPONSE_HEADERS @private = 100;
const usz MAX_RESPONSE_BYTES @private = 32 * 1024 * 1024;

<* Send a request over an already-open connection and read the response. The
   low-level entry point: convenience wrappers and `Client` build on it, and
   tests drive it with a mock `Conn`. *>
fn Response? send(Allocator allocator, Conn conn, Method method, String host, String path, Header[] headers = {}, char[] body = {})
{
    write_request(allocator, conn, method, host, path, headers, body)!;
    return read_response(allocator, conn);
}

fn Response? read_response(Allocator allocator, Conn conn) @private
{
    // Read the whole response (Connection: close) into one buffer.
    ByteWriter w;
    w.init(allocator);
    defer catch (void)w.destroy();   // frees the buffer on any fault exit; on success Response owns it
    char[4096] chunk;
    while (true)
    {
        sz n = conn.read(chunk[..])!;
        if (n <= 0) break;
        w.write(chunk[:(usz)n])!;
        if ((usz)w.index > MAX_RESPONSE_BYTES) return RESPONSE_TOO_LARGE~;
    }
    char[] raw = w.array_view();   // .ptr == allocation base; Response.free frees it

    // Parse the status line + headers.
    httpparser::Header[MAX_RESPONSE_HEADERS] hstore;
    httpparser::Response presp;
    usz? consumed = httpparser::parse_response(raw, &presp, hstore[..], 0);
    if (catch consumed) return MALFORMED_RESPONSE~;

    // Frame the body: chunked, Content-Length, or read-to-EOF.
    char[] rest = raw[consumed..];
    char[] body;
    String te = find_header(presp.headers, "Transfer-Encoding");
    bool is_chunked = false;
    if (te.len != 0)
    {
        String[] parts = te.tsplit(",");
        is_chunked = ci_eq((char[])parts[^1].trim(), "chunked");
    }
    if (is_chunked)
    {
        httpparser::ChunkedDecoder dec = { .consume_trailer = true };
        usz bsz = rest.len;
        if (catch httpparser::decode_chunked(&dec, rest, &bsz)) return MALFORMED_RESPONSE~;
        body = rest[:bsz];
    }
    else
    {
        String cl = find_header(presp.headers, "Content-Length");
        if (cl.len != 0)
        {
            ulong len = cl.to_ulong() ?? MALFORMED_RESPONSE~!;   // Content-Length is unsigned
            body = rest[:len > rest.len ? rest.len : (usz)len];  // clamp to what we received
        }
        else
        {
            body = rest;
        }
    }

    // Copy the parsed headers into an owned array (name/value still slice `raw`).
    usz nh = presp.headers.len;
    Header[] headers = {};
    if (nh != 0)
    {
        headers = alloc::new_array(allocator, Header, (sz)nh);
        headers[..] = presp.headers[..];
    }

    return {
        .status = presp.status,
        .minor_version = presp.minor_version,
        .headers = headers,
        .body = body,
        .raw = raw,
        .allocator = allocator,
    };
}

// ---- convenience wrappers (open a connection, send, close) ------------------

<* Parse `url_str` (must be http://) into the connect `Url`, the RFC 7230 §5.4
   Host header value (host, plus non-default port), and the request-target
   (percent-re-encoded path + raw query). *>
fn void? make_request_target(String url_str, Url* u, String* host_hdr, String* target) @private
{
    *u = url::parse(tmem, url_str)!;
    if (!ci_eq(u.scheme, "http")) return UNSUPPORTED_SCHEME~;
    int port = u.port ?: 80;
    *host_hdr = port == 80 ? u.host : string::tformat("%s:%d", u.host, port);
    String path = u.path.len != 0 ? url::tencode(u.path, url::UrlEncodingMode.PATH) : "/";  // re-encode path
    if (u.query.len != 0) path = string::tformat("%s?%s", path, u.query);                   // query left un-decoded by url::parse
    *target = path;
}

<* Perform `method url_str` over a fresh connection. `url_str` must be http://. *>
fn Response? request_url(Method method, String url_str, Header[] headers = {}, char[] body = {}, Duration timeout = time::DURATION_ZERO, Allocator allocator = tmem)
{
    Url u; String host_hdr; String target;
    make_request_target(url_str, &u, &host_hdr, &target)!;
    int port = u.port ?: 80;
    PlainConn conn = dial(u.host, port, timeout)!;
    defer (void)conn.close();
    return send(allocator, &conn, method, host_hdr, target, headers, body);
}

<* Perform `GET url` over a fresh connection. `url` must be http://. *>
fn Response? get(String url, Header[] headers = {}, Allocator allocator = tmem)
    => request_url(GET, url, headers, allocator: allocator);
<* Perform `HEAD url` over a fresh connection. `url` must be http://. *>
fn Response? head(String url, Header[] headers = {}, Allocator allocator = tmem)
    => request_url(HEAD, url, headers, allocator: allocator);
<* Perform `DELETE url` over a fresh connection. `url` must be http://. *>
fn Response? delete(String url, Header[] headers = {}, Allocator allocator = tmem)
    => request_url(DELETE, url, headers, allocator: allocator);
<* Perform `POST url` with `body` over a fresh connection. `url` must be http://. *>
fn Response? post(String url, char[] body, Header[] headers = {}, Allocator allocator = tmem)
    => request_url(POST, url, headers, body, allocator: allocator);
<* Perform `PUT url` with `body` over a fresh connection. `url` must be http://. *>
fn Response? put(String url, char[] body, Header[] headers = {}, Allocator allocator = tmem)
    => request_url(PUT, url, headers, body, allocator: allocator);
<* Perform `PATCH url` with `body` over a fresh connection. `url` must be http://. *>
fn Response? patch(String url, char[] body, Header[] headers = {}, Allocator allocator = tmem)
    => request_url(PATCH, url, headers, body, allocator: allocator);
