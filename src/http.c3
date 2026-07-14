// tinyhttp HTTP/1.1 client core: send a request over a Conn and read the
// response back through the parser. Increment 1 is blocking and uses
// "Connection: close" (read the whole response, then parse).

module tinyhttp;
import httpparser;
import std::net::url;
import std::time;

faultdef
    UNSUPPORTED_SCHEME,   // only http:// so far
    CONNECT_FAILED,       // could not reach the peer
    WRITE_FAILED,         // socket closed mid-write
    MALFORMED_RESPONSE;   // response could not be parsed

const usz MAX_RESPONSE_HEADERS @private = 100;

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
    DString acc = dstring::new(allocator);
    defer acc.free();
    char[4096] chunk;
    while (true)
    {
        sz n = conn.read(chunk[..])!;
        if (n <= 0) break;
        acc.append_bytes(chunk[:(usz)n]);
    }
    char[] raw = acc.copy_str(allocator);
    defer catch alloc::free(allocator, raw.ptr);   // freed only if we bail out below

    // Parse the status line + headers.
    httpparser::Header[MAX_RESPONSE_HEADERS] hstore;
    httpparser::Response presp;
    usz? consumed = httpparser::parse_response(raw, &presp, hstore[..], 0);
    if (catch consumed) return MALFORMED_RESPONSE~;

    // Frame the body: chunked, Content-Length, or read-to-EOF.
    char[] rest = raw[consumed..];
    char[] body;
    if (ci_eq(find_header(presp.headers, "Transfer-Encoding"), "chunked"))
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

<* Perform `method url` over a fresh connection. `url` must be http://. *>
fn Response? request_url(Allocator allocator, Method method, String url, Header[] headers = {}, char[] body = {}, Duration timeout = {})
{
    Url u = url::parse(tmem, url)!;
    if (!ci_eq(u.scheme, "http")) return UNSUPPORTED_SCHEME~;
    int port = u.port ?: 80;
    String path = u.path.len != 0 ? u.path : "/";
    if (u.query.len != 0) path = string::tformat("%s?%s", path, u.query);

    PlainConn conn = dial(u.host, port, timeout)!;
    defer (void)conn.close();
    return send(allocator, &conn, method, u.host, path, headers, body);
}

fn Response? get(Allocator allocator, String url, Header[] headers = {})
    => request_url(allocator, GET, url, headers);
fn Response? head(Allocator allocator, String url, Header[] headers = {})
    => request_url(allocator, HEAD, url, headers);
fn Response? delete(Allocator allocator, String url, Header[] headers = {})
    => request_url(allocator, DELETE, url, headers);
fn Response? post(Allocator allocator, String url, char[] body, Header[] headers = {})
    => request_url(allocator, POST, url, headers, body);
fn Response? put(Allocator allocator, String url, char[] body, Header[] headers = {})
    => request_url(allocator, PUT, url, headers, body);
fn Response? patch(Allocator allocator, String url, char[] body, Header[] headers = {})
    => request_url(allocator, PATCH, url, headers, body);
