// tinyhttp HTTP/1.1 client core: send a request over a Conn and read the
// response back through the parser. Increment 1 is blocking and uses
// "Connection: close" (read the whole response, then parse).
//
// Allocation model (R9): callers pass a single Allocator that owns the
// Response. Internally this module uses a two-tier scheme: transient work
// (URL parsing, Host/target formatting) goes through `tmem`, while everything
// the returned Response points at (the raw response buffer and the owned
// header array) is allocated from the caller-supplied `allocator` and freed
// by Response.free.

module tinyhttp;
import httpparser;
import std::io;
import std::net::url;
import std::time;

faultdef
    UNSUPPORTED_SCHEME,   // scheme is neither http:// nor https://
    CONNECT_FAILED,       // could not reach the peer
    TIMEOUT,              // connect timed out
    DNS_FAILED,           // host name / address resolution failed
    INVALID_HEADER,       // caller header name/value contains CR or LF
    TOO_MANY_HEADERS,     // more headers supplied than MAX_HEADERS
    RESPONSE_TOO_LARGE,   // response exceeded MAX_RESPONSE_BYTES
    MALFORMED_RESPONSE,   // response could not be parsed
    INVALID_URL,          // url could not be parsed into a usable http:// target
    INCOMPLETE_RESPONSE,  // Content-Length exceeded the bytes received before EOF
    TLS_FAILED,           // TLS setup, read, or write failed
    TLS_HANDSHAKE_FAILED; // TLS handshake or certificate verification failed

const usz MAX_RESPONSE_HEADERS @private = 100;
const usz MAX_RESPONSE_BYTES @private = 32 * 1024 * 1024;
const int DEFAULT_HTTP_PORT @private = 80;
const int DEFAULT_HTTPS_PORT @private = 443;

<* Send a request over an already-open connection and read the response. The
   low-level entry point: convenience wrappers and `Client` build on it, and
   tests drive it with a mock `Conn`. *>
fn Response? send(Allocator allocator, Conn conn, Method method, String host, String path, Header[] headers = {}, char[] body = {})
{
    write_request(conn, method, host, path, headers, body)!;
    return read_response(allocator, conn, method);
}

fn Response? read_response(Allocator allocator, Conn conn, Method method) @private
{
    // R11: read straight into the ByteWriter's spare capacity (no stack chunk + second memcpy).
    ByteWriter w;
    w.init(allocator);
    defer catch (void)w.destroy();   // frees the buffer on any fault exit; on success Response owns it
    while (true)
    {
        w.ensure_capacity(w.index + 4096)!;
        sz n = conn.read(w.bytes[w.index..])!;
        if (n <= 0) break;
        w.index += n;
        if ((usz)w.index > MAX_RESPONSE_BYTES) return RESPONSE_TOO_LARGE~;
    }
    char[] raw = w.array_view();   // .ptr == allocation base; Response.free frees it

    // R13: shrink the power-of-two over-allocation, keeping w.bytes in sync so the
    // defer-catch frees the right (possibly moved) pointer and every slice derives from it.
    if (w.bytes.len > w.index)
    {
        char* p = alloc::realloc(allocator, raw.ptr, w.index);
        w.bytes = p[:w.index];
        raw = p[:w.index];
    }

    // Parse the status line + headers (into the possibly-moved raw).
    httpparser::Header[MAX_RESPONSE_HEADERS] hstore;
    httpparser::Response presp;
    usz? consumed = httpparser::parse_response(raw, &presp, hstore[..], 0);
    if (catch consumed) return MALFORMED_RESPONSE~;

    char[] rest = raw[consumed..];
    char[] body;

    // R2: RFC 7230 §3.3.3 — HEAD, 1xx, 204, 304 carry no body regardless of framing headers.
    bool bodiless = method == HEAD
        || (presp.status >= 100 && presp.status < 200)
        || presp.status == 204
        || presp.status == 304;
    if (bodiless)
    {
        body = rest[:0];
    }
    else
    {
        // R5 + R14: chunked iff the FINAL transfer-coding across ALL Transfer-Encoding
        // header lines is chunked (multiple TE headers == one comma list; last one wins).
        String te = "";
        bool have_te = false;
        foreach (&h : presp.headers) if (ci_eq(h.name, "Transfer-Encoding")) { te = (String)h.value; have_te = true; }
        bool is_chunked = false;
        if (have_te)
        {
            String last = te;
            if (try i = te.rindex_of(",")) last = te[i + 1..];
            is_chunked = ci_eq((char[])last.trim(), "chunked");
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
                ulong len = cl.to_ulong() ?? MALFORMED_RESPONSE~!;
                if (len > rest.len) return INCOMPLETE_RESPONSE~;   // R2: expected body larger than received
                body = rest[:(usz)len];
            }
            else
            {
                body = rest;
            }
        }
    }

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

<* Parse `url_str` (must be http:// or https://) into the connect `Url`, the RFC 7230 §5.4
   Host header value (host, plus non-default port), and the request-target
   (percent-re-encoded path + raw query). *>
fn void? make_request_target(String url_str, Url* u, String* host_hdr, String* target) @private
{
    *u = url::parse(tmem, url_str) ?? INVALID_URL~!;   // maps url faults (incl. EMPTY on "") to INVALID_URL
    bool is_https = ci_eq(u.scheme, "https");
    if (!is_https && !ci_eq(u.scheme, "http")) return UNSUPPORTED_SCHEME~;
    int default_port = is_https ? DEFAULT_HTTPS_PORT : DEFAULT_HTTP_PORT;
    int port = u.port ?: default_port;
    *host_hdr = port == default_port ? u.host : string::tformat("%s:%d", u.host, port);
    String path = u.path.len != 0 ? url::tencode(u.path, url::UrlEncodingMode.PATH) : "/";  // re-encode path
    if (u.query.len != 0) path = string::tformat("%s?%s", path, u.query);                   // query left un-decoded by url::parse
    *target = path;
}

<* Perform `method url_str` over a fresh connection. `url_str` must be http:// or https://. *>
fn Response? request_url(Method method, String url_str, Header[] headers = {}, char[] body = {}, Duration timeout = time::DURATION_ZERO, Allocator allocator = tmem, TlsConfig tls = {})
{
    Url u; String host_hdr; String target;
    make_request_target(url_str, &u, &host_hdr, &target)!;
    if (ci_eq(u.scheme, "https"))
    {
        int tls_port = u.port ?: DEFAULT_HTTPS_PORT;
        TlsConn conn = dial_tls(u.host, tls_port, tls, timeout)!;
        defer (void)conn.close();
        return send(allocator, &conn, method, host_hdr, target, headers, body);
    }
    int port = u.port ?: DEFAULT_HTTP_PORT;
    PlainConn conn = dial(u.host, port, timeout)!;
    defer (void)conn.close();
    return send(allocator, &conn, method, host_hdr, target, headers, body);
}

<* Perform `GET url` over a fresh connection. `url` must be http:// or https://. *>
fn Response? get(String url, Header[] headers = {}, Allocator allocator = tmem)
    => request_url(GET, url, headers, allocator: allocator);
<* Perform `HEAD url` over a fresh connection. `url` must be http:// or https://. *>
fn Response? head(String url, Header[] headers = {}, Allocator allocator = tmem)
    => request_url(HEAD, url, headers, allocator: allocator);
<* Perform `DELETE url` over a fresh connection. `url` must be http:// or https://. *>
fn Response? delete(String url, Header[] headers = {}, Allocator allocator = tmem)
    => request_url(DELETE, url, headers, allocator: allocator);
<* Perform `POST url` with `body` over a fresh connection. `url` must be http:// or https://. *>
fn Response? post(String url, char[] body, Header[] headers = {}, Allocator allocator = tmem)
    => request_url(POST, url, headers, body, allocator: allocator);
<* Perform `PUT url` with `body` over a fresh connection. `url` must be http:// or https://. *>
fn Response? put(String url, char[] body, Header[] headers = {}, Allocator allocator = tmem)
    => request_url(PUT, url, headers, body, allocator: allocator);
<* Perform `PATCH url` with `body` over a fresh connection. `url` must be http:// or https://. *>
fn Response? patch(String url, char[] body, Header[] headers = {}, Allocator allocator = tmem)
    => request_url(PATCH, url, headers, body, allocator: allocator);
