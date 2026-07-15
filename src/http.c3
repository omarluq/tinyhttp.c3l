// tinyhttp HTTP/1.1 client core: send a request over a Conn and read the
// response back through the parser. The reader frames the body precisely (per
// RFC 7230) so a keep-alive connection can be reused; only a close-delimited
// body (no Content-Length, not chunked) is read to EOF.
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
    TLS_HANDSHAKE_FAILED, // TLS handshake or certificate verification failed
    STALE_CONNECTION;     // internal retry signal: a reused keep-alive conn was closed before the response arrived; consumed by the retry-once path and never returned to the user

const usz MAX_RESPONSE_HEADERS @private = 100;
const usz MAX_RESPONSE_BYTES @private = 32 * 1024 * 1024;
const int DEFAULT_HTTP_PORT @private = 80;
const int DEFAULT_HTTPS_PORT @private = 443;

<* Send a request over an already-open connection and read the response back. The
   low-level entry point: convenience wrappers and `Client` build on it, and tests
   drive it with a mock `Conn`. Sends `Connection: close` and frames the response
   body exactly — bodiless (HEAD/1xx/204/304), Content-Length, or chunked — reading
   to EOF only for a close-delimited body. The connection is not reused. *>
fn Response? send(Allocator allocator, Conn conn, Method method, String host, String path, Header[] headers = {}, char[] body = {})
{
    write_request(conn, method, host, path, headers, body)!;
    return read_response(allocator, conn, method);
}

// Read once into the ByteWriter's spare capacity, advance the write cursor, tally
// the cumulative byte count and enforce MAX_RESPONSE_BYTES. Returns the byte count
// (0 == EOF); a read fault propagates and a size-cap breach raises RESPONSE_TOO_LARGE.
// Callers own their ensure_capacity call (site-specific) and their own n==0 reaction.
fn sz? read_into(Conn conn, ByteWriter* w, usz* received) @private
{
    sz n = conn.read(w.bytes[w.index..])!;
    w.index += n;
    *received += (usz)n;
    if (*received > MAX_RESPONSE_BYTES) return RESPONSE_TOO_LARGE~;
    return n;
}

// The outcome of consuming a framed body: the decoded/copied body length written
// into raw[consumed..] and the count of trailing bytes buffered past the message
// end. Each body strategy leaves w.index at consumed + body_len so the phase-3
// shrink and phase-4 re-parse observe identical buffer state. (C3 has no tuple
// returns, so the two scalars ride out together.)
struct BodyFrame @private
{
    usz body_len;
    usz leftover;
}

// Content-Length body: read until `content_length` body bytes are buffered past the
// header block, then trim any trailing (pipelined) bytes. `received` stays running so
// the MAX_RESPONSE_BYTES cap spans the whole response.
fn BodyFrame? read_body_content_length(Conn conn, ByteWriter* w, usz consumed, usz content_length, usz* received) @private
{
    usz have = (usz)w.index - consumed;
    usz target = consumed + content_length;
    while (have < content_length)
    {
        // Grow to a bounded read-ahead window, never past the declared total, so memory
        // tracks bytes actually delivered rather than reserving the full (possibly near-cap)
        // Content-Length up front on the first byte.
        usz want = (usz)w.index + 65536;
        w.ensure_capacity((sz)(want < target ? want : target))!;
        sz? nr = read_into(conn, w, received);   // read into the spare capacity
        if (catch e = nr) return e~;
        sz n = nr;
        if (n == 0) return INCOMPLETE_RESPONSE~;   // fewer bytes than Content-Length before EOF
        have = (usz)w.index - consumed;
    }
    w.index = (sz)(consumed + content_length);   // drop any trailing (pipelined) bytes
    return { .body_len = content_length, .leftover = have - content_length };
}

// Chunked body: incremental in-place decode. Each pass feeds only the newly-read bytes
// and appends decoded output right after the previously-decoded region. Recompute the
// base slice from array_view() every pass because ensure_capacity may move the buffer;
// the decoder only ever rewrites raw[consumed..], so header bytes stay put.
fn BodyFrame? read_body_chunked(Conn conn, ByteWriter* w, usz consumed, usz* received) @private
{
    httpparser::ChunkedDecoder dec = { .consume_trailer = true };
    usz decoded = 0;
    usz seg = (usz)w.index - consumed;
    while (true)
    {
        usz seg2 = seg;
        usz? left = httpparser::decode_chunked(&dec, ((w.array_view())[consumed..])[decoded..], &seg2);
        decoded += seg2;
        w.index = (sz)(consumed + decoded);
        if (catch e2 = left)
        {
            if (e2 == httpparser::MALFORMED) return MALFORMED_RESPONSE~;
            // INCOMPLETE: append more chunk bytes past the decoded region and decode
            // again. w.index (== consumed+decoded here) must advance by the bytes read
            // so the next array_view() exposes them as the new segment.
            w.ensure_capacity((sz)(consumed + decoded) + 4096)!;
            sz? nr = read_into(conn, w, received);
            if (catch e = nr) return e~;
            sz n = nr;
            if (n == 0) return INCOMPLETE_RESPONSE~;   // EOF mid-chunk
            seg = (usz)n;
            continue;
        }
        return { .body_len = decoded, .leftover = left };
    }
}

// Close-delimited body (HTTP/1.0 style): no Content-Length, not chunked. Read until EOF.
// Never poolable (the framing boundary is the connection close itself), so leftover is 0.
fn BodyFrame? read_body_to_eof(Conn conn, ByteWriter* w, usz consumed, usz* received) @private
{
    while (true)
    {
        w.ensure_capacity(w.index + 4096)!;
        sz? nr = read_into(conn, w, received);
        if (catch e = nr) return e~;
        sz n = nr;
        if (n == 0) break;
    }
    return { .body_len = (usz)w.index - consumed, .leftover = 0 };
}

<* Read one HTTP/1.1 response from `conn` into a single owned buffer (Response.raw).

   The header block is read incrementally, then the body is consumed by its declared
   framing so the reader stops exactly at the message end and the connection stays
   reusable: bodiless (HEAD/1xx/204/304), Content-Length, or chunked transfer-encoding.
   Only a body delimited by neither Content-Length nor chunking (an HTTP/1.0-style
   close-delimited body) is read to EOF.

   `reused` marks a connection drawn from the keep-alive pool: if the very first read
   sees a closed/empty socket the response never started, so STALE_CONNECTION is raised
   and the caller can retry once on a fresh connection. When `reusable` is non-null it
   receives whether this connection may return to the pool — the body was precisely
   delimited, neither side asked to close, and no trailing bytes remain. *>
fn Response? read_response(Allocator allocator, Conn conn, Method method, bool reused = false, bool* reusable = null) @private
{
    // R11: read straight into the ByteWriter's spare capacity (no stack chunk + second memcpy).
    ByteWriter w;
    w.init(allocator);
    defer catch (void)w.destroy();   // frees the buffer on any fault exit; on success Response owns it

    httpparser::Header[MAX_RESPONSE_HEADERS] hstore;
    httpparser::Response presp;
    usz received = 0;   // cumulative bytes read, for the size cap
    usz last = 0;       // buf length at the previous parse attempt (slowloris check)
    usz consumed = 0;   // header-block length, once parsed

    // PHASE 1: read the status line + header block, re-parsing after each read.
    // An HTTP/1.1 server may emit one or more 1xx interim responses (100 Continue,
    // 103 Early Hints — now routinely injected by CDNs) ahead of the real response.
    // A 1xx carries no body (RFC 7230 §3.3.3), so discard each interim block, compact
    // any already-buffered tail (which may hold the start of the next response) down to
    // offset 0 and keep reading; phase 4 re-parses from offset 0, so the compaction must
    // be physical, not a base-offset. 101 Switching Protocols is a real response, not
    // interim. Bound the interim count so a peer can't stream 1xx forever (DoS).
    const usz MAX_INTERIM_RESPONSES = 8;
    usz interim = 0;
    while (true)
    {
        // Accumulate one complete header block, parsing already-buffered bytes first and
        // reading more only while the block is incomplete (after compaction the next
        // response may already be fully buffered, so a blind read must not precede a parse).
        while (true)
        {
            if ((usz)w.index > last)
            {
                usz? c = httpparser::parse_response(w.array_view(), &presp, hstore[..], last);
                if (try cv = c)
                {
                    consumed = cv;   // parsed: cv is the header-block length
                    break;
                }
                if (catch pe = c)
                {
                    if (pe == httpparser::MALFORMED) return MALFORMED_RESPONSE~;
                    last = (usz)w.index;   // INCOMPLETE: valid prefix, read more
                }
            }
            w.ensure_capacity(w.index + 4096)!;
            sz? nr = read_into(conn, &w, &received);
            if (catch e = nr)
            {
                if (reused && interim == 0 && w.index == 0) return STALE_CONNECTION~;   // idle keep-alive conn was closed
                return e~;
            }
            sz n = nr;
            if (n == 0)
            {
                if (reused && interim == 0 && w.index == 0) return STALE_CONNECTION~;
                return MALFORMED_RESPONSE~;                             // EOF before a complete header block
            }
        }

        // Discard a 1xx interim response (except 101) and re-parse the compacted tail.
        if (presp.status >= 100 && presp.status < 200 && presp.status != 101)
        {
            if (++interim > MAX_INTERIM_RESPONSES) return MALFORMED_RESPONSE~;   // interim flood
            usz tail = (usz)w.index - consumed;   // bytes past the interim block: start of the next response
            if (tail != 0)
            {
                char[] view = w.array_view();
                mem::move(view.ptr, view.ptr + consumed, (sz)tail);   // physically shift the tail to offset 0
            }
            w.index = (sz)tail;
            last = 0;   // buffer shifted; the slowloris resume hint no longer applies
            continue;
        }
        break;   // final response: status >= 200, or 101 Switching Protocols
    }

    // Framing SCALARS from the phase-1 parse. Header token slices are invalidated by
    // later buffer growth, so capture values (never slices) now.
    // R2: RFC 7230 §3.3.3 — HEAD, 1xx, 204, 304 carry no body regardless of framing headers.
    bool bodiless = method == HEAD
        || (presp.status >= 100 && presp.status < 200)
        || presp.status == 204
        || presp.status == 304;

    bool is_chunked = false;
    long content_length = -1;
    if (!bodiless)
    {
        is_chunked = te_is_chunked(presp.headers);
        // RFC 7230 §3.3.3 rule 3: when Transfer-Encoding is present but chunked is not
        // the final coding, the body is delimited by connection close and Content-Length
        // MUST be ignored. Only trust Content-Length when Transfer-Encoding is absent;
        // otherwise leave content_length = -1 so phase 2 dispatches to read_body_to_eof
        // and `delimited` stays false (non-reusable), closing a smuggling-adjacent hazard.
        if (!is_chunked && !has_header(presp.headers, "Transfer-Encoding"))
        {
            long clv = content_length_header(presp.headers)!;   // -1 when absent; faults on conflicting duplicate fields
            if (clv >= 0)
            {
                if ((ulong)clv > MAX_RESPONSE_BYTES) return RESPONSE_TOO_LARGE~;   // cap the DECLARED length before it sizes the buffer
                content_length = clv;                                             // now provably >= 0, so framing is never mis-read
            }
        }
    }

    // PHASE 2: consume exactly the framed body, dispatching to the matching strategy.
    // Each helper leaves w.index at consumed + body_len and returns the body length plus
    // any trailing bytes buffered past the message end. The bodiless case stays inline:
    // there is nothing to read, and every already-buffered byte is leftover.
    BodyFrame frame;
    if (bodiless)
    {
        frame = { .body_len = 0, .leftover = (usz)w.index - consumed };
    }
    else if (content_length >= 0)
    {
        frame = read_body_content_length(conn, &w, consumed, (usz)content_length, &received)!;
    }
    else if (is_chunked)
    {
        frame = read_body_chunked(conn, &w, consumed, &received)!;
    }
    else
    {
        frame = read_body_to_eof(conn, &w, consumed, &received)!;
    }
    usz body_len = frame.body_len;
    usz leftover = frame.leftover;

    // PHASE 3 (R13): shrink the power-of-two over-allocation, keeping w.bytes in sync so
    // the defer-catch frees the right (possibly moved) pointer and every slice derives from it.
    char[] raw = w.array_view();   // .ptr == allocation base; Response.free frees it
    if (w.bytes.len > w.index)
    {
        char* p = alloc::realloc(allocator, raw.ptr, w.index);
        w.bytes = p[:w.index];
        raw = p[:w.index];
    }

    // PHASE 4: re-parse the now-stable, shrunk buffer to get output header/body slices.
    // The double parse is intentional: phase 1 drives framing while the buffer still
    // grows; phase 4 yields stable slices into the final allocation.
    httpparser::Response presp2;
    usz consumed2 = httpparser::parse_response(raw, &presp2, hstore[..], 0)!;
    char[] body = raw[consumed2 : body_len];   // bytes [consumed2 .. consumed2 + body_len)

    usz nh = presp2.headers.len;
    Header[] headers = {};
    if (nh != 0)
    {
        headers = alloc::new_array(allocator, Header, (sz)nh);
        headers[..] = presp2.headers[..];
    }

    // Reusability: precisely delimited, both peers persistent, and no trailing bytes
    // (leftover > 0 means unframed data we can't push back into the socket).
    if (reusable != null)
    {
        // Header bytes are never mutated after phase 1, so presp2 yields the same
        // Connection tokens and minor version as the phase-1 parse would.
        bool resp_close = has_connection_token(presp2.headers, "close");
        bool resp_keepalive = has_connection_token(presp2.headers, "keep-alive");
        bool delimited = bodiless || content_length >= 0 || is_chunked;
        bool persistent = presp2.minor_version >= 1 ? !resp_close : resp_keepalive;
        *reusable = delimited && persistent && leftover == 0;
    }

    return {
        .status = presp2.status,
        .minor_version = presp2.minor_version,
        .headers = headers,
        .body = body,
        .raw = raw,
        .allocator = allocator,
    };
}

<* Write a request and read its response over an already-open connection, threading
   keep-alive state for `Client.request`. `reused` marks a pooled connection: a write
   failure or a dead first read surfaces as STALE_CONNECTION so the caller can retry
   once on a fresh connection. A fresh connection passes `reused` false, so read_response
   can never raise STALE_CONNECTION there and the signal never escapes to the user. On
   success `*reusable` says whether the connection may return to the pool — the response
   permitted reuse AND the request itself did not send Connection: close. *>
fn Response? do_exchange(Allocator allocator, Conn conn, Method method, String host, String path, Header[] headers, char[] body, bool reused, bool* reusable) @private
{
    if (catch e = write_request(conn, method, host, path, headers, body, close: false))
    {
        // Only auto-retry idempotent methods: a partial write of a POST/PATCH may have
        // reached a server that already started processing, so resending could double it.
        return reused && method.is_idempotent() ? STALE_CONNECTION~ : e~;
    }
    bool resp_reusable = false;
    Response resp = read_response(allocator, conn, method, reused, &resp_reusable)!;   // STALE_CONNECTION propagates when reused && the first read failed
    *reusable = resp_reusable && !has_connection_close(headers);
    return resp;
}

// ---- convenience wrappers (open a connection, send, close) ------------------

<* The resolved pieces of a request URL: the connect `Url`, the RFC 7230 §5.4
   Host header value, the request-target, the resolved connect port and whether
   the scheme is https. *>
struct RequestTarget @private
{
    Url    url;
    String host_hdr;
    String target;
    int    port;
    bool   is_https;
}

<* Parse `url_str` (must be http:// or https://) into a `RequestTarget`: the connect
   `Url`, the RFC 7230 §5.4 Host header value (host, plus non-default port), the
   request-target (percent-re-encoded path + raw query), the resolved connect port
   (explicit port, else the scheme default) and the is_https flag. *>
fn RequestTarget? make_request_target(String url_str) @private
{
    Url u = url::parse(tmem, url_str) ?? INVALID_URL~!;   // maps url faults (incl. EMPTY on "") to INVALID_URL
    bool is_https = ci_eq(u.scheme, "https");
    if (!is_https && !ci_eq(u.scheme, "http")) return UNSUPPORTED_SCHEME~;
    int default_port = is_https ? DEFAULT_HTTPS_PORT : DEFAULT_HTTP_PORT;
    int port = u.port ?: default_port;
    String host_hdr = port == default_port ? u.host : string::tformat("%s:%d", u.host, port);
    String path = u.path.len != 0 ? url::tencode(u.path, url::UrlEncodingMode.PATH) : "/";  // re-encode path
    if (u.query.len != 0) path = string::tformat("%s?%s", path, u.query);                   // query left un-decoded by url::parse
    return { .url = u, .host_hdr = host_hdr, .target = path, .port = port, .is_https = is_https };
}

<* Perform `method url_str` over a fresh connection. `url_str` must be http:// or https://. *>
fn Response? request_url(Method method, String url_str, Header[] headers = {}, char[] body = {}, Duration timeout = time::DURATION_ZERO, Allocator allocator = tmem, TlsConfig tls = {})
{
    RequestTarget rt = make_request_target(url_str)!;
    if (rt.is_https)
    {
        TlsConn conn = dial_tls(rt.url.host, rt.port, tls, timeout)!;
        defer (void)conn.close();
        return send(allocator, &conn, method, rt.host_hdr, rt.target, headers, body);
    }
    PlainConn conn = dial(rt.url.host, rt.port, timeout)!;
    defer (void)conn.close();
    return send(allocator, &conn, method, rt.host_hdr, rt.target, headers, body);
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
