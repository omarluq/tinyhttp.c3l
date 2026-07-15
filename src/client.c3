// A reusable HTTP client: a base URL, default headers, and a connection timeout,
// applied to every request. Client.request reuses connections through a
// keep-alive pool (Increment 4); the convenience wrappers stay one-shot.

module tinyhttp;
import std::net::url;
import std::time;

<* Configuration reused across requests. `base_url` is prepended to each path,
   `default_headers` supply header defaults for every request: a per-call header
   of the same name REPLACES (overrides) a default, so defaults contribute only
   the names the per-call set does not provide. `timeout` bounds the connect
   (0 = none). *>
struct Client
{
    Allocator allocator;
    String    base_url;
    Header[]  default_headers;
    Duration  timeout;
    TlsConfig tls;          // applied to https:// requests (default: verify vs the system CA bundle)
    ConnPool  pool;         // keep-alive pool of idle connections, keyed by scheme|host|port
}

<* Create a client. *>
fn Client client(Allocator allocator, String base_url = "", Header[] default_headers = {}, Duration timeout = time::DURATION_ZERO, TlsConfig tls = {})
    => { .allocator = allocator, .base_url = base_url, .default_headers = default_headers, .timeout = timeout, .tls = tls, .pool = { .allocator = allocator } };

<* Append `src` into `dst` starting at `count`; raise TOO_MANY_HEADERS if they
   would not all fit. Returns the new count. *>
fn usz? append_headers(Header[] dst, usz count, Header[] src) @private
{
    foreach (&h : src)
    {
        if (count >= dst.len) return TOO_MANY_HEADERS~;
        dst[count] = *h;
        count++;
    }
    return count;
}

<* Merge `defaults` and `overrides` into `dst` with override semantics: every
   header in `overrides` is included, and a default is included only when
   `overrides` has no header of the same name (case-insensitive). Returns the
   merged count; raises TOO_MANY_HEADERS if they do not all fit. *>
fn usz? merge_headers(Header[] dst, Header[] defaults, Header[] overrides) @private
{
    usz m = 0;
    foreach (&h : defaults)
    {
        bool overridden = false;
        foreach (&c : overrides) if (ci_eq(h.name, (String)c.name)) { overridden = true; break; }
        if (overridden) continue;
        if (m >= dst.len) return TOO_MANY_HEADERS~;
        dst[m++] = *h;
    }
    return append_headers(dst, m, overrides);
}

<* Perform `method` on base_url+path, merging the default headers with `headers`:
   a per-call header REPLACES (overrides) a default of the same name, so defaults
   contribute only the names `headers` does not provide (up to MAX_HEADERS total).

   Connections are reused through the client's keep-alive pool: an idle conn for
   the target scheme|host|port is tried first (retrying once on a stale idle
   socket), otherwise a fresh connection is dialed. A precisely-delimited,
   still-persistent response returns its conn to the pool; anything else closes
   it. Call `close` when done to release pooled sockets. *>
fn Response? Client.request(&self, Method method, String path, Header[] headers = {}, char[] body = {})
{
    String url = self.base_url.len != 0 ? self.base_url.tconcat(path) : path;

    Header[MAX_HEADERS] merged;
    usz m = merge_headers(merged[..], self.default_headers, headers)!;

    RequestTarget rt = make_request_target(url)!;
    String scheme = rt.is_https ? "https" : "http";
    String key = pool_key(scheme, rt.url.host, rt.port);

    // Pooled attempt: reuse an idle connection if one is available.
    if (try ic = self.pool.checkout(key))
    {
        Response? r = self.exchange_and_settle(key, ic, method, rt.host_hdr, rt.target, merged[:m], body, true);
        // On a real fault the socket is already discarded; only a stale idle
        // socket falls through to a fresh dial.
        if (catch e = r)
        {
            if (e != STALE_CONNECTION) return e~;
        }
        else
        {
            return r;
        }
    }

    // Fresh connection (also the stale-retry path; reused:false, so STALE_CONNECTION cannot arise here).
    IdleConn ic = self.dial_idle(rt.is_https, rt.url.host, rt.port)!;
    return self.exchange_and_settle(key, ic, method, rt.host_hdr, rt.target, merged[:m], body, false);
}

<* Run one request/response exchange on `ic` and settle its pool membership:
   on fault the connection is discarded and the fault re-raised; otherwise the
   connection is returned to the pool under `key` when still reusable, or
   discarded when not. `reused` marks whether `ic` came from the pool. *>
fn Response? Client.exchange_and_settle(&self, String key, IdleConn ic, Method method, String host_hdr, String target, Header[] headers, char[] body, bool reused) @private
{
    bool reusable;
    Response? r = do_exchange(self.allocator, ic.conn, method, host_hdr, target, headers, body, reused, &reusable);
    if (catch e = r)
    {
        self.pool.discard(ic);
        return e~;
    }
    if (reusable) { self.pool.checkin(key, ic); }
    else { self.pool.discard(ic); }
    return r;
}

<* Drain and close every connection held in the keep-alive pool, releasing their
   sockets. A Client that made requests must be closed to release the pooled
   sockets; the convenience wrappers close their connections eagerly and need no
   cleanup. *>
fn void Client.close(&self)
{
    self.pool.free();
}

<* Compose the transient pool key "scheme|host|port". The key lives in `tmem`;
   ConnPool.checkin copies it into the pool allocator when it stores an entry. *>
fn String pool_key(String scheme, String host, int port) @private
    => string::tformat("%s|%s|%d", scheme, host, port);

<* Dial a fresh connection into a heap object owned by the Client allocator,
   returning it wrapped as an IdleConn (`.conn` = the Conn fat pointer, `.mem` =
   the heap allocation to free). *>
fn IdleConn? Client.dial_idle(&self, bool is_https, String host, int port) @private
{
    if (is_https)
    {
        TlsConn* c = alloc::new(self.allocator, TlsConn);
        defer catch alloc::free(self.allocator, c);
        *c = dial_tls(host, port, self.tls, self.timeout)!;
        return { .conn = (Conn)c, .mem = c };
    }
    PlainConn* c = alloc::new(self.allocator, PlainConn);
    defer catch alloc::free(self.allocator, c);
    *c = dial(host, port, self.timeout)!;
    return { .conn = (Conn)c, .mem = c };
}

<* GET base_url+path with the default headers merged with `headers`. *>
fn Response? Client.get(&self, String path, Header[] headers = {})
    => self.request(GET, path, headers);

<* HEAD base_url+path with the default headers merged with `headers`. *>
fn Response? Client.head(&self, String path, Header[] headers = {})
    => self.request(HEAD, path, headers);

<* DELETE base_url+path with the default headers merged with `headers`. *>
fn Response? Client.delete(&self, String path, Header[] headers = {})
    => self.request(DELETE, path, headers);

<* POST `body` to base_url+path with the default headers merged with `headers`. *>
fn Response? Client.post(&self, String path, char[] body, Header[] headers = {})
    => self.request(POST, path, headers, body);

<* PUT `body` to base_url+path with the default headers merged with `headers`. *>
fn Response? Client.put(&self, String path, char[] body, Header[] headers = {})
    => self.request(PUT, path, headers, body);

<* PATCH base_url+path with `body` and the default headers merged with `headers`. *>
fn Response? Client.patch(&self, String path, char[] body, Header[] headers = {})
    => self.request(PATCH, path, headers, body);
