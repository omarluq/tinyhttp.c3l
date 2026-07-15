// A reusable HTTP client: a base URL, default headers, and a connection timeout,
// applied to every request. Client.request reuses connections through a
// keep-alive pool; the convenience wrappers stay one-shot.

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
    SslCtx    tls_ctx;      // shared long-lived SSL_CTX for https dials, built lazily on first use

    // Lazily-cached connection target for a non-empty base_url: base_url fixes the
    // scheme/host/port/host-header/pool-key (only the request-target varies per
    // call), so these are computed once on the first request rather than reparsed
    // every call. Cached at first use, not construction, because client() is
    // infallible while url::parse can fault. The strings live on `allocator` and
    // are released by close(). `base_target_prefix` is "http://h" + base_url's
    // authority-stripped remainder, so the per-call target is derived by
    // re-parsing only that short prefix + path (never base_url's origin again).
    bool   base_cached;
    bool   base_https;
    String base_host;
    int    base_port;
    String base_host_hdr;
    String base_key;
    String base_target_prefix;
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
        if (has_header(overrides, (String)h.name)) continue;
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
fn Response? Client.request(&self, Method method, String path, Header[] headers = {}, char[] body = {}) => @pool()
{
    // Merge headers first so a header overflow faults before any per-Client cache
    // is populated (nothing persistent is allocated on the way out).
    Header[MAX_HEADERS] merged;
    usz m = merge_headers(merged[..], self.default_headers, headers)!;

    bool   is_https;
    String host;
    int    port;
    String host_hdr;
    String key;
    String target;
    if (self.base_url.len != 0)
    {
        // Non-empty base_url: scheme/host/port/host-header/pool-key are invariant,
        // cached once (self.allocator). Only the request-target varies per call, and
        // it is built by re-parsing just the cached authority-stripped prefix + path
        // — base_url's origin is never reparsed after the first request.
        self.ensure_base_cached()!;
        is_https = self.base_https;
        host     = self.base_host;
        port     = self.base_port;
        host_hdr = self.base_host_hdr;
        key      = self.base_key;
        target   = make_request_target(self.base_target_prefix.tconcat(path))!.target;
    }
    else
    {
        // Empty base_url: `path` is a full absolute URL parsed per call; everything
        // here lives in tmem and is reset on every exit path.
        RequestTarget rt = make_request_target(path)!;
        is_https = rt.is_https;
        host     = rt.url.host;
        port     = rt.port;
        host_hdr = rt.host_hdr;
        target   = rt.target;
        key      = pool_key(rt.is_https ? "https" : "http", rt.url.host, rt.port);
    }

    // Pooled attempt: reuse an idle connection if one is available.
    if (try ic = self.pool.checkout(key))
    {
        Response? r = self.exchange_and_settle(key, ic, method, host_hdr, target, merged[:m], body, true);
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
    IdleConn ic = self.dial_idle(is_https, host, port)!;
    return self.exchange_and_settle(key, ic, method, host_hdr, target, merged[:m], body, false);
}

<* Populate the per-Client cache of connection invariants for a non-empty
   `base_url` on first use: scheme/host/port/host-header/pool-key (all constant
   for the Client's life) plus `base_target_prefix` ("http://h" + base_url's
   authority-stripped remainder) so later calls re-parse only that short prefix +
   path. Copies live on `self.allocator` and are released by close(). Raises
   INVALID_URL/UNSUPPORTED_SCHEME if base_url does not parse. *>
fn void? Client.ensure_base_cached(&self) @private
{
    if (self.base_cached) return;
    RequestTarget rt = make_request_target(self.base_url)!;
    self.base_https         = rt.is_https;
    self.base_host          = rt.url.host.copy(self.allocator);
    self.base_port          = rt.port;
    self.base_host_hdr      = rt.host_hdr.copy(self.allocator);
    self.base_key           = pool_key(rt.is_https ? "https" : "http", rt.url.host, rt.port).copy(self.allocator);
    self.base_target_prefix = ("http://h").concat(self.allocator, base_authority_rest(self.base_url));
    self.base_cached        = true;
}

<* The authority-stripped remainder of `url_str` (everything from the first '/',
   '?' or '#' after "scheme://" to the end, or "" if the authority is the whole
   rest). Prepending a dummy authority to `rest` + path reproduces the request
   target that parsing base_url + path would yield, without reparsing base_url's
   origin. *>
fn String base_authority_rest(String url_str) @private
{
    usz start = 0;
    if (try i = url_str.index_of("://")) start = (usz)i + 3;
    String after = url_str[start..];
    sz rel = after.index_of_chars("/?#") ?? (sz)after.len;
    return after[(usz)rel..];
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
    // Free pooled sockets first, then the shared ctx AFTER, so it outlives every
    // SSL layered over it.
    self.pool.free();
    free_shared_ctx(self.tls_ctx);
    self.tls_ctx = (SslCtx)null;
    // Release the base_url cache copies made on first request (if any).
    if (self.base_cached)
    {
        alloc::free(self.allocator, self.base_host.ptr);
        alloc::free(self.allocator, self.base_host_hdr.ptr);
        alloc::free(self.allocator, self.base_key.ptr);
        alloc::free(self.allocator, self.base_target_prefix.ptr);
        self.base_cached = false;
    }
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
        // One shared, long-lived ctx per Client (its TlsConfig is fixed); pooled
        // TlsConns borrow it (owns_ctx = false) and Client.close frees it.
        if (self.tls_ctx == null) self.tls_ctx = make_ctx(self.tls)!;
        TlsConn* c = alloc::new(self.allocator, TlsConn);
        defer catch alloc::free(self.allocator, c);
        *c = dial_tls_ctx(self.tls_ctx, !self.tls.no_verify, host, port, self.timeout)!;
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

<* OPTIONS base_url+path with the default headers merged with `headers`. *>
fn Response? Client.options(&self, String path, Header[] headers = {})
    => self.request(OPTIONS, path, headers);

<* POST `body` to base_url+path with the default headers merged with `headers`. *>
fn Response? Client.post(&self, String path, char[] body, Header[] headers = {})
    => self.request(POST, path, headers, body);

<* PUT `body` to base_url+path with the default headers merged with `headers`. *>
fn Response? Client.put(&self, String path, char[] body, Header[] headers = {})
    => self.request(PUT, path, headers, body);

<* PATCH base_url+path with `body` and the default headers merged with `headers`. *>
fn Response? Client.patch(&self, String path, char[] body, Header[] headers = {})
    => self.request(PATCH, path, headers, body);
