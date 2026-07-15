// A reusable HTTP client: a base URL, default headers, and a connection timeout,
// applied to every request. (Increment 1's one-connection-per-request transport
// still applies.)

module tinyhttp;
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
}

<* Create a client. *>
fn Client client(Allocator allocator, String base_url = "", Header[] default_headers = {}, Duration timeout = time::DURATION_ZERO, TlsConfig tls = {})
    => { .allocator = allocator, .base_url = base_url, .default_headers = default_headers, .timeout = timeout, .tls = tls };

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
   contribute only the names `headers` does not provide (up to MAX_HEADERS total). *>
fn Response? Client.request(&self, Method method, String path, Header[] headers = {}, char[] body = {})
{
    String url = self.base_url.len != 0 ? self.base_url.tconcat(path) : path;

    Header[MAX_HEADERS] merged;
    usz m = merge_headers(merged[..], self.default_headers, headers)!;

    return request_url(method, url, merged[:m], body, self.timeout, self.allocator, self.tls);
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
