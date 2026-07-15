// One-shot verb facade: open a fresh connection, send one request, close it.
// `request_url` resolves the URL and dials plain or TLS; the six verb helpers are
// thin argument-shaping wrappers over it.

module tinyhttp;
import std::time;

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
<* Perform `OPTIONS url` over a fresh connection. `url` must be http:// or https://. *>
fn Response? options(String url, Header[] headers = {}, Allocator allocator = tmem)
    => request_url(OPTIONS, url, headers, allocator: allocator);
<* Perform `POST url` with `body` over a fresh connection. `url` must be http:// or https://. *>
fn Response? post(String url, char[] body, Header[] headers = {}, Allocator allocator = tmem)
    => request_url(POST, url, headers, body, allocator: allocator);
<* Perform `PUT url` with `body` over a fresh connection. `url` must be http:// or https://. *>
fn Response? put(String url, char[] body, Header[] headers = {}, Allocator allocator = tmem)
    => request_url(PUT, url, headers, body, allocator: allocator);
<* Perform `PATCH url` with `body` over a fresh connection. `url` must be http:// or https://. *>
fn Response? patch(String url, char[] body, Header[] headers = {}, Allocator allocator = tmem)
    => request_url(PATCH, url, headers, body, allocator: allocator);
