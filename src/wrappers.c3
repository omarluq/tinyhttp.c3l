// One-shot verb facade: open a fresh connection, send one request, close it.
// `request_url` resolves the URL and dials plain or TLS; the six verb helpers are
// thin argument-shaping wrappers over it.

module tinyhttp;
import std::time;

<* Perform `method url_str` over a fresh connection. `url_str` must be http:// or https://. *>
fn Response? request_url(
	Method method,
	String url_str,
	Header[] headers = { },
	char[] body = { },
	Timeouts timeouts = DEFAULT_TIMEOUTS,
	Allocator allocator = tmem,
	TlsConfig tls = { }
)
{
	RequestTarget rt = make_request_target(url_str)!;
	// Both concrete conns are declared up front so the one we bind outlives the
	// call; the unused sibling stays zero-initialized and is never touched. The
	// defer is registered only after `conn` is bound, so a dial fault rethrows
	// without closing anything.
	TlsConn tls_conn;
	PlainConn plain_conn;
	Conn conn;
	if (rt.is_https)
	{
		tls_conn = dial_tls(rt.url.host, rt.port, tls, timeouts)!;
		conn = &tls_conn;
	}
	else
	{
		plain_conn = dial(rt.url.host, rt.port, timeouts)!;
		conn = &plain_conn;
	}
	defer (void)conn.close();
	return send(allocator, conn, method, rt.host_hdr, rt.target, headers, body, timeouts);
}

<* Perform `GET url` over a fresh connection. `url` must be http:// or https://. *>
fn Response? get(
	String url,
	Header[] headers = { },
	Allocator allocator = tmem,
	Timeouts timeouts = DEFAULT_TIMEOUTS
) => request_url(GET, url, headers, timeouts: timeouts, allocator: allocator);
<* Perform `HEAD url` over a fresh connection. `url` must be http:// or https://. *>
fn Response? head(
	String url,
	Header[] headers = { },
	Allocator allocator = tmem,
	Timeouts timeouts = DEFAULT_TIMEOUTS
) => request_url(HEAD, url, headers, timeouts: timeouts, allocator: allocator);
<* Perform `DELETE url` over a fresh connection. `url` must be http:// or https://. *>
fn Response? delete(
	String url,
	Header[] headers = { },
	Allocator allocator = tmem,
	Timeouts timeouts = DEFAULT_TIMEOUTS
) => request_url(DELETE, url, headers, timeouts: timeouts, allocator: allocator);
<* Perform `OPTIONS url` over a fresh connection. `url` must be http:// or https://. *>
fn Response? options(
	String url,
	Header[] headers = { },
	Allocator allocator = tmem,
	Timeouts timeouts = DEFAULT_TIMEOUTS
) => request_url(OPTIONS, url, headers, timeouts: timeouts, allocator: allocator);
<* Perform `POST url` with `body` over a fresh connection. `url` must be http:// or https://. *>
fn Response? post(
	String url,
	char[] body,
	Header[] headers = { },
	Allocator allocator = tmem,
	Timeouts timeouts = DEFAULT_TIMEOUTS
) => request_url(POST, url, headers, body, timeouts: timeouts, allocator: allocator);
<* Perform `PUT url` with `body` over a fresh connection. `url` must be http:// or https://. *>
fn Response? put(
	String url,
	char[] body,
	Header[] headers = { },
	Allocator allocator = tmem,
	Timeouts timeouts = DEFAULT_TIMEOUTS
) => request_url(PUT, url, headers, body, timeouts: timeouts, allocator: allocator);
<* Perform `PATCH url` with `body` over a fresh connection. `url` must be http:// or https://. *>
fn Response? patch(
	String url,
	char[] body,
	Header[] headers = { },
	Allocator allocator = tmem,
	Timeouts timeouts = DEFAULT_TIMEOUTS
) => request_url(PATCH, url, headers, body, timeouts: timeouts, allocator: allocator);