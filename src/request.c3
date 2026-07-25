// HTTP method, request serialization, and the fluent request builder.

module tinyhttp;
import std::time;
import std::io;

const String USER_AGENT @private = "tinyhttp/0.1";
const usz MAX_HEADERS @private   = 32; // capacity of the builder / merged-header arrays

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

<*
 True for methods safe to auto-retry after a mid-flight write failure. POST and
 PATCH are excluded: a partial write may have reached a server that already began
 processing, so a transparent resend could execute them twice.
*>
fn bool Method.is_idempotent(self) => self != POST && self != PATCH;

fn bool has_crlf(String s) @private => s.contains_char('\r') || s.contains_char('\n');

// io::write_all loops internally and offers no hook to re-arm the socket between
// iterations, so a slow-drip reader could let every individual write succeed while
// the total budget drained unchecked. This loop re-arms each pass.
fn void? write_all_deadline(Conn conn, char[] buf, Deadline* dl) @private
{
	usz off = 0;
	while (off < buf.len)
	{
		dl.arm_write(conn)!;
		sz? nw = conn.write(buf[off..]);
		if (catch e = nw)
		{
			// Mirror of read_into: the socket was possibly armed from the remaining
			// total, so a fired write timeout may really be the total budget expiring.
			if (e == WRITE_TIMEOUT && dl.total_spent()) return TIMEOUT~;
			return e~;
		}
		sz n = nw;
		if (n == 0) return io::INCOMPLETE_WRITE~;
		off += (usz)n;
	}
}

<*
 Serialize an HTTP/1.1 request and write it to `conn`. Host, a default
 User-Agent, and Content-Length for a body are each added only if the caller
 did not already supply them. Connection: close is sent when `close` is true
 (the default, used by the one-shot send() path) OR when the caller supplied a
 Connection header carrying the close token; the pooled/Client path passes
 close:false so the HTTP/1.1 connection stays persistent unless the caller asks
 to close. Caller header names/values containing CR or LF fault with
 INVALID_HEADER.
*>
fn void? write_request(
	Conn conn,
	Method method,
	String host,
	String path,
	Header[] headers,
	char[] body,
	Deadline* dl,
	bool close = true
) @private
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
		String hname  = (String)h.name;
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

	write_all_deadline(conn, (char[])req.str_view(), dl)!;
	if (body.len != 0) write_all_deadline(conn, body, dl)!;
}

// ---- fluent builder --------------------------------------------------------

<*
 A fluent request builder. Chain `header` / `body` / `timeout`, then `send`.
 Holds up to MAX_HEADERS headers inline; supplying more marks the builder
 overflowed and `send` faults with TOO_MANY_HEADERS.
*>
struct RequestBuilder
{
	Method method;
	String url;
	char[] _body;
	Timeouts _timeouts;
	TlsConfig _tls;
	Header[MAX_HEADERS] _headers;
	usz _count;
	bool _overflow;
}

<*
 Begin a `method` request to `url` (must be http:// or https://). Returns an
 UNSENT RequestBuilder: chain `.header()` / `.body()` / `.timeout()` / `.tls()`,
 then call `.send()` to execute — unlike `Client.request` / `request_url`, no
 I/O happens here. The time budget starts at DEFAULT_TIMEOUTS, matching every
 other entry point; `.timeout()` / `.timeouts()` adjust it.
*>
fn RequestBuilder request(Method method, String url) => { .method = method, .url = url, ._timeouts = DEFAULT_TIMEOUTS };

<*
 Append a header. Returns the builder for chaining. Beyond MAX_HEADERS the
 builder is marked overflowed and `send` will fault.
*>
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

<*
 Override just the connect field of the budget, leaving the other three as they
 stand (0 = block indefinitely). Returns the builder for chaining.
*>
fn RequestBuilder* RequestBuilder.timeout(&self, Duration timeout)
{
	self._timeouts.connect = timeout;
	return self;
}

<*
 REPLACE the whole time budget — connect, per-read, per-write and total (0 =
 none for each) — dropping the builder's DEFAULT_TIMEOUTS starting point, so a
 partial literal such as `{ .read = 5 * time::SEC }` also drops the connect
 default (see the same caveat on DEFAULT_TIMEOUTS). That is also why
 `.timeout(d).timeouts(t)` and `.timeouts(t).timeout(d)` differ. Returns the
 builder for chaining.
*>
fn RequestBuilder* RequestBuilder.timeouts(&self, Timeouts timeouts)
{
	self._timeouts = timeouts;
	return self;
}

<*
 Set the TLS configuration used for an https:// URL (ignored for http://).
 Returns the builder for chaining.
*>
fn RequestBuilder* RequestBuilder.tls(&self, TlsConfig tls)
{
	self._tls = tls;
	return self;
}

<*
 Open a connection, send the request, and read the response. Faults with
 TOO_MANY_HEADERS if more than MAX_HEADERS headers were supplied.
*>
fn Response? RequestBuilder.send(&self, Allocator allocator = tmem)
{
	if (self._overflow) return TOO_MANY_HEADERS~;
	return request_url(
		self.method,
		self.url,
		self._headers[:self._count],
		self._body,
		self._timeouts,
		allocator,
		tls: self._tls
	);
}