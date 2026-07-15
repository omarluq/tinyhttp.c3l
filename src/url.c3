// URL resolution for the convenience wrappers: parse an http:// or https:// URL
// string into the pieces a request needs — the connect Url, the RFC 7230 §5.4
// Host header value, the request-target, the resolved port and the scheme flag.

module tinyhttp;
import std::net::url;

<*
 The resolved pieces of a request URL: the connect `Url`, the RFC 7230 §5.4
 Host header value, the request-target, the resolved connect port and whether
 the scheme is https.
*>
struct RequestTarget @private
{
	Url url;
	String host_hdr;
	String target;
	int port;
	bool is_https;
}

<*
 Parse `url_str` (must be http:// or https://) into a `RequestTarget`: the connect
 `Url`, the RFC 7230 §5.4 Host header value (host, plus non-default port), the
 request-target (percent-re-encoded path + raw query), the resolved connect port
 (explicit port, else the scheme default) and the is_https flag.
*>
fn RequestTarget? make_request_target(String url_str) @private
{
	Url u         = url::parse(tmem, url_str) ?? INVALID_URL~!; // maps url faults (incl. EMPTY on "") to INVALID_URL
	bool is_https = ci_eq(u.scheme, "https");
	if (!is_https && !ci_eq(u.scheme, "http")) return UNSUPPORTED_SCHEME~;
	int default_port = is_https ? DEFAULT_HTTPS_PORT : DEFAULT_HTTP_PORT;
	int port         = u.port ?: default_port;
	String host_hdr  = port == default_port ? u.host : string::tformat("%s:%d", u.host, port);
	String path      = u.path.len != 0 ? url::tencode(u.path, url::UrlEncodingMode.PATH) : "/"; // re-encode path
	if (u.query.len != 0) path = string::tformat("%s?%s", path, u.query); // query left un-decoded by url::parse
	return { .url = u, .host_hdr = host_hdr, .target = path, .port = port, .is_https = is_https };
}