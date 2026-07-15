// A reusable Client: a base URL plus default headers applied to every call.
// 
// The client holds configuration (allocator, base_url, default headers) and a
// keep-alive connection pool, so the two calls below reuse a single TCP
// connection instead of dialing twice. A per-call header of the same name
// overrides a default; otherwise the defaults are merged in. Because the client
// owns pooled sockets, close() must be called when it is done with.

module examples::client;
import tinyhttp;
import std::io;

fn void main()
{
	// Default headers sent on every request made through this client.
	tinyhttp::Header[1] defaults = {
		{ .name = "User-Agent", .value = "tinyhttp-example/1.0" },
	};

	// `mem` (the heap allocator) owns the responses, so each is freed explicitly.
	tinyhttp::Client http = tinyhttp::client(mem, "http://example.com", defaults[..]);
	defer http.close(); // releases the pooled keep-alive sockets the client owns

	// First call: base_url + "/" with the default User-Agent merged in.
	tinyhttp::Response? first = http.get("/");
	if (catch err = first)
	{
		io::printfn("error: %s", err);
		return;
	}
	defer first.free();
	io::printfn("GET /           -> %d (%d bytes)", first.status, first.body.len);

	// Second call through the same client, reusing base_url and defaults.
	tinyhttp::Response? second = http.get("/index.html");
	if (catch err = second)
	{
		io::printfn("error: %s", err);
		return;
	}
	defer second.free();
	io::printfn("GET /index.html -> %d (%d bytes)", second.status, second.body.len);
}