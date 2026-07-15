// POST a JSON body with an explicit Content-Type header.
// 
// The body is passed as bytes; Content-Length is filled in automatically from
// its length, so only Content-Type has to be supplied here. A backtick raw
// string keeps the JSON readable (no escaped quotes).

module examples::post_json;
import tinyhttp;
import std::io;

fn void main()
{
	String payload = `{"name": "tinyhttp", "stars": 42}`;

	tinyhttp::Header[1] headers = {
		{ .name = "Content-Type", .value = "application/json" },
	};

	tinyhttp::Response? result = tinyhttp::post("http://httpbin.org/post", payload, headers[..]);
	if (catch err = result)
	{
		io::printfn("error: %s", err);
		return;
	}
	defer result.free();

	io::printfn("status:       %d", result.status);
	io::printfn("ok:           %s", result.ok());
	io::printfn("content-type: %s", result.header("Content-Type"));
	io::printfn("body length:  %d", result.body.len);
}