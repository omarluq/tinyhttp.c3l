// The fluent RequestBuilder.
//
// `request(method, url)` returns an UNSENT builder: no I/O happens until send().
// Chain `.header()`, `.body()`, and `.timeout()` to configure it, then call
// `.send(allocator)` to open the connection, write the request, and read the
// response.

module examples::builder;
import tinyhttp;
import std::io;
import std::time;

fn void main()
{
    tinyhttp::RequestBuilder req = tinyhttp::request(tinyhttp::Method.POST, "http://httpbin.org/post");
    req.header("Content-Type", "text/plain")
       .header("User-Agent", "tinyhttp-builder/1.0")
       .body("hello from the builder")
       .timeout(5 * time::SEC);

    tinyhttp::Response? result = req.send(mem);
    if (catch err = result)
    {
        io::printfn("error: %s", err);
        return;
    }
    defer result.free();

    io::printfn("status:      %d", result.status);
    io::printfn("ok:          %s", result.ok());
    io::printfn("body length: %d", result.body.len);
}
