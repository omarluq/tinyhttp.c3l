// Basic GET over http://.
//
// The convenience `get` opens a connection, sends "GET /", reads the whole
// response, then closes. With no allocator argument the response is backed by
// the temp allocator (tmem), which is fine for a short-lived program like this.

module examples::get;
import tinyhttp;
import std::io;

fn void main()
{
    tinyhttp::Response? result = tinyhttp::get("http://example.com/");
    if (catch err = result)
    {
        io::printfn("error: %s", err);
        return;
    }
    // Past the catch, `result` is unwrapped to a Response for the rest of scope.
    defer result.free();

    io::printfn("status:      %d", result.status);
    io::printfn("ok:          %s", result.ok());
    io::printfn("server:      %s", result.header("Server"));
    io::printfn("body length: %d", result.body.len);
}
