// Custom request headers, and reading response headers back.
//
// The request carries two custom headers. On the way back, `header()` looks a
// value up case-insensitively (empty string when absent), while `has_header()`
// reports presence, which tells an absent header apart from a present but empty
// one.

module examples::headers;
import tinyhttp;
import std::io;

fn void main()
{
    tinyhttp::Header[2] headers = {
        { .name = "Accept",          .value = "application/json" },
        { .name = "X-Example-Trace", .value = "abc123" },
    };

    tinyhttp::Response? result = tinyhttp::get("http://httpbin.org/get", headers[..]);
    if (catch err = result)
    {
        io::printfn("error: %s", err);
        return;
    }
    defer result.free();

    io::printfn("status: %d", result.status);

    // Read several response headers back by name.
    io::printfn("Content-Type:   %s", result.header("Content-Type"));
    io::printfn("Content-Length: %s", result.header("Content-Length"));
    io::printfn("Server:         %s", result.header("Server"));

    // has_header distinguishes absent from present-but-empty.
    if (result.has_header("Date"))
    {
        io::printfn("Date present:   %s", result.header("Date"));
    }
    else
    {
        io::printfn("Date present:   no");
    }
}
