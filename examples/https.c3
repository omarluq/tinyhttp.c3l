// GET over https://.
//
// The scheme alone selects the TLS transport. By default the server certificate
// chain and the hostname are verified against the system trust store, so no
// TlsConfig is needed for a normal, trusted site.

module examples::https;
import tinyhttp;
import std::io;

fn void main()
{
    tinyhttp::Response? result = tinyhttp::get("https://example.com/");
    if (catch err = result)
    {
        io::printfn("error: %s", err);
        return;
    }
    defer result.free();

    io::printfn("status: %d", result.status);

    // Print the first stretch of the body, guarding against a short response.
    usz n = result.body.len < 200 ? result.body.len : 200;
    io::printfn("body (first %d bytes):\n%s", n, (String)result.body[:n]);
}
