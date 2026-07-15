# tinyhttp

A tiny and versatile HTTP/1.1 client for the [C3](https://c3-lang.org) language.

## Install

Drop `tinyhttp.c3l` into your project's library path and add `tinyhttp` to the
`dependencies` in your `project.json`, then `import tinyhttp;`.

## Quick start (GET)

Get a URL, check the status, and read the body. A `Response` owns one backing
buffer, so free it with `defer resp.free()`.

```c3
import std::io;
import tinyhttp;

fn void main()
{
    Response? resp = tinyhttp::get("https://example.com");
    if (catch err = resp)
    {
        io::printfn("request failed: %s", err);
        return;
    }
    defer resp.free();

    io::printfn("status: %d", resp.status);
    if (resp.ok()) io::printn((String)resp.body);
}
```

## POST with a body and a header

```c3
Header[1] headers = { { .name = "Content-Type", .value = "application/json" } };

Response? resp = tinyhttp::post("https://httpbin.org/post", `{"name": "ada"}`, headers[..]);
if (catch err = resp) return;
defer resp.free();

io::printfn("status: %d", resp.status);
```

## Reusable Client

A `Client` holds a base URL, default headers, and a connect timeout, and applies
them to every call. A per-call header of the same name overrides a default.

```c3
Header[1] defaults = { { .name = "Accept", .value = "application/json" } };
Client client = tinyhttp::client(mem, "https://api.github.com", defaults[..]);

Response? user = client.get("/users/octocat");
if (catch err = user) return;
defer user.free();
io::printfn("status: %d", user.status);

// The same client is reused for the next call.
Response? repos = client.get("/users/octocat/repos");
if (catch err = repos) return;
defer repos.free();
```

## Fluent builder

Chain the request, then `send`.

```c3
Response? resp = tinyhttp::request(Method.POST, "https://example.com/submit")
    .header("Content-Type", "application/json")
    .body(`{"ok": true}`)
    .send(mem);
if (catch err = resp) return;
defer resp.free();
```

## HTTPS

HTTPS links against the system OpenSSL (`libssl` and `libcrypto`), so those must
be installed. tinyhttp already names them for `linux-x64` in its manifest. On
other setups, pass the flags to your linker yourself, for example
`-l ssl -l crypto`.

## Allocators

Every entry point takes the allocator as a trailing argument that defaults to
`tmem` (the temporary allocator), so the examples above need no explicit
allocator. When a response must outlive the current scope, pass an explicit
allocator (for example the heap allocator `mem`) as the last argument:

```c3
Response? resp = tinyhttp::get("https://example.com", allocator: mem);
```

## Errors

Results are C3 optionals (`Response?`). Handle them with `if (catch err = ...)`:

```c3
Response? resp = tinyhttp::get("https://example.com");
if (catch err = resp)
{
    // err is one of tinyhttp's faults: CONNECT_FAILED, TIMEOUT, DNS_FAILED,
    // MALFORMED_RESPONSE, TLS_HANDSHAKE_FAILED, and so on.
    return;
}
defer resp.free();
```

## License

[MIT](LICENSE).
