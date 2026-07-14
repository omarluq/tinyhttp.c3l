// The HTTP response value.

module tinyhttp;

<* A parsed HTTP response. Owns a single backing buffer (`raw`); `headers` and
   `body` are slices into it, so the whole response is one allocation plus the
   header array. Release with `defer resp.free()`. *>
struct Response
{
    int       status;
    int       minor_version;
    Header[]  headers;     // name/value slices into `raw`
    char[]    body;        // slice into `raw` (dechunked in place if needed)
    char[]    raw;         // owned backing buffer
    Allocator allocator;
}

<* True for a 2xx status. *>
fn bool Response.ok(&self) => self.status >= 200 && self.status < 300;

<* Case-insensitive lookup of a header value, or an empty string if absent. *>
fn String Response.header(&self, String name) => find_header(self.headers, name);

<* True if a header named `name` is present (case-insensitive), even when its
   value is empty. Distinguishes absent from present-but-empty, which
   `header` (empty-string sentinel) cannot. *>
fn bool Response.has_header(&self, String name) => has_header(self.headers, name);

<* Free the backing buffer and header array. Idempotent (null-safe + self-reset). *>
fn void Response.free(&self)
{
    alloc::free(self.allocator, self.raw.ptr);
    alloc::free(self.allocator, self.headers.ptr);
    *self = {};
}
