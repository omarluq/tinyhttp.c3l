// A reusable HTTP client: a base URL, default headers, and a connection timeout,
// applied to every request. (Increment 1's one-connection-per-request transport
// still applies.)

module tinyhttp;
import std::time;

<* Configuration reused across requests. `base_url` is prepended to each path,
   `default_headers` are merged into every request (before the per-call headers),
   and `timeout` bounds the connect (0 = none). *>
struct Client
{
    Allocator allocator;
    String    base_url;
    Header[]  default_headers;
    Duration  timeout;
}

<* Create a client. *>
fn Client client(Allocator allocator, String base_url = "", Header[] default_headers = {}, Duration timeout = {})
    => { .allocator = allocator, .base_url = base_url, .default_headers = default_headers, .timeout = timeout };

<* Perform `method` on base_url+path, merging the default headers with `headers`
   (default headers first; up to MAX_HEADERS total). *>
fn Response? Client.request(&self, Method method, String path, Header[] headers = {}, char[] body = {})
{
    String url = self.base_url.len != 0 ? string::tformat("%s%s", self.base_url, path) : path;

    Header[MAX_HEADERS] merged;
    usz m = 0;
    foreach (h : self.default_headers) if (m < MAX_HEADERS) { merged[m] = h; m++; }
    foreach (h : headers) if (m < MAX_HEADERS) { merged[m] = h; m++; }

    return request_url(self.allocator, method, url, merged[:m], body, self.timeout);
}

fn Response? Client.get(&self, String path, Header[] headers = {})
    => self.request(GET, path, headers);
fn Response? Client.head(&self, String path, Header[] headers = {})
    => self.request(HEAD, path, headers);
fn Response? Client.delete(&self, String path, Header[] headers = {})
    => self.request(DELETE, path, headers);
fn Response? Client.post(&self, String path, char[] body, Header[] headers = {})
    => self.request(POST, path, headers, body);
fn Response? Client.put(&self, String path, char[] body, Header[] headers = {})
    => self.request(PUT, path, headers, body);
fn Response? Client.patch(&self, String path, char[] body, Header[] headers = {})
    => self.request(PATCH, path, headers, body);
