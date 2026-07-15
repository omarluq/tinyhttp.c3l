// TLS tests. The unit-level check proves the OpenSSL bindings link and the
// library initializes; the full handshake + certificate verification is
// exercised by the network-gated live test.
module tinyhttp;
import std::os::env;

// Links against system libssl/libcrypto and allocates + frees an SSL_CTX. No
// network — just proves the bindings resolve and OpenSSL is usable.
fn void test_openssl_links() @test
{
    SslCtx ctx = ssl_ctx_new(tls_client_method());
    assert(ctx != null);
    ssl_ctx_free(ctx);
}

// Live end-to-end HTTPS round-trip: real handshake + certificate verification vs
// the system trust store, then a decrypted 200 response. Gated on TINYHTTP_LIVE
// (needs a network), so the default `compile-test` stays offline.
fn void test_https_live() @test
{
    if (catch env::tget_var("TINYHTTP_LIVE")) return;   // skip unless explicitly enabled

    Response resp = get("https://example.com")!!;
    defer resp.free();
    assert(resp.status == 200);
    assert(resp.ok());
    assert(resp.body.len > 0);
}
