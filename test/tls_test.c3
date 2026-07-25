// TLS tests. The unit-level check proves the OpenSSL bindings link and the
// library initializes; the full handshake + certificate verification is
// exercised by the network-gated live test.
module tinyhttp;
import std::net;
import std::net::tcp;
import std::os::env;
import std::time;

// Links against system libssl/libcrypto and allocates + frees an SSL_CTX. No
// network — just proves the bindings resolve and OpenSSL is usable.
fn void test_openssl_links() @test
{
	SslCtx ctx = ssl_ctx_new(tls_client_method());
	assert(ctx != null);
	ssl_ctx_free(ctx);
}

// ip_literal classifies hosts: IP literals (including bracketed IPv6) select the
// iPAddress-SAN verification path with brackets stripped; hostnames fault so the
// SNI + hostname-check path is used instead.
fn void test_ip_literal() @test
{
	assert(ip_literal("127.0.0.1")!! == "127.0.0.1");
	assert(ip_literal("192.168.1.1")!! == "192.168.1.1");
	assert(ip_literal("::1")!! == "::1");
	assert(ip_literal("[::1]")!! == "::1"); // URL-form IPv6 unwrapped
	assert(ip_literal("[2001:db8::1]")!! == "2001:db8::1");
	assert(!@ok(ip_literal("example.com"))); // hostname -> fault
	assert(!@ok(ip_literal("localhost")));
}

// A zero-length read/write must return 0 without invoking OpenSSL, matching
// PlainConn's contract (SSL_write(num==0) would otherwise fault as TLS_FAILED).
// The 0-len guard returns before touching self.ssl, so a null-ssl conn is safe.
fn void test_zero_length_io() @test
{
	TlsConn tc   = { }; // ssl == null; guards short-circuit before any OpenSSL call
	char[] empty = { };
	assert(tc.write(empty)!! == 0);
	assert(tc.read(empty)!! == 0);
}

// A TLS session both ends of which live in this process, over a socketpair: no
// network, no certificate. Anonymous-DH (ADH) at security level 0 is what removes
// the certificate — it is a test-only cipher and nothing but this file selects it.
// The handshake is pumped by alternating the two sides, each with a short
// SO_RCVTIMEO, so a side that is waiting on the other simply yields its turn.
const CInt SSL_CTRL_SET_DH_AUTO @private           = 118;
const CInt SSL_CTRL_SET_MAX_PROTO_VERSION @private = 124;
const CLong TLS1_2_VERSION @private                = 0x0303;
const ZString ANON_CIPHER @private                 = "ADH-AES128-GCM-SHA256";

extern fn SslMethod tls_server_method() @cname("TLS_server_method") @private;
extern fn CLong ssl_ctx_ctrl(SslCtx ctx, CInt cmd, CLong larg, void* parg) @cname("SSL_CTX_ctrl") @private;
extern fn CInt ssl_ctx_set_cipher_list(SslCtx ctx, ZString list) @cname("SSL_CTX_set_cipher_list") @private;
extern fn void ssl_ctx_set_security_level(SslCtx ctx, CInt level) @cname("SSL_CTX_set_security_level") @private;
extern fn CInt ssl_accept(Ssl ssl) @cname("SSL_accept") @private;

// Cap a ctx at TLS 1.2 and offer only the anonymous cipher (TLS 1.3 has no
// certificate-less mode, hence the cap).
fn void anon_ctx(SslCtx ctx) @local
{
	ssl_ctx_set_security_level(ctx, 0);
	ssl_ctx_ctrl(ctx, SSL_CTRL_SET_MAX_PROTO_VERSION, TLS1_2_VERSION, null);
	ssl_ctx_ctrl(ctx, SSL_CTRL_SET_DH_AUTO, 1, null); // ADH still needs DH parameters
	assert(ssl_ctx_set_cipher_list(ctx, ANON_CIPHER) == 1, "this OpenSSL build has no %s", ANON_CIPHER);
}

// SSL_get_error consults the thread-local error queue *before* the SSL's own retry
// flags, so a stale entry (a rejected trust store, a handshake that failed
// verification and was retried, any unrelated OpenSSL use in the host program)
// would be reported as this call's error. Here the read can only end one way — the
// peer never writes and SO_RCVTIMEO fires — so with a dirty queue left unhandled
// the timeout is misread as SSL_ERROR_SYSCALL and surfaces as TLS_FAILED, which
// the reader would then take for a dead connection rather than a timeout.
fn void test_read_timeout_survives_dirty_error_queue() @test
{
	TcpSocketPair pair;
	pair.init()!!;
	defer (void)pair.destroy();

	SslCtx cctx = make_ctx({ .no_verify = true })!!;
	defer free_shared_ctx(cctx);
	anon_ctx(cctx);

	SslCtx sctx = ssl_ctx_new(tls_server_method());
	assert(sctx != null);
	defer free_shared_ctx(sctx);
	anon_ctx(sctx);

	Ssl client = ssl_new(cctx);
	Ssl server = ssl_new(sctx);
	assert(client != null && server != null);
	defer ssl_free(client);
	defer ssl_free(server);
	assert(ssl_set_fd(client, (CInt)pair.send.sock) == 1);
	assert(ssl_set_fd(server, (CInt)pair.recv.sock) == 1);
	set_fd_timeout(pair.send, os::SO_RCVTIMEO, 30 * time::MS)!!;
	set_fd_timeout(pair.recv, os::SO_RCVTIMEO, 30 * time::MS)!!;

	bool up, down;
	for (int i = 0; i < 40 && !(up && down); i++)
	{
		if (!up) up = ssl_connect(client) == 1;
		if (!down) down = ssl_accept(server) == 1;
	}
	assert(up && down, "anonymous handshake did not complete");

	TlsConn tc = { .sock = pair.send, .ctx = cctx, .ssl = client };
	// Push a real entry onto the queue, exactly as an earlier failure elsewhere would.
	assert(ssl_ctx_load_verify_locations(cctx, "/nonexistent/tinyhttp-ca.pem", null) != 1);

	char[64] buf;
	sz? n = tc.read(&buf); // the peer never writes: only SO_RCVTIMEO can end this
	if (catch err = n)
	{
		assert(err == READ_TIMEOUT, "got '%s'", err);
		return;
	}
	assert(false, "expected READ_TIMEOUT, read %d byte(s)", (int)n);
}

// Live end-to-end HTTPS round-trip: real handshake + certificate verification vs
// the system trust store, then a decrypted 200 response. Gated on TINYHTTP_LIVE
// (needs a network), so the default `compile-test` stays offline.
fn void test_https_live() @test
{
	if (catch env::tget_var("TINYHTTP_LIVE")) return; // skip unless explicitly enabled

	Response resp = get("https://example.com")!!;
	defer resp.free();
	assert(resp.status == 200);
	assert(resp.ok());
	assert(resp.body.len > 0);
}