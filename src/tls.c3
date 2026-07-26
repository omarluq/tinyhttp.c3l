// tinyhttp TLS transport — an https:// `Conn` backed by the system OpenSSL
// (libssl/libcrypto, named in manifest.json's `linked-libraries`). OpenSSL is
// bound directly as opaque handles — no C shim, no vendored binary, no headers
// in the repo — which is the idiomatic c3c-library shape (cf. `sqlite3.c3l`
// naming its system lib rather than bundling one).

module tinyhttp;
import std::io;
import std::net;
import std::net::tcp;
import std::time;

faultdef
	TLS_FAILED, // TLS setup, read, or write failed
	TLS_HANDSHAKE_FAILED; // TLS handshake or certificate verification failed

// ---- OpenSSL bindings (the library heap-allocates every handle) ------------

typedef SslMethod @private = inline void*; // const SSL_METHOD*
typedef SslCtx @private = inline void*; // SSL_CTX*
typedef Ssl @private = inline void*; // SSL*
typedef X509VerifyParam @private = inline void*; // X509_VERIFY_PARAM*

const CInt SSL_VERIFY_NONE @private              = 0x00;
const CInt SSL_VERIFY_PEER @private              = 0x01;
const CInt SSL_CTRL_SET_TLSEXT_HOSTNAME @private = 55;
const CLong TLSEXT_NAMETYPE_HOST_NAME @private   = 0;
const CInt SSL_ERROR_WANT_READ @private          = 2;
const CInt SSL_ERROR_WANT_WRITE @private         = 3;
const CInt SSL_ERROR_SYSCALL @private            = 5;
const CInt SSL_ERROR_ZERO_RETURN @private        = 6;
const CLong X509_V_OK @private                   = 0;

// On a blocking socket WANT_READ/WANT_WRITE can only mean SO_RCVTIMEO/SO_SNDTIMEO
// fired (an SSL_read may want to write mid-renegotiation and vice versa; either way
// it was a timeout). Each call site maps that to its own timeout fault.
fn bool ssl_want_io(CInt err) @private => err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE;

// Bound on the close_notify write in `TlsConn.close`; see there for why teardown
// carries its own budget instead of inheriting the request's `Timeouts`.
const Duration SHUTDOWN_TIMEOUT @private = (Duration)5_000_000;

extern fn SslMethod tls_client_method() @cname("TLS_client_method") @private;
extern fn SslCtx ssl_ctx_new(SslMethod method) @cname("SSL_CTX_new") @private;
extern fn void ssl_ctx_free(SslCtx ctx) @cname("SSL_CTX_free") @private;
extern fn void ssl_ctx_set_verify(SslCtx ctx, CInt mode, void* callback) @cname("SSL_CTX_set_verify") @private;
extern fn CInt ssl_ctx_set_default_verify_paths(SslCtx ctx) @cname("SSL_CTX_set_default_verify_paths") @private;
extern fn CInt ssl_ctx_load_verify_locations(
	SslCtx ctx,
	ZString ca_file,
	ZString ca_path
) @cname("SSL_CTX_load_verify_locations") @private;
extern fn Ssl ssl_new(SslCtx ctx) @cname("SSL_new") @private;
extern fn void ssl_free(Ssl ssl) @cname("SSL_free") @private;
extern fn CInt ssl_set_fd(Ssl ssl, CInt fd) @cname("SSL_set_fd") @private;
extern fn CInt ssl_set1_host(Ssl ssl, ZString host) @cname("SSL_set1_host") @private;
extern fn X509VerifyParam ssl_get0_param(Ssl ssl) @cname("SSL_get0_param") @private;
extern fn CInt x509_verify_param_set1_ip_asc(
	X509VerifyParam param,
	ZString ipasc
) @cname("X509_VERIFY_PARAM_set1_ip_asc") @private;
extern fn CLong ssl_ctrl(Ssl ssl, CInt cmd, CLong larg, void* parg) @cname("SSL_ctrl") @private;
extern fn CInt ssl_connect(Ssl ssl) @cname("SSL_connect") @private;
extern fn CLong ssl_get_verify_result(Ssl ssl) @cname("SSL_get_verify_result") @private;
extern fn CInt ssl_read(Ssl ssl, void* buf, CInt num) @cname("SSL_read") @private;
extern fn CInt ssl_write(Ssl ssl, void* buf, CInt num) @cname("SSL_write") @private;
extern fn CInt ssl_shutdown(Ssl ssl) @cname("SSL_shutdown") @private;
extern fn CInt ssl_get_error(Ssl ssl, CInt ret) @cname("SSL_get_error") @private;
extern fn void err_clear_error() @cname("ERR_clear_error") @private;

// ---- public config ---------------------------------------------------------

<*
 TLS options. By default the server certificate chain and hostname are verified
 against OpenSSL's default trust store. Set `no_verify` to disable verification
 (insecure), or set `ca_file`/`ca_path` to override the trust source.
*>
struct TlsConfig
{
	bool no_verify;
	String ca_file;
	String ca_path;
}

// ---- TlsConn ---------------------------------------------------------------

<*
 A TLS connection: a TCP socket with an OpenSSL session layered on top.
 Implements the same `Conn` seam as `PlainConn`, so nothing above the transport
 layer changes. `owns_ctx` is true only for a one-shot conn that built its own
 `ctx`; pooled conns share a Client-owned ctx and leave it for the Client to free.
*>
struct TlsConn (Conn)
{
	TcpSocket sock;
	SslCtx ctx;
	Ssl ssl;
	bool owns_ctx;
}

<*
 Clamp a slice length to what SSL_read/SSL_write's `num` parameter can carry.
 A buffer past `CInt::max` would truncate to 0 or a negative num, and OpenSSL
 would fault an otherwise valid transfer; clamping makes it a short read/write
 instead, which both call sites already loop on. PlainConn has no equivalent
 narrowing (libc recv/send take a usz), so this keeps the `Conn` seam uniform.
*>
fn CInt ssl_chunk_len(usz len) @private => len > (usz)CInt::max ? CInt::max : (CInt)len;

fn sz? TlsConn.read(&self, char[] buf) @dynamic
{
	if (buf.len == 0) return 0; // honor the same 0-byte contract as PlainConn/recv
	err_clear_error(); // SSL_get_error reads the thread-local queue first, so it must hold only this call's error
	CInt n = ssl_read(self.ssl, (void*)buf.ptr, ssl_chunk_len(buf.len));
	if (n > 0) return (sz)n;
	// 0 / negative: distinguish EOF (clean close, or the peer just closed TCP)
	// from a genuine protocol error. The queue was emptied above, so what
	// SSL_get_error reports here belongs to this ssl_read and nothing else —
	// which is what the READ_TIMEOUT and benign-EOF arms below depend on.
	CInt err = ssl_get_error(self.ssl, n);
	if (err == SSL_ERROR_ZERO_RETURN) return 0; // clean close_notify
	if (ssl_want_io(err)) return READ_TIMEOUT~;
	// SSL_ERROR_SYSCALL with n == 0 is a peer TCP close without close_notify
	// (benign EOF); n < 0 is a genuine syscall failure and must surface.
	if (err == SSL_ERROR_SYSCALL) return n == 0 ? 0 : TLS_FAILED~;
	return TLS_FAILED~;
}

fn sz? TlsConn.write(&self, char[] buf) @dynamic
{
	if (buf.len == 0) return 0; // SSL_write(num==0) returns <=0; match PlainConn's 0-byte contract
	err_clear_error(); // as in read: SSL_get_error below must see only this call's error
	CInt n = ssl_write(self.ssl, (void*)buf.ptr, ssl_chunk_len(buf.len));
	if (n > 0) return (sz)n;
	CInt err = ssl_get_error(self.ssl, n);
	if (ssl_want_io(err)) return WRITE_TIMEOUT~;
	// No ZERO_RETURN/SYSCALL arms to mirror read's: n == 0 out of SSL_write means
	// "no progress", not a clean EOF, and write_all_deadline maps that to
	// INCOMPLETE_WRITE — reporting it as a successful 0-byte write would hide it.
	return TLS_FAILED~;
}

fn char? TlsConn.read_byte(&self) @dynamic => io::read_byte_using_read(self);
fn void? TlsConn.write_byte(&self, char c) @dynamic => io::write_byte_using_write(self, c);

<*
 Tear the connection down: send close_notify, free the SSL (and the ctx when this
 conn owns it), then close the socket. The close_notify write is bounded by a
 fixed short budget (`SHUTDOWN_TIMEOUT`) independent of the request's `Timeouts`,
 so closing a wedged peer cannot block indefinitely.
*>
fn void? TlsConn.close(&self) @dynamic
{
	if (self.ssl != null)
	{
		// Teardown must not inherit whatever SO_SNDTIMEO the request loop left armed
		// (or none at all, which is what dial hands back): SSL_shutdown writes
		// close_notify, a blocking socket write that a peer with a closed receive
		// window stalls forever. Best-effort, so the arming fault is dropped.
		(void)set_fd_timeout(self.sock, os::SO_SNDTIMEO, SHUTDOWN_TIMEOUT);
		ssl_shutdown(self.ssl);
		ssl_free(self.ssl);
		self.ssl = (Ssl)null;
	}
	if (self.owns_ctx && self.ctx != null)
	{
		ssl_ctx_free(self.ctx);
		self.ctx = (SslCtx)null;
	}
	return self.sock.close();
}

// SO_RCVTIMEO/SO_SNDTIMEO sit below TLS, so the plain helper arms a TLS socket too.
fn void? TlsConn.set_read_timeout(&self, Duration d) @dynamic => set_fd_timeout(self.sock, os::SO_RCVTIMEO, d);
fn void? TlsConn.set_write_timeout(&self, Duration d) @dynamic => set_fd_timeout(self.sock, os::SO_SNDTIMEO, d);

// ---- dial ------------------------------------------------------------------

<*
 Build a client `SSL_CTX` from `config`: method + verify mode + trust store.
 An `SSL_CTX` is meant to be long-lived and shared across many short-lived SSL
 sessions, so build it once and reuse it; the caller owns the returned handle
 and must `ssl_ctx_free` it once every SSL layered over it is gone.
*>
fn SslCtx? make_ctx(TlsConfig config) @private
{
	bool verify = !config.no_verify;

	SslCtx ctx = ssl_ctx_new(tls_client_method());
	if (ctx == null) return TLS_FAILED~;
	defer catch ssl_ctx_free(ctx);

	if (verify)
	{
		ssl_ctx_set_verify(ctx, SSL_VERIFY_PEER, null);
		if (config.ca_file.len != 0 || config.ca_path.len != 0)
		{
			ZString cf = config.ca_file.len != 0 ? config.ca_file.zstr_tcopy() : null;
			ZString cp = config.ca_path.len != 0 ? config.ca_path.zstr_tcopy() : null;
			if (ssl_ctx_load_verify_locations(ctx, cf, cp) != 1) return TLS_FAILED~;
		}
		else
		{
			if (ssl_ctx_set_default_verify_paths(ctx) != 1) return TLS_FAILED~;
		}
	}
	else
	{
		ssl_ctx_set_verify(ctx, SSL_VERIFY_NONE, null);
	}
	return ctx;
}

<*
 Free a shared `SSL_CTX` built by `make_ctx`, tolerating null. Mirrors `make_ctx`
 so the raw OpenSSL teardown stays confined to this transport file; the caller
 invokes it once every SSL layered over the ctx is gone.
*>
fn void free_shared_ctx(SslCtx ctx) @private
{
	if (ctx != null) ssl_ctx_free(ctx);
}

<*
 If `host` is an IP literal, return the bare IP text (IPv6 brackets stripped) for
 `X509_VERIFY_PARAM_set1_ip_asc`; otherwise fault. Lets `dial_tls_ctx` verify an
 `https://<ip>/` peer against the certificate's iPAddress SAN rather than a
 hostname, which OpenSSL only matches against dNSName SANs / CN.
*>
fn String? ip_literal(String host) @private
{
	String s = host;
	if (s.len >= 2 && s[0] == '[' && s[^1] == ']') s = s[1..^2]; // [::1] -> ::1
	if (try net::ipv4_from_str(s)) return s;
	net::ipv6_from_str(s)!; // rethrows INVALID_IP_STRING when host is not an IP literal
	return s;
}

<*
 Open a TLS connection to host:port over a pre-built shared `ctx` and perform the
 handshake (SNI = host, hostname verified when `verify`). The SNI/hostname checks
 are per-SSL, so the ctx is safely shared. The returned TlsConn does NOT own `ctx`
 (owns_ctx = false): the caller keeps `ctx` alive for the connection's lifetime and
 frees it after every SSL over it is gone. `timeouts.connect` bounds the TCP
 connect and the TLS handshake.
*>
fn TlsConn? dial_tls_ctx(SslCtx ctx, bool verify, String host, int port, Timeouts timeouts = DEFAULT_TIMEOUTS) @private
{
	// Reuse the plain dial for the TCP connect (timeout, TCP_NODELAY, fault map).
	PlainConn pc   = dial(host, port, timeouts)!;
	TcpSocket sock = pc.sock;
	defer catch (void)sock.close();

	Ssl ssl = ssl_new(ctx);
	if (ssl == null) return TLS_FAILED~;
	defer catch ssl_free(ssl);

	if (ssl_set_fd(ssl, (CInt)sock.sock) != 1) return TLS_FAILED~;

	if (try String ip = ip_literal(host))
	{
		// IP literal: OpenSSL's X509_check_host never matches an IP against a
		// dNSName SAN or CN, so verify against the cert's iPAddress SAN instead,
		// and skip SNI entirely (RFC 6066 forbids an IP-literal server name).
		if (verify && x509_verify_param_set1_ip_asc(ssl_get0_param(ssl), ip.zstr_tcopy()) != 1)
		{
			return TLS_HANDSHAKE_FAILED~;
		}
	}
	else
	{
		ZString host_z = host.zstr_tcopy();
		if (ssl_ctrl(
			ssl,
			SSL_CTRL_SET_TLSEXT_HOSTNAME,
			TLSEXT_NAMETYPE_HOST_NAME,
			(void*)host_z
		) != 1) return TLS_HANDSHAKE_FAILED~; // SNI
		if (verify && ssl_set1_host(ssl, host_z) != 1) return TLS_HANDSHAKE_FAILED~; // hostname check
	}

	// Bound the handshake with the same mechanism: without this a peer that accepts
	// TCP and never speaks TLS hangs ssl_connect forever, even with a connect timeout.
	set_fd_timeout(sock, os::SO_RCVTIMEO, timeouts.connect)!;
	set_fd_timeout(sock, os::SO_SNDTIMEO, timeouts.connect)!;
	// Same rule as read/write, and placed here rather than earlier because every
	// call above returns on its own failure — their queue entries are never fed to
	// an ssl_get_error, and only this handshake's are.
	err_clear_error();
	CInt rc = ssl_connect(ssl);
	if (rc != 1)
	{
		// SSL_get_error branches on the exact return of the call that failed, so
		// forward `rc` rather than a literal: 0 keeps the ZERO_RETURN classification
		// available, < 0 is the retry/syscall case.
		CInt herr = ssl_get_error(ssl, rc);
		if (ssl_want_io(herr)) return CONNECT_TIMEOUT~;
		return TLS_HANDSHAKE_FAILED~;
	}
	if (verify && ssl_get_verify_result(ssl) != X509_V_OK) return TLS_HANDSHAKE_FAILED~;

	// Hand the socket back unarmed. The connect budget bounds the handshake only, and
	// the reader's memo starts at zero meaning "not armed", so leaving the handshake
	// value in place would silently impose it on every read of the transfer.
	set_fd_timeout(sock, os::SO_RCVTIMEO, time::DURATION_ZERO)!;
	set_fd_timeout(sock, os::SO_SNDTIMEO, time::DURATION_ZERO)!;

	return { .sock = sock, .ctx = ctx, .ssl = ssl, .owns_ctx = false };
}

<*
 Open a TLS connection to host:port and perform the handshake (SNI = host,
 hostname verified). Builds a private `SSL_CTX` owned by the returned conn, so it
 is self-contained for one-shot use; the Client keep-alive path shares one ctx via
 `make_ctx` + `dial_tls_ctx`. `timeouts.connect` bounds the TCP connect and the
 handshake (0 = block indefinitely); the socket is handed back unarmed.
*>
fn TlsConn? dial_tls(String host, int port, TlsConfig config = { }, Timeouts timeouts = DEFAULT_TIMEOUTS)
{
	SslCtx ctx = make_ctx(config)!;
	defer catch ssl_ctx_free(ctx);

	TlsConn tc = dial_tls_ctx(ctx, !config.no_verify, host, port, timeouts)!;
	tc.owns_ctx = true;
	return tc;
}