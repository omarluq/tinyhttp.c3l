// tinyhttp TLS transport — an https:// `Conn` backed by the system OpenSSL
// (libssl/libcrypto, named in manifest.json's `linked-libraries`). OpenSSL is
// bound directly as opaque handles — no C shim, no vendored binary, no headers
// in the repo — which is the idiomatic c3c-library shape (cf. `sqlite3.c3l`
// naming its system lib rather than bundling one).

module tinyhttp;
import std::io;
import std::net::tcp;
import std::time;

// ---- OpenSSL bindings (the library heap-allocates every handle) ------------

typedef SslMethod @private = inline void*;   // const SSL_METHOD*
typedef SslCtx    @private = inline void*;   // SSL_CTX*
typedef Ssl       @private = inline void*;   // SSL*

const CInt  SSL_VERIFY_NONE              @private = 0x00;
const CInt  SSL_VERIFY_PEER              @private = 0x01;
const CInt  SSL_CTRL_SET_TLSEXT_HOSTNAME @private = 55;
const CLong TLSEXT_NAMETYPE_HOST_NAME    @private = 0;
const CInt  SSL_ERROR_SYSCALL            @private = 5;
const CInt  SSL_ERROR_ZERO_RETURN        @private = 6;
const CLong X509_V_OK                    @private = 0;

extern fn SslMethod tls_client_method() @cname("TLS_client_method") @private;
extern fn SslCtx    ssl_ctx_new(SslMethod method) @cname("SSL_CTX_new") @private;
extern fn void      ssl_ctx_free(SslCtx ctx) @cname("SSL_CTX_free") @private;
extern fn void      ssl_ctx_set_verify(SslCtx ctx, CInt mode, void* callback) @cname("SSL_CTX_set_verify") @private;
extern fn CInt      ssl_ctx_set_default_verify_paths(SslCtx ctx) @cname("SSL_CTX_set_default_verify_paths") @private;
extern fn CInt      ssl_ctx_load_verify_locations(SslCtx ctx, ZString ca_file, ZString ca_path) @cname("SSL_CTX_load_verify_locations") @private;
extern fn Ssl       ssl_new(SslCtx ctx) @cname("SSL_new") @private;
extern fn void      ssl_free(Ssl ssl) @cname("SSL_free") @private;
extern fn CInt      ssl_set_fd(Ssl ssl, CInt fd) @cname("SSL_set_fd") @private;
extern fn CInt      ssl_set1_host(Ssl ssl, ZString host) @cname("SSL_set1_host") @private;
extern fn CLong     ssl_ctrl(Ssl ssl, CInt cmd, CLong larg, void* parg) @cname("SSL_ctrl") @private;
extern fn CInt      ssl_connect(Ssl ssl) @cname("SSL_connect") @private;
extern fn CLong     ssl_get_verify_result(Ssl ssl) @cname("SSL_get_verify_result") @private;
extern fn CInt      ssl_read(Ssl ssl, void* buf, CInt num) @cname("SSL_read") @private;
extern fn CInt      ssl_write(Ssl ssl, void* buf, CInt num) @cname("SSL_write") @private;
extern fn CInt      ssl_shutdown(Ssl ssl) @cname("SSL_shutdown") @private;
extern fn CInt      ssl_get_error(Ssl ssl, CInt ret) @cname("SSL_get_error") @private;

// ---- public config ---------------------------------------------------------

<* TLS options. By default the server certificate chain and hostname are verified
   against OpenSSL's default trust store. Set `no_verify` to disable verification
   (insecure), or set `ca_file`/`ca_path` to override the trust source. *>
struct TlsConfig
{
    bool   no_verify;
    String ca_file;
    String ca_path;
}

// ---- TlsConn ---------------------------------------------------------------

<* A TLS connection: a TCP socket with an OpenSSL session layered on top.
   Implements the same `Conn` seam as `PlainConn`, so nothing above the transport
   layer changes. *>
struct TlsConn (Conn)
{
    TcpSocket sock;
    SslCtx    ctx;
    Ssl       ssl;
}

fn sz? TlsConn.read(&self, char[] buf) @dynamic
{
    CInt n = ssl_read(self.ssl, (void*)buf.ptr, (CInt)buf.len);
    if (n > 0) return (sz)n;
    // 0 / negative: distinguish EOF (clean close, or the peer just closed TCP)
    // from a genuine protocol error.
    CInt err = ssl_get_error(self.ssl, n);
    if (err == SSL_ERROR_ZERO_RETURN) return 0;                    // clean close_notify
    // SSL_ERROR_SYSCALL with n == 0 is a peer TCP close without close_notify
    // (benign EOF); n < 0 is a genuine syscall failure and must surface.
    if (err == SSL_ERROR_SYSCALL) return n == 0 ? 0 : TLS_FAILED~;
    return TLS_FAILED~;
}

fn sz? TlsConn.write(&self, char[] buf) @dynamic
{
    CInt n = ssl_write(self.ssl, (void*)buf.ptr, (CInt)buf.len);
    if (n > 0) return (sz)n;
    return TLS_FAILED~;
}

fn char? TlsConn.read_byte(&self) @dynamic => io::read_byte_using_read(self);
fn void? TlsConn.write_byte(&self, char c) @dynamic => io::write_byte_using_write(self, c);

fn void? TlsConn.close(&self) @dynamic
{
    if (self.ssl != null) { ssl_shutdown(self.ssl); ssl_free(self.ssl); self.ssl = (Ssl)null; }
    if (self.ctx != null) { ssl_ctx_free(self.ctx); self.ctx = (SslCtx)null; }
    return self.sock.close();
}

// ---- dial ------------------------------------------------------------------

<* Open a TLS connection to host:port and perform the handshake (SNI = host,
   hostname verified). `timeout` bounds the TCP connect (0 = block indefinitely). *>
fn TlsConn? dial_tls(String host, int port, TlsConfig config = {}, Duration timeout = time::DURATION_ZERO)
{
    // Reuse the plain dial for the TCP connect (timeout, TCP_NODELAY, fault map).
    PlainConn pc = dial(host, port, timeout)!;
    TcpSocket sock = pc.sock;
    defer catch (void)sock.close();

    SslCtx ctx = ssl_ctx_new(tls_client_method());
    if (ctx == null) return TLS_FAILED~;
    defer catch ssl_ctx_free(ctx);

    if (config.no_verify)
    {
        ssl_ctx_set_verify(ctx, SSL_VERIFY_NONE, null);
    }
    else
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

    Ssl ssl = ssl_new(ctx);
    if (ssl == null) return TLS_FAILED~;
    defer catch ssl_free(ssl);

    if (ssl_set_fd(ssl, (CInt)sock.sock) != 1) return TLS_FAILED~;

    ZString host_z = host.zstr_tcopy();
    ssl_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_HOST_NAME, (void*)host_z);   // SNI
    if (!config.no_verify && ssl_set1_host(ssl, host_z) != 1) return TLS_HANDSHAKE_FAILED~;   // hostname check

    if (ssl_connect(ssl) != 1) return TLS_HANDSHAKE_FAILED~;
    if (!config.no_verify && ssl_get_verify_result(ssl) != X509_V_OK) return TLS_HANDSHAKE_FAILED~;

    return { .sock = sock, .ctx = ctx, .ssl = ssl };
}
