// tinyhttp transport layer — the single seam between the HTTP logic and the
// byte stream. Today: a blocking plain-TCP connection. Later a TLS connection
// or a test mock can implement the same interface with nothing above changing.

module tinyhttp;
import std::core::env;
import std::io;
import std::net;
import std::net::tcp;
import std::net::os;
import std::time;

// disable Nagle's algorithm so small request writes go out immediately.
// std::net::os exposes IPPROTO_TCP only in its no-libc fallback and does not expose
// a TCP_NODELAY constant at all, so both are declared locally.
const CInt IPPROTO_TCP @private = 6;
const CInt TCP_NODELAY @private = 1;

<*
 Per-request time budget. Zero means no limit for every field.

 `connect` bounds DNS, the TCP connect and, for https, the TLS handshake.
 `read` and `write` bound ONE socket operation each and reset on every successful
 one, so a stalled peer is detected without capping total transfer time.
 `total` bounds the request/response exchange only — from the first request byte
 written to the last body byte read — as an absolute deadline, so activity cannot
 reset it within one exchange. It does NOT cover DNS, the TCP connect or the TLS
 handshake: those are bounded separately by `connect`, so one dialing call can
 spend up to `connect` + `total`. A `Client` request that retries once on a stale
 pooled connection starts a fresh `total` for the second attempt. Over TLS `total`
 is enforced per socket operation, not per SSL_read/SSL_write: one SSL_read
 assembles a whole TLS record and one SSL_write drains a whole buffer, each
 issuing many recv/send calls that individually re-arm the remaining budget, so a
 peer that dribbles bytes can overshoot `total`. Set `read`/`write` alongside
 `total` to bound such a peer.
*>
struct Timeouts
{
	Duration connect;
	Duration read;
	Duration write;
	Duration total;
}

<*
 The default budget: bound the connect (and, for https, the handshake), leave
 transfer unbounded. This follows Go, whose DefaultTransport dials with a 30s
 timeout and a 10s handshake timeout while `http.Client.Timeout` stays zero; no
 mainstream client bounds reads by default, since that would break a slow but
 honest download. Pass a `Timeouts` with `connect` zero to block indefinitely.

 Note a partial literal zeroes the rest, so `{ .read = ... }` also drops the
 connect default, exactly as Go's `&Transport{}` drops its dialer defaults.
*>
const Timeouts DEFAULT_TIMEOUTS = { .connect = (Duration)30_000_000 };

<*
 A blocking byte transport built on the stdlib stream interfaces:
 `read`/`write` move bytes (0 from `read` == peer closed) or fault;
 `close` releases the underlying resource. The timeout setters arm the stream
 until changed again (0 = block indefinitely); they live here because the timeout
 is a property of the byte stream, and because SO_RCVTIMEO sits below TLS, so one
 implementation serves both plain and TLS connections.

 An implementation MUST report an expired timeout as `READ_TIMEOUT` /
 `WRITE_TIMEOUT` rather than an underlying stream fault: the reader distinguishes
 a timeout (the peer is alive) from a closed idle keep-alive socket (safe to
 retry) purely by that fault, and mislabelling one as the other replays the
 request.
*>
interface Conn : InStream, OutStream
{
	fn void? close();
	fn void? set_read_timeout(Duration d);
	fn void? set_write_timeout(Duration d);
}

// The stdlib has no Timeval type, and Socket.set_option only carries a 4-byte
// bool, so SO_RCVTIMEO/SO_SNDTIMEO are set through os::setsockopt directly. That
// puts the platform ABI split on us: POSIX takes a `timeval`, Winsock a single
// DWORD of milliseconds with optlen 4, and handing Winsock a timeval just fails
// (WSAEFAULT), so the arming below branches at compile time. That branch does not
// make Windows whole: Winsock reports an expired SO_RCVTIMEO as WSAETIMEDOUT
// rather than EWOULDBLOCK, so the READ_TIMEOUT/WRITE_TIMEOUT mapping in
// PlainConn.read/write is still POSIX-shaped and needs its own fix.
struct Timeval @private
{
	CLong tv_sec;
	CLong tv_usec;
}

<*
 Milliseconds covering `d`, rounded up. Winsock reads 0 as "block forever", so a
 non-zero sub-millisecond budget must never collapse to it; only a non-positive
 `d` (the caller's own "no limit") maps to 0. Computed without adding to `d`, so
 a budget near `time::FOREVER` cannot overflow, then clamped to the DWORD range.
*>
fn uint duration_to_ms_ceil(Duration d) @private
{
	if (d <= time::DURATION_ZERO) return 0;
	Duration ms = (d - (Duration)1) / time::MS + (Duration)1;
	return ms >= (Duration)uint::max ? uint::max : (uint)ms;
}

// Arm one direction of a socket.
fn void? set_fd_timeout(TcpSocket sock, CInt optname, Duration d) @private
{
	$if env::WIN32:
		uint ms = duration_to_ms_ceil(d);
		if (os::setsockopt(sock.sock, os::SOL_SOCKET, optname, &ms, uint::size)) return SOCKOPT_FAILED~;
	$else
		// Duration is microseconds, so the seconds and microseconds fields fall
		// straight out of it.
		Timeval tv = d <= time::DURATION_ZERO ? { 0, 0 } : { (CLong)(d / time::SEC), (CLong)(d % time::SEC) };
		if (os::setsockopt(sock.sock, os::SOL_SOCKET, optname, &tv, Timeval::size)) return SOCKOPT_FAILED~;
	$endif
}

<* A plain (cleartext) TCP connection. *>
struct PlainConn (Conn)
{
	TcpSocket sock;
}

// The socket is always blocking, so EWOULDBLOCK (which the stdlib surfaces as
// io::WOULD_BLOCK) can only mean the armed SO_RCVTIMEO/SO_SNDTIMEO fired. Naming
// it here is what lets the reader tell a timeout from a dead keep-alive socket:
// left unmapped it is mistaken for a stale connection and the request is replayed.
fn sz? PlainConn.read(&self, char[] buf) @dynamic
{
	sz? n = self.sock.read(buf);
	if (catch e = n) return e == io::WOULD_BLOCK ? READ_TIMEOUT~ : e~;
	return n;
}

fn sz? PlainConn.write(&self, char[] buf) @dynamic
{
	sz? n = self.sock.write(buf);
	if (catch e = n) return e == io::WOULD_BLOCK ? WRITE_TIMEOUT~ : e~;
	return n;
}

// Route the byte helpers through the mapped methods above, not around them.
fn char? PlainConn.read_byte(&self) @dynamic => io::read_byte_using_read(self);
fn void? PlainConn.write_byte(&self, char c) @dynamic => io::write_byte_using_write(self, c);
fn void? PlainConn.close(&self) @dynamic => self.sock.close();
fn void? PlainConn.set_read_timeout(&self, Duration d) @dynamic => set_fd_timeout(self.sock, os::SO_RCVTIMEO, d);
fn void? PlainConn.set_write_timeout(&self, Duration d) @dynamic => set_fd_timeout(self.sock, os::SO_SNDTIMEO, d);

<*
 Open a plain TCP connection to host:port, bounded by `timeouts.connect`
 (0 = block indefinitely).

 Maps the underlying `tcp::connect` fault onto tinyhttp's faults:
 `net::CONNECTION_TIMED_OUT` -> `CONNECT_TIMEOUT`, `net::ADDRINFO_FAILED` ->
 `DNS_FAILED`, everything else -> `CONNECT_FAILED`.
*>
fn PlainConn? dial(String host, int port, Timeouts timeouts = DEFAULT_TIMEOUTS)
{
	TcpSocket? sock = tcp::connect(host, port, timeouts.connect);
	if (catch err = sock)
	{
		switch (err)
		{
			case net::CONNECTION_TIMED_OUT: return CONNECT_TIMEOUT~;
			case net::ADDRINFO_FAILED: return DNS_FAILED~;
			default: return CONNECT_FAILED~;
		}
	}
	// best-effort TCP_NODELAY; failure to tune is non-fatal, so the CInt
	// result is intentionally discarded.
	CInt nodelay = 1;
	(void)os::setsockopt(sock.sock, IPPROTO_TCP, TCP_NODELAY, &nodelay, CInt::size);
	return { .sock = sock };
}