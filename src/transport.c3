// tinyhttp transport layer — the single seam between the HTTP logic and the
// byte stream. Today: a blocking plain-TCP connection. Later a TLS connection
// or a test mock can implement the same interface with nothing above changing.

module tinyhttp;
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
 `total` bounds the whole request from dial to the last body byte; it is an
 absolute deadline, so activity cannot reset it.
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
 `close` releases the underlying resource. The timeout setters bound a single
 subsequent operation (0 = block indefinitely); they live here because the
 timeout is a property of the byte stream, and because SO_RCVTIMEO sits below
 TLS, so one implementation serves both plain and TLS connections.
*>
interface Conn : InStream, OutStream
{
	fn void? close();
	fn void? set_read_timeout(Duration d);
	fn void? set_write_timeout(Duration d);
}

// The stdlib has no Timeval type, and Socket.set_option only carries a 4-byte
// bool, so SO_RCVTIMEO/SO_SNDTIMEO are set through os::setsockopt directly.
struct Timeval @private
{
	CLong tv_sec;
	CLong tv_usec;
}

// Arm one direction of a socket. Duration is microseconds, so the seconds and
// microseconds fields fall straight out of it.
fn void? set_fd_timeout(TcpSocket sock, CInt optname, Duration d) @private
{
	Timeval tv = d <= time::DURATION_ZERO ? { 0, 0 } : { (CLong)(d / time::SEC), (CLong)(d % time::SEC) };
	if (os::setsockopt(sock.sock, os::SOL_SOCKET, optname, &tv, Timeval::size)) return SOCKOPT_FAILED~;
}

<* A plain (cleartext) TCP connection. *>
struct PlainConn (Conn)
{
	TcpSocket sock;
}

fn sz? PlainConn.read(&self, char[] buf) @dynamic => self.sock.read(buf);
fn sz? PlainConn.write(&self, char[] buf) @dynamic => self.sock.write(buf);
fn char? PlainConn.read_byte(&self) @dynamic => self.sock.read_byte();
fn void? PlainConn.write_byte(&self, char c) @dynamic => self.sock.write_byte(c);
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