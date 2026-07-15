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
 A blocking byte transport built on the stdlib stream interfaces:
 `read`/`write` move bytes (0 from `read` == peer closed) or fault;
 `close` releases the underlying resource.
*>
interface Conn : InStream, OutStream
{
	fn void? close();
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

<*
 Open a plain TCP connection to host:port (timeout 0 = block indefinitely).

 Maps the underlying `tcp::connect` fault onto tinyhttp's faults:
 `net::CONNECTION_TIMED_OUT` -> `TIMEOUT`, `net::ADDRINFO_FAILED` ->
 `DNS_FAILED`, everything else -> `CONNECT_FAILED`.
*>
fn PlainConn? dial(String host, int port, Duration timeout = time::DURATION_ZERO)
{
	TcpSocket? sock = tcp::connect(host, port, timeout);
	if (catch err = sock)
	{
		switch (err)
		{
			case net::CONNECTION_TIMED_OUT: return TIMEOUT~;
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