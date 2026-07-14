// tinyhttp transport layer — the single seam between the HTTP logic and the
// byte stream. Today: a blocking plain-TCP connection. Later a TLS connection
// or a test mock can implement the same interface with nothing above changing.

module tinyhttp;
import std::net::tcp;
import std::time;

<* A blocking byte transport. `read`/`write` return the number of bytes moved
   (0 from `read` means the peer closed), or a fault on error. *>
interface Conn
{
    fn sz? read(char[] buf);
    fn sz? write(char[] buf);
    fn void? close();
}

// A plain (cleartext) TCP connection.
struct PlainConn (Conn)
{
    TcpSocket sock;
}

fn sz? PlainConn.read(&self, char[] buf) @dynamic => self.sock.read(buf);
fn sz? PlainConn.write(&self, char[] buf) @dynamic => self.sock.write(buf);
fn void? PlainConn.close(&self) @dynamic => self.sock.close();

<* Open a plain TCP connection to host:port (timeout 0 = block indefinitely).

   KNOWN LIMITATION: a non-zero timeout routes through the stdlib's non-blocking
   `connect_with_timeout`, which on c3c 0.8.2/Linux mishandles the normal
   EINPROGRESS (errno 115) from a non-blocking connect and fails with
   `io::GENERAL_ERROR`. Until that upstream bug is fixed, timeout 0 (the default)
   is the reliable path. The wiring here is correct and will work once it lands. *>
fn PlainConn? dial(String host, int port, Duration timeout = {})
{
    if (try sock = tcp::connect(host, port, timeout)) return { .sock = sock };
    return CONNECT_FAILED~;
}
