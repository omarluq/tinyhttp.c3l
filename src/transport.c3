// tinyhttp transport layer — the single seam between the HTTP logic and the
// byte stream. Today: a blocking plain-TCP connection. Later a TLS connection
// or a test mock can implement the same interface with nothing above changing.

module tinyhttp;
import std::net::tcp;

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

<* Open a plain TCP connection to host:port. *>
fn PlainConn? dial(String host, int port)
{
    if (try sock = tcp::connect(host, port)) return { .sock = sock };
    return CONNECT_FAILED~;
}
