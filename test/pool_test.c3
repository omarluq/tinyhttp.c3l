// Keep-alive tests (Increment 4): the precise reader, the do_exchange framing
// decision, the stale-retry signal, and the connection pool — all driven in
// process by a mock Conn, no network.
// 
// CountConn serves canned response bytes one CHUNK per read() (a chunk models
// one TCP read result). One chunk per read is what makes keep-alive testable:
// the precise reader reads into a >=4096 buffer, so if a whole keep-alive stream
// arrived in a single read it would slurp the *next* response as leftover and
// drop it. Delivering resp1 and resp2 as separate chunks lets the reader frame
// resp1 exactly and leave resp2 in the "socket" for the next read_response —
// which is the reuse guarantee. A response whose framed body plus trailing junk
// share one chunk (test 6) proves the leftover path the other way.
module tinyhttp;
import std::io;
import std::os::env;

// A Conn that serves response bytes chunk-by-chunk, counts read/close calls, and
// records everything written. Heap-friendly so the pool tests can own one behind
// a fat Conn pointer and free it through ConnPool.discard/free.
struct CountConn (Conn)
{
	char[][] chunks; // each read() returns the next chunk; past the end == EOF
	usz pos; // index of the next chunk to serve
	usz closes; // close() call count
	bool stale_first; // model a dead idle keep-alive socket: first read() returns 0
	usz reads; // read() call count
	DString written; // bytes handed to write()
}

fn sz? CountConn.read(&self, char[] buf) @dynamic
{
	if (self.stale_first && self.reads == 0)
	{
		self.reads++;
		return 0; // idle socket was closed before any byte arrived
	}
	self.reads++;
	if (self.pos >= self.chunks.len) return 0; // EOF: no more chunks
	char[] chunk = self.chunks[self.pos];
	usz n        = chunk.len < buf.len ? chunk.len : buf.len;
	buf[:n] = chunk[:n];
	self.pos++; // one chunk per read (chunks are <= buf here)
	return (sz)n;
}

fn sz? CountConn.write(&self, char[] buf) @dynamic
{
	self.written.append_bytes(buf);
	return (sz)buf.len;
}

fn void? CountConn.close(&self) @dynamic
{
	self.closes++;
}

// Forward read_byte/write_byte to satisfy Conn : InStream, OutStream (mirror MockConn).
fn char? CountConn.read_byte(&self) @dynamic => io::read_byte_using_read(self);
fn void? CountConn.write_byte(&self, char c) @dynamic => io::write_byte_using_write(self, c);

// Build a stack CountConn serving `chunks` (for the reader / do_exchange tests).
fn CountConn stack_conn(char[][] chunks) @local
{
	return { .chunks = chunks, .written = dstring::new(mem) };
}

// Build a heap CountConn owned by `mem` (for the pool tests, which need a fat
// Conn pointer into a heap object that ConnPool.discard/free can release).
fn CountConn* heap_conn(char[][] chunks, bool stale_first = false) @local
{
	return alloc::new(mem, CountConn, { .chunks = chunks, .written = dstring::new(mem), .stale_first = stale_first });
}

// ---- precise reader --------------------------------------------------------

// (1) The reader frames a Content-Length body exactly and does NOT read to EOF:
// a single read supplies the whole first chunk, the body is satisfied, and the
// trailing "EXTRA" chunk is never served. A read-to-EOF reader would read again.
fn void test_reader_precise_content_length() @test
{
	char[][2] chunks = {
		(char[])"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
		(char[])"EXTRA",
	};
	CountConn m = stack_conn(chunks[..]);
	defer m.written.free();

	Response resp = read_response(mem, &m, GET)!!;
	defer resp.free();

	assert(resp.body == "hello");
	assert(m.reads == 1); // exactly one read framed the body — no EOF-seeking second read
	assert(m.pos == 1); // the "EXTRA" chunk is still unserved (reader stopped after "hello")
}

// (2) Precise framing lets one stream serve two responses back-to-back: after
// resp1 is framed, resp2 is still in the "socket" and the next read_response
// reads it cleanly. This is the core keep-alive guarantee.
fn void test_reader_reuse_two_responses() @test
{
	char[][2] chunks = {
		(char[])"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
		(char[])"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc",
	};
	CountConn m = stack_conn(chunks[..]);
	defer m.written.free();

	Response r1 = read_response(mem, &m, GET)!!; // reused:false
	assert(r1.body == "hello");
	r1.free();

	Response r2 = read_response(mem, &m, GET)!!; // reused:false, SAME conn
	assert(r2.body == "abc");
	r2.free();
}

// ---- do_exchange framing decision ------------------------------------------

// (3) do_exchange on the persistent path writes without Connection: close and
// reports the conn reusable, twice over one conn (proves reuse end to end).
fn void test_do_exchange_reuse() @test
{
	char[][2] chunks = {
		(char[])"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
		(char[])"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc",
	};
	CountConn m = stack_conn(chunks[..]);
	defer m.written.free();

	bool reusable1;
	Response r1 = do_exchange(mem, &m, GET, "h", "/", { }, { }, false, &reusable1)!!;
	assert(r1.body == "hello");
	assert(reusable1);
	r1.free();

	bool reusable2;
	Response r2 = do_exchange(mem, &m, GET, "h", "/", { }, { }, false, &reusable2)!!;
	assert(r2.body == "abc");
	assert(reusable2);
	r2.free();

	String req = m.written.str_view();
	assert(req.contains("GET / HTTP/1.1"));
	assert(!req.contains("Connection: close")); // persistent write: no close line
}

// (4) A close-delimited body (no Content-Length, not chunked) is read to EOF and
// is never poolable.
fn void test_reusable_false_read_to_eof() @test
{
	char[][1] chunks = { (char[])"HTTP/1.0 200 OK\r\n\r\nsome body bytes" };
	CountConn m      = stack_conn(chunks[..]);
	defer m.written.free();

	bool reusable;
	Response resp = do_exchange(mem, &m, GET, "h", "/", { }, { }, false, &reusable)!!;
	defer resp.free();
	assert(resp.status == 200);
	assert(resp.body == "some body bytes");
	assert(!reusable);
}

// (5) A server Connection: close makes the conn non-reusable even with a precise
// Content-Length body.
fn void test_reusable_false_conn_close() @test
{
	char[][1] chunks = { (char[])"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 3\r\n\r\nabc" };
	CountConn m      = stack_conn(chunks[..]);
	defer m.written.free();

	bool reusable;
	Response resp = do_exchange(mem, &m, GET, "h", "/", { }, { }, false, &reusable)!!;
	defer resp.free();
	assert(resp.body == "abc");
	assert(!reusable);
}

// (6) Trailing bytes past the Content-Length body arrive in the same chunk: the
// reader over-reads them, sees leftover it cannot push back, and refuses reuse.
fn void test_reusable_false_leftover() @test
{
	char[][1] chunks = { (char[])"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloWORLD" };
	CountConn m      = stack_conn(chunks[..]);
	defer m.written.free();

	bool reusable;
	Response resp = do_exchange(mem, &m, GET, "h", "/", { }, { }, false, &reusable)!!;
	defer resp.free();
	assert(resp.body == "hello");
	assert(!reusable); // 5 unframed trailing bytes remain
}

// ---- stale-retry signal ----------------------------------------------------

// (7) A reused conn whose first read returns 0 (idle socket closed) surfaces as
// STALE_CONNECTION so the caller can retry once on a fresh dial.
fn void test_stale_signal() @test
{
	char[][1] chunks = { (char[])"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello" };
	CountConn m      = stack_conn(chunks[..]);
	m.stale_first = true;
	defer m.written.free();

	bool reusable;
	Response? r = do_exchange(mem, &m, GET, "h", "/", { }, { }, true, &reusable);
	if (try resp = r)
	{
		resp.free();
		assert(false, "expected STALE_CONNECTION");
	}
	if (catch e = r) assert(e == STALE_CONNECTION);
}

// (8) A reused conn that delivers a partial body then EOF is a REAL failure
// (INCOMPLETE_RESPONSE), not STALE_CONNECTION: only a dead first read is stale,
// so a half-sent (possibly non-idempotent) request is not silently retried.
fn void test_stale_not_retried_midbody() @test
{
	char[][1] chunks = { (char[])"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nhi" };
	CountConn m      = stack_conn(chunks[..]);
	defer m.written.free();

	bool reusable;
	Response? r = do_exchange(mem, &m, GET, "h", "/", { }, { }, true, &reusable);
	if (try resp = r)
	{
		resp.free();
		assert(false, "expected INCOMPLETE_RESPONSE");
	}
	if (catch e = r) assert(e == INCOMPLETE_RESPONSE);
}

// ---- connection pool -------------------------------------------------------

// (9) checkin then checkout returns the stored conn; a second checkout on the
// now-empty bucket misses with POOL_EMPTY.
fn void test_pool_checkin_checkout() @test
{
	ConnPool p   = { .allocator = mem };
	String key   = "http|h|80";
	CountConn* c = heap_conn({ });
	DString w    = c.written; // save the buffer ptr; discard frees the struct, not this
	p.checkin(key, { .conn = (Conn)c, .mem = c });

	IdleConn got   = p.checkout(key)!!;
	IdleConn? miss = p.checkout(key); // bucket is empty now
	if (catch e = miss)
	{
		assert(e == POOL_EMPTY);
	}
	else
	{
		assert(false, "expected POOL_EMPTY");
	}

	p.discard(got); // close + free the conn object
	w.free();
	p.free(); // release the (now empty) bucket + copied key
}

// (10) discard closes the connection exactly once.
fn void test_pool_discard_closes() @test
{
	ConnPool p   = { .allocator = mem };
	String key   = "http|h|80";
	CountConn* c = heap_conn({ });
	DString w    = c.written;
	p.checkin(key, { .conn = (Conn)c, .mem = c });

	IdleConn got = p.checkout(key)!!;
	p.discard(got);
	assert(c.closes == 1); // closes lives past the freed tcache header (offset > 16)
	w.free();
	p.free();
}

// (11) free drains every bucket, closing all idle conns.
fn void test_pool_free_drains() @test
{
	ConnPool p    = { .allocator = mem };
	CountConn* c1 = heap_conn({ });
	CountConn* c2 = heap_conn({ });
	DString w1    = c1.written;
	DString w2    = c2.written;
	p.checkin("http|a|80", { .conn = (Conn)c1, .mem = c1 });
	p.checkin("http|b|80", { .conn = (Conn)c2, .mem = c2 });

	p.free();
	assert(c1.closes == 1);
	assert(c2.closes == 1);
	w1.free();
	w2.free();
}

// (12) The full stale-retry orchestration (Client.request's two branches),
// assembled by hand with mocks: a stale pooled conn A raises STALE_CONNECTION on
// the reused exchange and is discarded (closed once); the retry then succeeds on
// a fresh conn B, which comes back reusable.
fn void test_stale_retry_orchestration() @test
{
	ConnPool p = { .allocator = mem };
	String key = "http|h|80";

	char[][1] achunks = { (char[])"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello" };
	CountConn* a      = heap_conn(achunks[..], true); // stale idle socket (first read returns 0)

	char[][1] bchunks = { (char[])"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello" };
	CountConn* b      = heap_conn(bchunks[..]); // the fresh dial

	p.checkin(key, { .conn = (Conn)a, .mem = a });

	// --- pooled branch: checkout A, exchange over the reused conn ---
	IdleConn ic  = p.checkout(key)!!;
	bool reusable_a;
	Response? ra = do_exchange(mem, ic.conn, GET, "h", "/", { }, { }, true, &reusable_a);
	if (try r = ra)
	{
		r.free();
		assert(false, "expected STALE_CONNECTION on the reused stale conn");
	}
	if (catch e = ra)
	{
		assert(e == STALE_CONNECTION);
		DString aw = a.written; // capture after the (grown) write, before discard frees the struct
		p.discard(ic); // stale idle socket -> close + free, fall through to a fresh dial
		aw.free();
	}
	assert(a.closes == 1);

	// --- fresh branch (the retry): dial B, exchange over a fresh conn ---
	bool reusable_b;
	Response rb = do_exchange(mem, (Conn)b, GET, "h", "/", { }, { }, false, &reusable_b)!!;
	defer rb.free();
	assert(rb.ok());
	assert(rb.body == "hello");
	assert(reusable_b);

	DString bw = b.written; // capture after the write, before p.free frees b
	p.checkin(key, { .conn = (Conn)b, .mem = b }); // reusable -> back to the pool
	p.free(); // drain: close + free B, free bucket + key
	bw.free();
}

// (13) Live end-to-end keep-alive: two GETs through one Client exercise a real
// dial -> pool -> reuse, then Client.close drains the pool. Gated on
// TINYHTTP_LIVE (needs a network), so the default compile-test stays offline.
fn void test_keepalive_live() @test
{
	if (catch env::tget_var("TINYHTTP_LIVE")) return; // skip unless explicitly enabled

	Client c    = client(mem, "http://example.com");
	Response r1 = c.get("/")!!;
	defer r1.free();
	assert(r1.status == 200);

	Response r2 = c.get("/")!!;
	defer r2.free();
	assert(r2.status == 200);

	c.close();
}