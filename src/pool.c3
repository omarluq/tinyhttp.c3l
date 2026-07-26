module tinyhttp;

import std::collections::list;
import std::collections::map;

alias IdleList = List{IdleConn};
alias PoolMap = HashMap{String, IdleList};

// internal miss signal raised by ConnPool.checkout when no idle conn is available
faultdef POOL_EMPTY @private;

// Default cap on the idle connections a Client keeps alive across all origins.
const usz DEFAULT_MAX_IDLE_CONNS @private = 32;

<*
 An idle, reusable connection plus the heap allocation backing its fat pointer,
 kept so ConnPool.discard/free can release the concrete object without interface introspection.
*>
struct IdleConn @private
{
	Conn conn;
	void* mem;
}

<*
 Keep-alive connection pool keyed by "scheme|host|port"; each bucket is a LIFO
 stack of idle connections. `max_idle` bounds the total idle set across every
 bucket (0 = unlimited, so a zero-initialized ConnPool is unbounded): without it
 a pool walking N distinct origins would hold one open socket, one bucket and one
 copied key per origin until free(). `idle_count` tracks how many conns are
 currently parked, and is maintained only by checkin/checkout/free — never by
 discard, which also runs on conns that were never pooled.
*>
struct ConnPool @private
{
	Allocator allocator;
	PoolMap map;
	bool inited;
	usz max_idle;
	usz idle_count;
}

fn void ConnPool.ensure_init(&self) @private
{
	if (self.inited) return;
	self.map.init(self.allocator);
	self.inited = true;
}

fn IdleConn? ConnPool.checkout(&self, String key) @private
{
	if (!self.inited) return POOL_EMPTY~;
	if (try list = self.map.get_ref(key))
	{
		if (try ic = list.pop())
		{
			self.idle_count--; // only ever decremented on a successful pop
			return ic;
		}
	}
	return POOL_EMPTY~;
}

<*
 Park `ic` under `key` for reuse. When the pool is already at `max_idle` the
 INCOMING conn is closed and freed rather than evicting a parked one: eviction
 would have to drop a map entry that owns an allocator-copied key and free its
 bucket, a lifetime hazard for no gain at this size.
*>
fn void ConnPool.checkin(&self, String key, IdleConn ic) @private
{
	if (self.max_idle != 0 && self.idle_count >= self.max_idle)
	{
		self.discard(ic);
		return;
	}
	self.ensure_init();
	// get_or_create_ref copies the transient `key` into self.allocator on a
	// miss (freed on map.free()), so the key need not outlive this call and
	// must not be pre-copied (that would leak). A freshly created bucket is
	// zeroed (is_initialized() false), so init it before the first push.
	IdleList* list = self.map.get_or_create_ref(key);
	if (!list.is_initialized()) list.init(self.allocator, 2);
	list.push(ic);
	self.idle_count++;
}

<*
 Close and release `ic`. Also used on conns that were never parked (a fresh dial
 whose exchange failed), so it must NOT touch idle_count: a decrement here would
 underflow the count and permanently wedge the cap.
*>
fn void ConnPool.discard(&self, IdleConn ic) @private
{
	(void)ic.conn.close();
	alloc::free(self.allocator, ic.mem);
}

fn void ConnPool.free(&self) @private
{
	if (!self.inited) return;
	foreach (list : self.map.values(tmem))
	{
		foreach (ic : list) self.discard(ic);
		list.free();
	}
	// map.free() releases each entry's owned key copy (String keys implement
	// copy) along with the table, so keys must not be freed here.
	self.map.free();
	// Zero the map so is_initialized() reports false again; HashMap.free leaves
	// map.allocator set, so a later ensure_init->map.init would trip its
	// @require !is_initialized() contract without this reset.
	self.map = { };
	self.inited = false;
	self.idle_count = 0;
}