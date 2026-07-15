module tinyhttp;

import std::collections::list;
import std::collections::map;

alias IdleList = List{IdleConn};
alias PoolMap = HashMap{String, IdleList};

// internal miss signal raised by ConnPool.checkout when no idle conn is available
faultdef POOL_EMPTY;

<* An idle, reusable connection plus the heap allocation backing its fat pointer,
   kept so ConnPool.discard/free can release the concrete object without interface introspection. *>
struct IdleConn
{
    Conn conn;
    void* mem;
}

<* Keep-alive connection pool keyed by "scheme|host|port"; each bucket is a LIFO stack of idle connections. *>
struct ConnPool
{
    Allocator allocator;
    PoolMap map;
    bool inited;
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
        if (try ic = list.pop()) return ic;
    }
    return POOL_EMPTY~;
}

fn void ConnPool.checkin(&self, String key, IdleConn ic) @private
{
    self.ensure_init();
    // get_or_create_ref copies the transient `key` into self.allocator on a
    // miss (freed on map.free()), so the key need not outlive this call and
    // must not be pre-copied (that would leak). A freshly created bucket is
    // zeroed (is_initialized() false), so init it before the first push.
    IdleList* list = self.map.get_or_create_ref(key);
    if (!list.is_initialized()) list.init(self.allocator, 2);
    list.push(ic);
}

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
    self.map = {};
    self.inited = false;
}
