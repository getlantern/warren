package dht

import (
	"math/bits"
	"math/rand/v2"
	"net/netip"
	"slices"
	"time"

	"github.com/getlantern/warren/krpc"
)

const (
	maxPerIPPrefixBucket = 2
	maxPerIPPrefixTable  = 8
)

type entry struct {
	id       krpc.NodeID
	addr     netip.AddrPort
	lastResp time.Time
	lastPing time.Time
	fails    int
}

type bucket struct {
	nodes   []*entry
	cache   []*entry
	changed time.Time
}

// table is a Kademlia routing table with libtorrent-style IP restrictions:
// one identity per IP, and bounded identities per /24 (or /64) per bucket and
// per table.
type table struct {
	self         krpc.NodeID
	k            int
	accept       func(krpc.NodeID, netip.Addr) bool
	unrestricted bool
	buckets      [160]bucket
	// byIP indexes live entries by IP, or by full address when unrestricted.
	byIP   map[netip.AddrPort]*entry
	prefix map[ipPrefix]int
}

func newTable(self krpc.NodeID, k int, unrestricted bool, accept func(krpc.NodeID, netip.Addr) bool) *table {
	return &table{self: self, k: k, accept: accept, unrestricted: unrestricted, byIP: map[netip.AddrPort]*entry{}, prefix: map[ipPrefix]int{}}
}

func (t *table) key(a netip.AddrPort) netip.AddrPort {
	ip := a.Addr().Unmap()
	if t.unrestricted {
		return netip.AddrPortFrom(ip, a.Port())
	}
	return netip.AddrPortFrom(ip, 0)
}

type ipPrefix struct {
	v6 bool
	b  [8]byte
}

func prefixOf(a netip.Addr) ipPrefix {
	a = a.Unmap()
	var p ipPrefix
	if a.Is4() {
		b := a.As4()
		copy(p.b[:3], b[:3])
		return p
	}
	b := a.As16()
	p.v6 = true
	copy(p.b[:], b[:8])
	return p
}

func distance(a, b krpc.NodeID) (d krpc.NodeID) {
	for i := range a {
		d[i] = a[i] ^ b[i]
	}
	return d
}

func commonPrefix(a, b krpc.NodeID) int {
	for i := range a {
		if x := a[i] ^ b[i]; x != 0 {
			return i*8 + bits.LeadingZeros8(x)
		}
	}
	return 160
}

func (t *table) bucketFor(id krpc.NodeID) *bucket {
	return &t.buckets[min(commonPrefix(t.self, id), 159)]
}

func (t *table) get(id krpc.NodeID) *entry {
	for _, e := range t.bucketFor(id).nodes {
		if e.id == id {
			return e
		}
	}
	return nil
}

func (t *table) admissible(id krpc.NodeID, addr netip.AddrPort, b *bucket) bool {
	ip := addr.Addr().Unmap()
	if id == t.self || !t.accept(id, ip) || t.byIP[t.key(addr)] != nil {
		return false
	}
	if t.unrestricted {
		return true
	}
	p := prefixOf(ip)
	if t.prefix[p] >= maxPerIPPrefixTable {
		return false
	}
	n := 0
	for _, e := range b.nodes {
		if prefixOf(e.addr.Addr()) == p {
			n++
		}
	}
	return n < maxPerIPPrefixBucket
}

func (t *table) index(e *entry) {
	t.byIP[t.key(e.addr)] = e
	t.prefix[prefixOf(e.addr.Addr())]++
}

func (t *table) unindex(e *entry) {
	delete(t.byIP, t.key(e.addr))
	p := prefixOf(e.addr.Addr())
	if t.prefix[p]--; t.prefix[p] <= 0 {
		delete(t.prefix, p)
	}
}

// heard records an authenticated response from id at addr. A live entry
// never silently moves to a new address; a failing one may.
func (t *table) heard(id krpc.NodeID, addr netip.AddrPort, now time.Time) {
	b := t.bucketFor(id)
	if e := t.get(id); e != nil {
		if e.addr != addr {
			if e.fails == 0 {
				return
			}
			t.unindex(e)
			e.addr = addr
			t.index(e)
		}
		e.lastResp, e.fails = now, 0
		return
	}
	if !t.admissible(id, addr, b) {
		return
	}
	e := &entry{id: id, addr: addr, lastResp: now}
	if len(b.nodes) < t.k {
		b.nodes = append(b.nodes, e)
		t.index(e)
		b.changed = now
		return
	}
	worst := -1
	for i, old := range b.nodes {
		if old.fails > 0 && (worst < 0 || old.fails > b.nodes[worst].fails) {
			worst = i
		}
	}
	if worst >= 0 {
		t.unindex(b.nodes[worst])
		b.nodes[worst] = e
		t.index(e)
		b.changed = now
		return
	}
	b.cache = slices.DeleteFunc(b.cache, func(c *entry) bool { return c.id == id })
	if len(b.cache) >= t.k {
		b.cache = b.cache[1:]
	}
	b.cache = append(b.cache, e)
}

// failed counts a timeout. Past threshold the entry is dropped and the most
// recently heard cache entry promoted; the caller should ping it.
func (t *table) failed(addr netip.AddrPort, threshold int) (promoted *entry) {
	e := t.byIP[t.key(addr)]
	if e == nil || e.addr != addr {
		return nil
	}
	if e.fails++; e.fails < threshold {
		return nil
	}
	b := t.bucketFor(e.id)
	b.nodes = slices.DeleteFunc(b.nodes, func(x *entry) bool { return x == e })
	t.unindex(e)
	for i := len(b.cache) - 1; i >= 0; i-- {
		c := b.cache[i]
		b.cache = slices.Delete(b.cache, i, i+1)
		if t.admissible(c.id, c.addr, b) {
			c.fails = 0
			b.nodes = append(b.nodes, c)
			t.index(c)
			return c
		}
	}
	return nil
}

// wantsVerify reports whether pinging an unknown querier could change the
// table: it must be admissible and its bucket must have room or a failing
// entry. Verifying anything else would only churn the replacement cache, and
// two nodes in each other's caches would ping each other forever.
func (t *table) wantsVerify(id krpc.NodeID, addr netip.AddrPort) bool {
	if t.get(id) != nil {
		return false
	}
	b := t.bucketFor(id)
	if !t.admissible(id, addr, b) {
		return false
	}
	if len(b.nodes) < t.k {
		return true
	}
	for _, e := range b.nodes {
		if e.fails > 0 {
			return true
		}
	}
	return false
}

func (t *table) contains(addr netip.AddrPort) bool {
	e := t.byIP[t.key(addr)]
	return e != nil && e.addr == addr
}

func (t *table) closest(target krpc.NodeID, n int) []krpc.NodeInfo {
	type item struct {
		d krpc.NodeID
		e *entry
	}
	var all []item
	for i := range t.buckets {
		for _, e := range t.buckets[i].nodes {
			all = append(all, item{distance(e.id, target), e})
		}
	}
	slices.SortFunc(all, func(a, b item) int { return compareID(a.d, b.d) })
	out := make([]krpc.NodeInfo, 0, min(n, len(all)))
	for _, it := range all[:min(n, len(all))] {
		out = append(out, krpc.NodeInfo{ID: it.e.id, Addr: it.e.addr})
	}
	return out
}

func (t *table) len() int { return len(t.byIP) }

func (t *table) each(f func(*entry)) {
	for i := range t.buckets {
		for _, e := range t.buckets[i].nodes {
			f(e)
		}
	}
}

// depth is one past the deepest non-empty bucket: buckets beyond it are
// empty because no closer node exists, not for lack of refresh.
func (t *table) depth() int {
	for i := 159; i >= 0; i-- {
		if len(t.buckets[i].nodes) > 0 {
			return i + 1
		}
	}
	return 0
}

func (t *table) randomIDInBucket(i int, r *rand.Rand) krpc.NodeID {
	id := t.self
	for j := i; j < 160; j++ {
		bit := byte(0x80) >> (j % 8)
		switch {
		case j == i:
			id[j/8] ^= bit
		case r.IntN(2) == 1:
			id[j/8] ^= bit
		}
	}
	return id
}

func compareID(a, b krpc.NodeID) int {
	for i := range a {
		if a[i] != b[i] {
			return int(a[i]) - int(b[i])
		}
	}
	return 0
}
