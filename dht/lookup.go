package dht

import (
	"bytes"
	"net/netip"
	"slices"
	"time"

	"github.com/getlantern/warren/krpc"
)

type OpID uint32

type lookupKind uint8

const (
	findNode lookupKind = iota
	getItem
	putItem
)

type candState uint8

const (
	unqueried candState = iota
	inflight
	responded
	failed
)

type cand struct {
	id      krpc.NodeID
	idKnown bool
	addr    netip.AddrPort
	dist    krpc.NodeID
	state   candState
	// slow: the query is past the adaptive short timeout and no longer
	// counts toward alpha, so the lookup widens. lapsed: it is past
	// Config.ShortTimeout too and no longer holds the lookup open.
	slow, lapsed bool
	domestic     bool
	token        []byte
}

// lookup is an iterative Kademlia traversal. It tracks two frontiers: the K
// closest live nodes overall and, when domestic copies are on, the K closest
// live domestic nodes, so a single traversal finds both replica sets.
type lookup struct {
	gen      uint64 // the node's network generation when it started
	op       OpID
	kind     lookupKind
	internal bool
	target   krpc.NodeID
	t        *table
	deadline time.Time
	domestic bool
	// started, first and settled time the lookup (see Timing).
	started, first, settled time.Time

	cands []*cand
	ips   map[netip.AddrPort]bool
	pfx   map[ipPrefix]int

	rec   record // put payload
	cas   *int64
	value []byte // immutable get result
	// Mutable gets: the expected key and salt, the best verified item, and
	// every distinct one seen (by signature), up to MaxGetItems.
	key        *[32]byte
	salt       []byte
	best       *MutableItem
	items      []*MutableItem
	finished   bool
	queried    int
	failures   int
	putPending int
	putAcks    int
	putDomAcks int

	// onDone, if set, replaces the completion event for internal lookups.
	onDone func(now time.Time, l *lookup)
	// holders are candidates that returned the best mutable item.
	holders []*cand
	// acked are replicas that acknowledged a put, in distance order.
	acked []ackedReplica
}

type ackedReplica struct {
	addr     netip.AddrPort
	token    []byte
	domestic bool
	dist     krpc.NodeID
}

const maxLookupPerPrefix = 8

func (l *lookup) add(n *Node, id krpc.NodeID, idKnown bool, addr netip.AddrPort) {
	ip := addr.Addr().Unmap()
	k := l.t.key(addr)
	if !ip.IsValid() || addr.Port() == 0 || l.ips[k] || (idKnown && id == n.cfg.ID) {
		return
	}
	if idKnown && !l.t.accept(id, ip) {
		return
	}
	p := prefixOf(ip)
	if !l.t.unrestricted && l.pfx[p] >= maxLookupPerPrefix {
		return
	}
	c := &cand{id: id, idKnown: idKnown, addr: addr, domestic: n.isDomestic(ip)}
	if n.iso.isolated && !c.domestic {
		return // known unreachable; the isolation probe watches for recovery
	}
	if idKnown {
		c.dist = distance(id, l.target)
	} else {
		for i := range c.dist {
			c.dist[i] = 0xff
		}
	}
	if len(l.cands) >= n.cfg.MaxCandidates {
		last := l.cands[len(l.cands)-1]
		if last.state != unqueried || compareID(c.dist, last.dist) >= 0 {
			return
		}
		l.cands = l.cands[:len(l.cands)-1]
		delete(l.ips, l.t.key(last.addr))
		l.pfx[prefixOf(last.addr.Addr())]--
	}
	l.ips[k] = true
	l.pfx[p]++
	l.insert(c)
}

func (l *lookup) insert(c *cand) {
	i, _ := slices.BinarySearchFunc(l.cands, c, func(a, b *cand) int { return compareID(a.dist, b.dist) })
	l.cands = slices.Insert(l.cands, i, c)
}

// identify fixes a seed's distance once its ID is known.
func (l *lookup) identify(c *cand, id krpc.NodeID) {
	i := slices.Index(l.cands, c)
	l.cands = slices.Delete(l.cands, i, i+1)
	c.id, c.idKnown, c.dist = id, true, distance(id, l.target)
	l.insert(c)
}

// next returns the closest unqueried candidate inside either frontier.
func (l *lookup) next(k int) *cand {
	overall, dom := 0, 0
	for _, c := range l.cands {
		if c.state == failed || (c.state == inflight && c.lapsed) {
			continue
		}
		inOverall := overall < k
		inDom := l.domestic && c.domestic && dom < k
		overall++
		if c.domestic {
			dom++
		}
		if c.state == unqueried && (inOverall || inDom) {
			return c
		}
		if overall >= k && (!l.domestic || dom >= k) {
			return nil
		}
	}
	return nil
}

// inflight counts the lookup's queries in flight: active ones (not yet
// slow), open ones (not yet lapsed, still holding the lookup open), and all.
func (l *lookup) inflight() (active, open, total int) {
	for _, c := range l.cands {
		if c.state == inflight {
			total++
			if !c.slow {
				active++
			}
			if !c.lapsed {
				open++
			}
		}
	}
	return
}

func (l *lookup) byAddr(addr netip.AddrPort) *cand {
	for _, c := range l.cands {
		if c.addr == addr {
			return c
		}
	}
	return nil
}

// responded notes c answered: the lookup's first response, and whether c
// joins the k closest responders, which moves when the result settled.
func (l *lookup) responded(now time.Time, c *cand, k int) {
	if l.first.IsZero() {
		l.first = now
	}
	closer := 0
	for _, o := range l.cands { // sorted by distance
		if o == c {
			break
		}
		if o.state == responded {
			closer++
		}
	}
	if closer < k {
		l.settled = now
	}
}

func (l *lookup) timing(now time.Time) Timing {
	since := func(t time.Time) time.Duration {
		if t.IsZero() {
			return 0
		}
		return t.Sub(l.started)
	}
	return Timing{First: since(l.first), Settled: since(l.settled), Total: now.Sub(l.started)}
}

// replicas returns the responded nodes a put should go to: the K closest,
// plus the K closest domestic ones when domestic copies are on.
func (l *lookup) replicas(k int) []*cand {
	var out []*cand
	overall, dom := 0, 0
	for _, c := range l.cands {
		if c.state != responded || c.token == nil {
			continue
		}
		take := overall < k || (l.domestic && c.domestic && dom < k)
		overall++
		if c.domestic {
			dom++
		}
		if take {
			out = append(out, c)
		}
	}
	return out
}

func (l *lookup) closestResponded(k int) []krpc.NodeInfo {
	var out []krpc.NodeInfo
	for _, c := range l.cands {
		if c.state == responded && c.idKnown && len(out) < k {
			out = append(out, krpc.NodeInfo{ID: c.id, Addr: c.addr})
		}
	}
	return out
}

// observe takes a verified item c returned to a mutable get. The newest is
// the one SortItems puts first (on equal seq, the lower signature), so
// Item and Items[0] agree; holders are the nodes storing that very item,
// not another value at its seq.
func (l *lookup) observe(mi *MutableItem, c *cand) {
	switch {
	case l.best == nil || older(l.best, mi):
		l.best, l.holders = mi, []*cand{c}
	case mi.Sig == l.best.Sig:
		l.holders = append(l.holders, c)
	}
	l.keep(mi)
}

// keep records a verified item a mutable get saw, once per signature,
// keeping the MaxGetItems newest: old signed items anyone can replay must
// not crowd out the current ones.
func (l *lookup) keep(mi *MutableItem) {
	if slices.ContainsFunc(l.items, func(x *MutableItem) bool { return x.Sig == mi.Sig }) {
		return
	}
	if len(l.items) < MaxGetItems {
		l.items = append(l.items, mi)
		return
	}
	oldest := 0
	for i, x := range l.items {
		if older(x, l.items[oldest]) {
			oldest = i
		}
	}
	if older(l.items[oldest], mi) {
		l.items[oldest] = mi
	}
}

// older reports whether a sorts after b in SortItems' newest-first order.
func older(a, b *MutableItem) bool {
	if a.Seq != b.Seq {
		return a.Seq < b.Seq
	}
	return bytes.Compare(a.Sig[:], b.Sig[:]) > 0
}
