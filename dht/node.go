package dht

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"time"

	"github.com/getlantern/warren/bencode"
	"github.com/getlantern/warren/krpc"
)

var (
	ErrBusy     = errors.New("dht: too many concurrent operations")
	ErrTooLarge = errors.New("dht: value exceeds 1000 bytes")
)

type Send struct {
	To   netip.AddrPort
	Data []byte
}

type Event interface{ isEvent() }

type LookupDone struct {
	Op       OpID
	Target   krpc.NodeID
	Closest  []krpc.NodeInfo
	Queried  int
	Failures int
}

type GetDone struct {
	Op     OpID
	Target krpc.NodeID
	Value  []byte // nil if not found
	// Item is the highest-sequence verified item, for mutable gets.
	Item    *MutableItem
	Queried int
}

type PutDone struct {
	Op       OpID
	Target   krpc.NodeID
	Stored   int
	Domestic int
}

type PartitionChanged struct{ Suspected bool }

// IsolationChanged reports entering or leaving isolation: domestic contacts
// answer while foreign ones have stopped.
type IsolationChanged struct{ Isolated bool }

func (LookupDone) isEvent()       {}
func (GetDone) isEvent()          {}
func (PutDone) isEvent()          {}
func (PartitionChanged) isEvent() {}
func (IsolationChanged) isEvent() {}

// Reflection is one BEP 42 observation of our address, for NAT analysis.
type Reflection struct {
	From   netip.AddrPort
	Mapped netip.AddrPort
	At     time.Time
	// Order is when we first sent to From among our destinations, which is
	// when the NAT created this mapping; replies can arrive in any order.
	// -1 if unknown.
	Order int
}

type txnKind uint8

const (
	txLookup txnKind = iota
	txPut
	txPing
	txKeepalive
	txOffer
	txAnswerToken
)

type txn struct {
	to       netip.AddrPort
	kind     txnKind
	lookup   *lookup
	sent     time.Time
	slow     bool
	tracked  bool // sent to a routing-table contact; counts toward health
	domestic bool
	token    []byte  // put: the token used, recorded on ack
	holder   *holder // keepalive
	signal   *signalOp
	attempt  int
	session  *session // txAnswerToken: the session whose answer waits for a token
}

// record is what a put carries: an immutable value or a signed mutable item.
type record struct {
	v   []byte
	mut *MutableItem
}

func (r record) args() krpc.Args {
	if r.mut != nil {
		return r.mut.args()
	}
	return krpc.Args{V: r.v}
}

type item struct {
	record
	expires   time.Time
	lastPut   time.Time
	community bool // stored by a community member
}

type owned struct {
	rec  record
	next time.Time
}

type Node struct {
	cfg Config
	// comm is nil for a plain Mainline node; primary is comm if set, else main.
	comm, main, primary *table

	txns    map[uint16]*txn
	nextTID uint16
	lookups []*lookup
	nextOp  OpID

	items map[krpc.NodeID]*item
	owned map[krpc.NodeID]*owned

	secret, prevSecret [8]byte
	// destOrder numbers destinations in first-contact order, for NAT
	// analysis; bounded like reflections.
	destOrder   map[netip.AddrPort]int
	rotated     time.Time
	nextMaint   time.Time
	health      health
	iso         isolation
	reflections []Reflection

	sends  []Send
	events []Event

	lst *listener
	// recordSeq is the last sequence number signed per record target. It
	// outlives the listener, so re-listening never reuses a number.
	recordSeq map[krpc.NodeID]int64
	signals   []*signalOp
	fwd       forwarder
	rel       relay
	// sibling is the node for the other address family, whose table answers
	// queries that want that family (libtorrent's get_foreign_node).
	sibling *Node
}

func New(cfg Config) *Node {
	cfg.setDefaults()
	n := &Node{
		cfg:   cfg,
		txns:  map[uint16]*txn{},
		items: map[krpc.NodeID]*item{},
		owned: map[krpc.NodeID]*owned{},
	}
	member := func(id krpc.NodeID) bool { return cfg.Community != nil && cfg.Community.IsMember(id) }
	n.main = newTable(cfg.ID, cfg.K, cfg.Unrestricted, func(id krpc.NodeID, _ netip.Addr) bool { return !member(id) })
	n.primary = n.main
	if cfg.Community != nil {
		n.comm = newTable(cfg.ID, cfg.K, cfg.Unrestricted, func(id krpc.NodeID, ip netip.Addr) bool {
			return member(id) && krpc.IsSecureID(ip, id)
		})
		n.primary = n.comm
	}
	n.fillSecret(&n.secret)
	n.prevSecret = n.secret
	return n
}

func (n *Node) fillSecret(s *[8]byte) { binary.LittleEndian.PutUint64(s[:], n.cfg.Rand.Uint64()) }

func (n *Node) isDomestic(ip netip.Addr) bool { return n.cfg.Domestic != nil && n.cfg.Domestic(ip) }

func (n *Node) isolationMode() bool { return n.cfg.IsolationMode && n.cfg.Domestic != nil }

func (n *Node) tableFor(id krpc.NodeID) *table {
	if n.comm != nil && n.cfg.Community.IsMember(id) {
		return n.comm
	}
	return n.main
}

// Drain returns and clears pending datagrams and events.
func (n *Node) Drain() ([]Send, []Event) {
	s, e := n.sends, n.events
	n.sends, n.events = nil, nil
	return s, e
}

func (n *Node) Reflections() []Reflection { return slices.Clone(n.reflections) }

// SetSibling pairs this node with the node for the other address family,
// as libtorrent pairs its per-family nodes: queries here that want the
// other family get referrals from the sibling's table of the same
// personality. Both nodes must be driven by the same goroutine.
func (n *Node) SetSibling(s *Node) { n.sibling = s }

func (n *Node) RoutingSize() (community, mainline int) {
	if n.comm != nil {
		community = n.comm.len()
	}
	return community, n.main.len()
}

func (n *Node) PartitionSuspected() bool { return n.health.suspected }
func (n *Node) Isolated() bool           { return n.iso.isolated }

// Holds reports whether this node stores an unexpired item for target.
func (n *Node) Holds(target krpc.NodeID) bool { return n.items[target] != nil }

// Knows reports whether addr is in any of this node's routing tables.
func (n *Node) Knows(addr netip.AddrPort) bool {
	return n.main.contains(addr) || (n.comm != nil && n.comm.contains(addr))
}

// NextWakeup is the latest time by which Tick must next be called.
func (n *Node) NextWakeup() time.Time {
	w := n.nextMaint
	for _, s := range n.signals {
		if s.offer == nil {
			continue
		}
		d := s.deadline
		if !s.acked && s.ackBy.Before(d) {
			d = s.ackBy
		}
		if w.IsZero() || d.Before(w) {
			w = d
		}
	}
	for _, t := range n.txns {
		d := t.sent.Add(n.cfg.QueryTimeout)
		if !t.slow && t.kind == txLookup {
			d = t.sent.Add(n.cfg.ShortTimeout)
		}
		if w.IsZero() || d.Before(w) {
			w = d
		}
	}
	return w
}

// ---- outbound ----

func (n *Node) send(now time.Time, to netip.AddrPort, q string, a krpc.Args, t *txn) bool {
	if len(n.txns) >= n.cfg.MaxTransactions {
		return false
	}
	for n.txns[n.nextTID] != nil {
		n.nextTID++
	}
	tid := n.nextTID
	n.nextTID++
	t.to, t.sent = to, now
	t.tracked = n.primary.contains(to) || n.main.contains(to)
	n.noteDestination(to)
	n.txns[tid] = t
	a.ID = n.cfg.ID
	var tb [2]byte
	binary.BigEndian.PutUint16(tb[:], tid)
	m := krpc.Msg{T: tb[:], Y: krpc.Query, Q: q, A: a, RO: n.cfg.ReadOnly, V: n.cfg.Version}
	n.sends = append(n.sends, Send{To: to, Data: krpc.AppendMarshal(nil, &m)})
	return true
}

func (n *Node) ping(now time.Time, e *entry) {
	e.lastPing = now
	n.send(now, e.addr, "ping", krpc.Args{}, &txn{kind: txPing})
}

// ---- operations ----

// Bootstrap looks up our own ID starting from seeds whose IDs are unknown.
func (n *Node) Bootstrap(now time.Time, seeds []netip.AddrPort) (OpID, error) {
	infos := make([]krpc.NodeInfo, len(seeds))
	for i, s := range seeds {
		infos[i].Addr = s
	}
	return n.start(now, n.primary, findNode, n.cfg.ID, record{}, infos, false)
}

// Rejoin looks up our own ID starting from previously known contacts, such
// as a saved Snapshot. They are candidates, not trusted routing entries:
// each enters the table only after it answers.
func (n *Node) Rejoin(now time.Time, contacts []krpc.NodeInfo) (OpID, error) {
	return n.start(now, n.primary, findNode, n.cfg.ID, record{}, contacts, false)
}

func (n *Node) FindNode(now time.Time, target krpc.NodeID) (OpID, error) {
	return n.start(now, n.primary, findNode, target, record{}, nil, false)
}

// Get retrieves a BEP 44 immutable item, finishing on the first value whose
// hash matches.
func (n *Node) Get(now time.Time, target krpc.NodeID) (OpID, error) {
	return n.start(now, n.primary, getItem, target, record{}, nil, false)
}

// GetMutable retrieves the highest-sequence item signed by key under salt.
// Unlike immutable gets it walks the whole frontier, since a closer node may
// hold a newer sequence number.
func (n *Node) GetMutable(now time.Time, key [32]byte, salt []byte) (OpID, error) {
	k := key
	// Configure before the first step: with no candidates, step finishes
	// and removes the lookup synchronously.
	l := n.startLookup(now, n.primary, getItem, MutableTarget(key, salt), record{}, nil, false)
	if l == nil {
		return 0, ErrBusy
	}
	l.key, l.salt = &k, salt
	n.step(now, l)
	return l.op, nil
}

// PutMutable stores a signed item once. cas, if set, makes each storing node
// accept it only if its current sequence number equals *cas.
func (n *Node) PutMutable(now time.Time, m MutableItem, cas *int64) (OpID, error) {
	if !m.Verify() {
		return 0, errors.New("dht: mutable item signature invalid")
	}
	l := n.startLookup(now, n.primary, putItem, m.Target(), record{v: m.V, mut: &m}, nil, false)
	if l == nil {
		return 0, ErrBusy
	}
	l.cas = cas
	n.step(now, l)
	return l.op, nil
}

// PublishMutable keeps a signed item stored like Publish. Publishing a newer
// item for the same key and salt replaces it.
func (n *Node) PublishMutable(now time.Time, m MutableItem) (krpc.NodeID, error) {
	if !m.Verify() {
		return krpc.NodeID{}, errors.New("dht: mutable item signature invalid")
	}
	target := m.Target()
	n.owned[target] = &owned{rec: record{v: m.V, mut: &m}, next: now}
	n.maintain(now)
	return target, nil
}

// Put stores a BEP 44 immutable item once. v is a bencoded value.
func (n *Node) Put(now time.Time, v []byte) (krpc.NodeID, OpID, error) {
	if len(v) > 1000 {
		return krpc.NodeID{}, 0, ErrTooLarge
	}
	target := krpc.NodeID(sha1.Sum(v))
	op, err := n.start(now, n.primary, putItem, target, record{v: v}, nil, false)
	return target, op, err
}

// Publish keeps an immutable item stored, republishing it periodically and
// immediately when a partition is suspected.
func (n *Node) Publish(now time.Time, v []byte) (krpc.NodeID, error) {
	if len(v) > 1000 {
		return krpc.NodeID{}, ErrTooLarge
	}
	target := krpc.NodeID(sha1.Sum(v))
	n.owned[target] = &owned{rec: record{v: slices.Clone(v)}, next: now}
	n.maintain(now)
	return target, nil
}

func (n *Node) Unpublish(target krpc.NodeID) { delete(n.owned, target) }

// start begins a lookup. Seeds with a zero ID are addresses whose identity
// is learned from their reply.
func (n *Node) start(now time.Time, t *table, kind lookupKind, target krpc.NodeID, rec record, seeds []krpc.NodeInfo, internal bool) (OpID, error) {
	l := n.startLookup(now, t, kind, target, rec, seeds, internal)
	if l == nil {
		return 0, ErrBusy
	}
	n.step(now, l)
	return l.op, nil
}

// startLookup registers a lookup without sending anything yet, so callers
// can configure it before the first step.
func (n *Node) startLookup(now time.Time, t *table, kind lookupKind, target krpc.NodeID, rec record, seeds []krpc.NodeInfo, internal bool) *lookup {
	if len(n.lookups) >= n.cfg.MaxLookups {
		return nil
	}
	n.nextOp++
	l := &lookup{
		op: n.nextOp, kind: kind, internal: internal, target: target, t: t,
		deadline: now.Add(n.cfg.LookupTimeout),
		domestic: kind == putItem && n.cfg.DomesticCopies && n.cfg.Domestic != nil,
		ips:      map[netip.AddrPort]bool{}, pfx: map[ipPrefix]int{}, rec: rec,
	}
	for _, ni := range t.closest(target, n.cfg.K*2) {
		l.add(n, ni.ID, true, ni.Addr)
	}
	for _, s := range seeds {
		l.add(n, s.ID, s.ID != krpc.NodeID{}, s.Addr)
	}
	n.lookups = append(n.lookups, l)
	return l
}

func (n *Node) startInternal(now time.Time, t *table, kind lookupKind, target krpc.NodeID, rec record) *lookup {
	if len(n.lookups) >= n.cfg.MaxLookups-4 {
		return nil
	}
	l := n.startLookup(now, t, kind, target, rec, nil, true)
	if l != nil {
		n.step(now, l)
	}
	return l
}

func (n *Node) step(now time.Time, l *lookup) {
	if l.finished {
		return
	}
	for {
		active, total := l.inflight()
		if active >= n.cfg.Alpha || total >= n.cfg.MaxInflight {
			break
		}
		c := l.next(n.cfg.K)
		if c == nil {
			break
		}
		// libtorrent builds bootstrap and refresh on get_peers and never
		// sends find_node, so a node that does stands out.
		q, a := "get_peers", krpc.Args{InfoHash: &l.target}
		if l.kind != findNode {
			q, a = "get", krpc.Args{Target: &l.target}
		}
		if !n.send(now, c.addr, q, a, &txn{kind: txLookup, lookup: l}) {
			break
		}
		c.state = inflight
		l.queried++
	}
	// Like libtorrent, queries past the short timeout no longer hold the
	// lookup open: one dead node near the target would otherwise add a full
	// query timeout to every lookup that passes it.
	if active, _ := l.inflight(); active == 0 && l.next(n.cfg.K) == nil {
		n.finish(now, l)
	}
}

func (n *Node) finish(now time.Time, l *lookup) {
	if l.finished {
		return
	}
	l.finished = true
	switch l.kind {
	case findNode:
		n.complete(now, l, LookupDone{Op: l.op, Target: l.target, Closest: l.closestResponded(n.cfg.K), Queried: l.queried, Failures: l.failures})
	case getItem:
		g := GetDone{Op: l.op, Target: l.target, Value: l.value, Queried: l.queried}
		if l.best != nil {
			g.Value, g.Item = l.best.V, l.best
		}
		slices.SortFunc(l.holders, func(a, b *cand) int { return compareID(a.dist, b.dist) })
		n.complete(now, l, g)
	case putItem:
		for _, c := range l.replicas(n.cfg.K) {
			a := l.rec.args()
			a.Token, a.CAS = c.token, l.cas
			if n.send(now, c.addr, "put", a, &txn{kind: txPut, lookup: l, domestic: c.domestic, token: c.token}) {
				l.putPending++
			}
		}
		if l.putPending > 0 {
			return // removed when the last put resolves
		}
		n.complete(now, l, PutDone{Op: l.op, Target: l.target})
	}
	n.removeLookup(l)
}

func (n *Node) complete(now time.Time, l *lookup, e Event) {
	if l.onDone != nil {
		l.onDone(now, l)
		return
	}
	n.emit(l, e)
}

func (n *Node) emit(l *lookup, e Event) {
	if !l.internal {
		n.events = append(n.events, e)
	}
}

func (n *Node) removeLookup(l *lookup) {
	n.lookups = slices.DeleteFunc(n.lookups, func(x *lookup) bool { return x == l })
}

func (n *Node) putResolved(now time.Time, l *lookup, t *txn, ok bool) {
	if ok {
		l.putAcks++
		if t.domestic {
			l.putDomAcks++
		}
		r := ackedReplica{addr: t.to, token: t.token, domestic: t.domestic, dist: distance(l.target, l.target)}
		if c := l.byAddr(t.to); c != nil {
			r.dist = c.dist
		}
		i, _ := slices.BinarySearchFunc(l.acked, r, func(a, b ackedReplica) int { return compareID(a.dist, b.dist) })
		l.acked = slices.Insert(l.acked, i, r)
	}
	if l.putPending--; l.putPending == 0 {
		n.complete(now, l, PutDone{Op: l.op, Target: l.target, Stored: l.putAcks, Domestic: l.putDomAcks})
		n.removeLookup(l)
	}
}

// ---- inbound ----

func (n *Node) HandlePacket(now time.Time, from netip.AddrPort, b []byte) {
	from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
	if len(b) > 0 && b[0] != 'd' {
		// Not KRPC: relayed traffic between a pair, if we relay for one.
		if n.relaying() {
			n.relayForward(now, from, b)
		}
		return
	}
	var m krpc.Msg
	if krpc.Unmarshal(b, &m) != nil {
		return
	}
	switch m.Y {
	case krpc.Query:
		n.handleQuery(now, from, &m)
	case krpc.Response, krpc.Err:
		n.handleReply(now, from, &m)
	}
}

func (n *Node) handleReply(now time.Time, from netip.AddrPort, m *krpc.Msg) {
	if len(m.T) != 2 {
		return
	}
	tid := binary.BigEndian.Uint16(m.T)
	t := n.txns[tid]
	if t == nil || t.to != from {
		return
	}
	delete(n.txns, tid)
	if t.tracked {
		n.health.record(false)
	}
	if n.isolationMode() {
		n.iso.heard(n.isDomestic(from.Addr()), now)
	}
	if m.Y == krpc.Response {
		if !m.RO {
			n.tableFor(m.R.ID).heard(m.R.ID, from, now)
		}
		n.reflect(from, m.IP, now)
	}
	switch t.kind {
	case txLookup:
		n.lookupReply(now, t.lookup, from, m)
	case txPut:
		n.putResolved(now, t.lookup, t, m.Y == krpc.Response)
	case txKeepalive:
		if m.Y == krpc.Response {
			n.keepaliveReply(now, t.holder, m)
		}
	case txOffer:
		n.offerAcked(t.signal, t.attempt, m.Y == krpc.Response)
	case txAnswerToken:
		n.answerToken(now, from, m, t.session)
	}
}

func (n *Node) lookupReply(now time.Time, l *lookup, from netip.AddrPort, m *krpc.Msg) {
	if l.finished {
		return
	}
	c := l.byAddr(from)
	if c == nil {
		return
	}
	if m.Y != krpc.Response || (c.idKnown && c.id != m.R.ID) || !l.t.accept(m.R.ID, from.Addr()) {
		c.state = failed
		l.failures++
		n.step(now, l)
		return
	}
	if !c.idKnown {
		l.identify(c, m.R.ID)
	}
	c.state = responded
	c.token = m.R.Token
	for _, ni := range m.R.Nodes {
		l.add(n, ni.ID, true, ni.Addr)
	}
	for _, ni := range m.R.Nodes6 {
		l.add(n, ni.ID, true, ni.Addr)
	}
	if l.kind == getItem && l.key != nil {
		if mi, ok := mutableFromReturn(&m.R, l.salt); ok && mi.Key == *l.key && mi.Verify() {
			switch {
			case l.best == nil || mi.Seq > l.best.Seq:
				mi.V = slices.Clone(mi.V)
				l.best, l.holders = mi, []*cand{c}
			case mi.Seq == l.best.Seq:
				l.holders = append(l.holders, c)
			}
		}
	} else if l.kind == getItem && m.R.V != nil && krpc.NodeID(sha1.Sum(m.R.V)) == l.target {
		l.value = slices.Clone(m.R.V)
		n.finish(now, l)
		return
	}
	n.step(now, l)
}

func (n *Node) handleQuery(now time.Time, from netip.AddrPort, q *krpc.Msg) {
	if n.handleSignal(now, from, q) {
		if !n.cfg.ReadOnly {
			r := krpc.Msg{T: q.T, Y: krpc.Response, IP: from, V: n.cfg.Version, R: krpc.Return{ID: n.cfg.ID, P: int(from.Port())}}
			n.sends = append(n.sends, Send{To: from, Data: krpc.AppendMarshal(nil, &r)})
		}
		return
	}
	if n.cfg.ReadOnly {
		return
	}
	t := n.tableFor(q.A.ID)
	if !q.RO && t.wantsVerify(q.A.ID, from) && n.verifying() < 8 {
		n.send(now, from, "ping", krpc.Args{}, &txn{kind: txPing})
	}
	r := krpc.Msg{T: q.T, Y: krpc.Response, IP: from, V: n.cfg.Version, R: krpc.Return{ID: n.cfg.ID, P: int(from.Port())}}
	switch q.Q {
	case "ping":
	case "find_node":
		if q.A.Target == nil {
			n.reject(from, q, krpc.ErrProtocol, "missing target")
			return
		}
		r.R.Nodes, r.R.Nodes6 = n.referrals(t, *q.A.Target, from, q.A.Want)
	case "get_peers":
		if q.A.InfoHash == nil {
			n.reject(from, q, krpc.ErrProtocol, "missing info_hash")
			return
		}
		r.R.Nodes, r.R.Nodes6 = n.referrals(t, *q.A.InfoHash, from, q.A.Want)
		r.R.Token = n.token(from.Addr(), n.secret)
	case "announce_peer":
		if !n.validToken(from.Addr(), q.A.Token) {
			n.reject(from, q, krpc.ErrProtocol, "invalid token")
			return
		}
		if q.A.InfoHash != nil {
			n.relayAnnounce(now, from, *q.A.InfoHash)
		}
	case "get":
		if q.A.Target == nil {
			n.reject(from, q, krpc.ErrProtocol, "missing target")
			return
		}
		r.R.Nodes, r.R.Nodes6 = n.referrals(t, *q.A.Target, from, q.A.Want)
		r.R.Token = n.token(from.Addr(), n.secret)
		n.fwd.touch(*q.A.Target, from, now)
		if it := n.items[*q.A.Target]; it != nil && now.Before(it.expires) {
			switch {
			case it.mut == nil:
				r.R.V = it.v
			case q.A.Seq == nil || it.mut.Seq > *q.A.Seq:
				seq := it.mut.Seq
				r.R.V, r.R.K, r.R.Sig, r.R.Seq = it.mut.V, it.mut.Key[:], it.mut.Sig[:], &seq
			default:
				seq := it.mut.Seq
				r.R.Seq = &seq
			}
		}
	case "put":
		if !n.validToken(from.Addr(), q.A.Token) {
			n.reject(from, q, krpc.ErrProtocol, "invalid token")
			return
		}
		if len(q.A.V) == 0 {
			n.reject(from, q, krpc.ErrProtocol, "missing v")
			return
		}
		if len(q.A.V) > MaxValueSize {
			n.reject(from, q, ErrCodeTooBig, "message (v field) too big")
			return
		}
		if q.A.K == nil {
			n.store(now, krpc.NodeID(sha1.Sum(q.A.V)), record{v: q.A.V}, t == n.comm)
			break
		}
		if code, msg := n.putMutable(now, from, q, t == n.comm); code != 0 {
			n.reject(from, q, code, msg)
			return
		}
	default:
		n.reject(from, q, krpc.ErrMethodUnknown, "Method Unknown")
		return
	}
	n.sends = append(n.sends, Send{To: from, Data: krpc.AppendMarshal(nil, &r)})
}

func (n *Node) verifying() int {
	c := 0
	for _, t := range n.txns {
		if t.kind == txPing {
			c++
		}
	}
	return c
}

func (n *Node) reject(to netip.AddrPort, q *krpc.Msg, code int, msg string) {
	e := krpc.Msg{T: q.T, Y: krpc.Err, V: n.cfg.Version, E: &krpc.Error{Code: code, Msg: msg}}
	n.sends = append(n.sends, Send{To: to, Data: krpc.AppendMarshal(nil, &e)})
}

// Tokens are 4 bytes, like libtorrent's.
func (n *Node) token(ip netip.Addr, secret [8]byte) []byte {
	h := sha1.New()
	h.Write(secret[:])
	b, _ := ip.Unmap().MarshalBinary()
	h.Write(b)
	return h.Sum(nil)[:4]
}

func (n *Node) validToken(ip netip.Addr, tok []byte) bool {
	return len(tok) == 4 && (string(tok) == string(n.token(ip, n.secret)) || string(tok) == string(n.token(ip, n.prevSecret)))
}

// putMutable validates and stores a BEP 44 mutable put, returning a nonzero
// error code on rejection.
func (n *Node) putMutable(now time.Time, from netip.AddrPort, q *krpc.Msg, community bool) (int, string) {
	a := &q.A
	if len(a.Salt) > MaxSaltSize {
		return ErrCodeSaltTooBig, "salt (salt field) too big"
	}
	if len(a.K) != 32 || len(a.Sig) != 64 || a.Seq == nil {
		return krpc.ErrProtocol, "invalid mutable put"
	}
	m := &MutableItem{Key: [32]byte(a.K), Salt: slices.Clone(a.Salt), Seq: *a.Seq, V: slices.Clone(a.V), Sig: [64]byte(a.Sig)}
	if !m.Verify() {
		return ErrCodeBadSignature, "invalid signature"
	}
	if n.relay(now, from, m) {
		return 0, ""
	}
	target := m.Target()
	if cur := n.items[target]; cur != nil && cur.mut != nil && now.Before(cur.expires) {
		if a.CAS != nil && *a.CAS != cur.mut.Seq {
			return ErrCodeCASMismatch, "CAS mismatched, re-read value and try again"
		}
		if m.Seq < cur.mut.Seq || (m.Seq == cur.mut.Seq && string(m.V) != string(cur.mut.V)) {
			return ErrCodeSeqTooLow, "sequence number less than current"
		}
	}
	n.store(now, target, record{v: m.V, mut: m}, community)
	n.fwd.bind(target, from, m.Seq, now)
	return 0, ""
}

func (n *Node) store(now time.Time, target krpc.NodeID, rec record, community bool) {
	if _, ok := n.items[target]; !ok && len(n.items) >= n.cfg.MaxItems {
		var soonest krpc.NodeID
		var at time.Time
		for k, it := range n.items {
			if at.IsZero() || it.expires.Before(at) || (it.expires.Equal(at) && compareID(k, soonest) < 0) {
				soonest, at = k, it.expires
			}
		}
		delete(n.items, soonest)
	}
	if it := n.items[target]; it != nil {
		it.expires, it.lastPut = now.Add(n.cfg.ItemLifetime), now
		it.community = it.community || community
		if rec.mut != nil {
			it.record = rec
		}
		return
	}
	if rec.mut == nil {
		rec.v = slices.Clone(rec.v)
	}
	n.items[target] = &item{record: rec, expires: now.Add(n.cfg.ItemLifetime), lastPut: now, community: community}
}

// ---- time ----

func (n *Node) Tick(now time.Time) {
	n.expire(now)
	n.signalTimeouts(now)
	if !now.Before(n.nextMaint) {
		n.maintain(now)
	}
}

func (n *Node) expire(now time.Time) {
	var tids []uint16
	for tid := range n.txns {
		tids = append(tids, tid)
	}
	slices.Sort(tids)
	for _, tid := range tids {
		t := n.txns[tid]
		if now.Sub(t.sent) >= n.cfg.QueryTimeout {
			delete(n.txns, tid)
			n.timedOut(now, t)
			continue
		}
		if t.kind == txLookup && !t.slow && now.Sub(t.sent) >= n.cfg.ShortTimeout {
			t.slow = true
			if c := t.lookup.byAddr(t.to); c != nil && c.state == inflight {
				c.slow = true
			}
			n.step(now, t.lookup)
		}
	}
	for _, l := range slices.Clone(n.lookups) {
		if !l.finished && !now.Before(l.deadline) {
			n.finish(now, l)
		}
	}
}

func (n *Node) timedOut(now time.Time, t *txn) {
	if t.tracked {
		n.health.record(true)
	}
	if n.isolationMode() && !n.isDomestic(t.to.Addr()) {
		n.iso.foreignFailed(t.to)
	}
	threshold := n.cfg.EvictAfterFailures
	if n.health.suspected {
		threshold = 1
	}
	for _, tb := range []*table{n.comm, n.main} {
		if tb == nil {
			continue
		}
		if p := tb.failed(t.to, threshold); p != nil {
			n.ping(now, p)
		}
	}
	switch t.kind {
	case txLookup:
		l := t.lookup
		if c := l.byAddr(t.to); c != nil && c.state == inflight {
			c.state = failed
			l.failures++
		}
		n.step(now, l)
	case txPut:
		n.putResolved(now, t.lookup, t, false)
	case txKeepalive:
		n.keepaliveFailed(now, t.holder)
	}
}

func (n *Node) maintain(now time.Time) {
	n.nextMaint = now.Add(n.cfg.MaintenanceInterval)
	if now.Sub(n.rotated) >= n.cfg.TokenRotation {
		n.prevSecret = n.secret
		n.fillSecret(&n.secret)
		n.rotated = now
	}
	for k, it := range n.items {
		if !now.Before(it.expires) {
			delete(n.items, k)
		}
	}
	n.fwd.expire(now)
	n.expireRelays(now)
	if n.lst != nil {
		n.ensureRecords(now)
		n.keepalive(now)
	}
	if n.cfg.PartitionDetection {
		if changed := n.health.eval(now); changed {
			n.events = append(n.events, PartitionChanged{Suspected: n.health.suspected})
			if n.health.suspected {
				n.onPartition(now)
			}
		}
	}
	if n.isolationMode() {
		if changed := n.iso.eval(now); changed {
			n.events = append(n.events, IsolationChanged{Isolated: n.iso.isolated})
			if n.iso.isolated {
				n.onPartition(now)
			}
		}
		if n.iso.isolated {
			if a, ok := n.iso.probeDue(now); ok {
				n.send(now, a, "ping", krpc.Args{}, &txn{kind: txPing})
			}
			n.replicateHeld(now)
		}
	}
	for _, t := range []*table{n.comm, n.main} {
		if t != nil {
			n.maintainTable(now, t)
		}
	}
	var due []krpc.NodeID
	for k, o := range n.owned {
		if !now.Before(o.next) {
			due = append(due, k)
		}
	}
	slices.SortFunc(due, compareID)
	for _, k := range due {
		if len(n.lookups) >= n.cfg.MaxLookups-4 {
			break
		}
		if e, ok := n.recordEpoch(k); ok {
			n.signRecord(now, e) // a fresh seq rebinds holders that lost us
		}
		o := n.owned[k]
		o.next = now.Add(n.cfg.RepublishInterval)
		if n.isRecord(k) {
			// Configure before the first step, which can finish synchronously.
			if l := n.startLookup(now, n.primary, putItem, k, o.rec, nil, true); l != nil {
				l.onDone = n.recordStored
				n.step(now, l)
			}
			continue
		}
		n.startInternal(now, n.primary, putItem, k, o.rec)
	}
}

// replicateHeld re-puts community items we hold that nobody has re-put
// within the republish interval, as original Kademlia does, keeping records
// alive for the length of a shutdown. The interval is jittered per item so
// holders don't all fire together, and the first holder's put resets the
// others' timers.
func (n *Node) replicateHeld(now time.Time) {
	var due []krpc.NodeID
	for k, it := range n.items {
		jitter := time.Duration(binary.BigEndian.Uint16(k[18:])) * n.cfg.RepublishInterval / 4 / 65536
		if it.community && now.Sub(it.lastPut) >= n.cfg.RepublishInterval+jitter {
			due = append(due, k)
		}
	}
	slices.SortFunc(due, compareID)
	for _, k := range due[:min(len(due), 4)] {
		if len(n.lookups) >= n.cfg.MaxLookups-4 {
			return
		}
		it := n.items[k]
		it.lastPut, it.expires = now, now.Add(n.cfg.ItemLifetime)
		n.startInternal(now, n.primary, putItem, k, it.record)
	}
}

// onPartition refreshes every bucket and republishes everything we own, so
// records move onto the surviving side quickly.
func (n *Node) onPartition(now time.Time) {
	for _, t := range []*table{n.comm, n.main} {
		if t == nil {
			continue
		}
		for i := range t.buckets {
			t.buckets[i].changed = time.Time{}
		}
	}
	for _, o := range n.owned {
		o.next = now
	}
}

func (n *Node) maintainTable(now time.Time, t *table) {
	if t.len() == 0 {
		return
	}
	pings := 2
	if n.health.suspected {
		pings = 8
	}
	t.each(func(e *entry) {
		stale := now.Sub(e.lastResp) >= n.cfg.QuestionableAfter ||
			(n.health.suspected && e.lastResp.Before(n.health.since))
		if pings > 0 && stale && now.Sub(e.lastPing) >= n.cfg.QueryTimeout {
			n.ping(now, e)
			pings--
		}
	})
	for i := 0; i < t.depth(); i++ {
		if now.Sub(t.buckets[i].changed) >= n.cfg.RefreshInterval {
			t.buckets[i].changed = now
			n.startInternal(now, t, findNode, t.randomIDInBucket(i, n.cfg.Rand), record{})
			break
		}
	}
}

func cryptoSeed() (s [32]byte) {
	rand.Read(s[:])
	return s
}

// ImmutableValue bencodes s as a string, the usual BEP 44 immutable payload.
func ImmutableValue(s []byte) []byte { return bencode.AppendBytes(nil, s) }

// Contacts returns up to n live routing contacts closest to our own ID,
// for example to reflect a fresh socket's public address.
func (n *Node) Contacts(k int) []krpc.NodeInfo { return n.primary.closest(n.cfg.ID, k) }

const maxReflections = 64

// noteDestination numbers a destination the first time we send to it: under
// endpoint-dependent mapping, that is when our NAT creates its mapping.
func (n *Node) noteDestination(to netip.AddrPort) {
	if n.destOrder == nil {
		n.destOrder = map[netip.AddrPort]int{}
	}
	if _, ok := n.destOrder[to]; !ok && len(n.destOrder) < 4*maxReflections {
		n.destOrder[to] = len(n.destOrder)
	}
}

// reflect records one observation per destination, ordered by mapping
// creation rather than reply arrival.
func (n *Node) reflect(from, mapped netip.AddrPort, now time.Time) {
	if !mapped.IsValid() || len(n.reflections) >= maxReflections {
		return
	}
	for _, r := range n.reflections {
		if r.From == from {
			return // a reused mapping adds no allocation information
		}
	}
	order, ok := n.destOrder[from]
	if !ok {
		order = -1
	}
	n.reflections = append(n.reflections, Reflection{From: from, Mapped: mapped, At: now, Order: order})
}

// referrals returns the closest contacts split by address family, since
// "nodes" holds only 26-byte IPv4 entries and "nodes6" only 38-byte IPv6
// ones (BEP 32). It returns the families the querier asked for with "want",
// or by default its own.
func (n *Node) referrals(t *table, target krpc.NodeID, from netip.AddrPort, want []string) (v4, v6 []krpc.NodeInfo) {
	wantV4, wantV6 := from.Addr().Unmap().Is4(), !from.Addr().Unmap().Is4()
	if len(want) > 0 {
		wantV4, wantV6 = slices.Contains(want, "n4"), slices.Contains(want, "n6")
	}
	cands := t.closest(target, 4*n.cfg.K)
	if s := n.sibling; s != nil {
		st := s.main
		if t == n.comm {
			st = s.comm
		}
		if st != nil {
			cands = append(cands, st.closest(target, 4*n.cfg.K)...)
		}
	}
	for _, ni := range cands {
		if ni.Addr.Addr().Unmap().Is4() {
			if wantV4 && len(v4) < n.cfg.K {
				v4 = append(v4, ni)
			}
		} else if wantV6 && len(v6) < n.cfg.K {
			v6 = append(v6, ni)
		}
	}
	if wantV4 && v4 == nil {
		v4 = []krpc.NodeInfo{}
	}
	return v4, v6
}
