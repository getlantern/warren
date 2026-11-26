// Package driver runs dht.Nodes over real UDP sockets: one node, or an IPv4
// and an IPv6 node paired as siblings, as libtorrent runs one node per
// address family. One goroutine owns every node: packets, operations, and
// timers are serialized through it, so the sans-IO core stays
// single-threaded exactly as in the simulator, and siblings can call each
// other directly.
package driver

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/getlantern/warren/dht"
	"github.com/getlantern/warren/krpc"
)

const (
	inboxSize   = 128 // datagrams queued between the readers and the loop
	eventsSize  = 32
	maxPacket   = 2048
	maxSessions = 1024 // incoming signaling sessions remembered for Answer
	// writeTimeout bounds how long the loop waits on a full send buffer.
	writeTimeout = 200 * time.Millisecond
)

var ErrClosed = errors.New("driver: closed")

// listenUDP binds sockets; tests replace it to simulate bind failures.
var listenUDP = net.ListenUDP

type packet struct {
	fam  int
	conn *net.UDPConn // the socket it arrived on
	from netip.AddrPort
	data []byte
}

// family is one address family's socket and node. conn and addr change on
// Rebind, on the loop goroutine, under Node.mu; Close and Addr read them
// under Node.mu, the loop without it.
type family struct {
	network  string       // "udp4" or "udp6"
	bindAddr *net.UDPAddr // resolved once at Listen: rebinding mustn't block the loop on DNS
	conn     *net.UDPConn
	addr     netip.AddrPort
	node     *dht.Node
	stale    bool // the last rebind failed: still on the old network or socketless
}

type waitKey struct {
	fam int
	op  dht.OpID
}

type Node struct {
	fams   []*family // the primary (IPv4 when present) first
	inbox  chan packet
	ops    chan func(time.Time)
	events chan dht.Event
	done   chan struct{}
	once   sync.Once
	wg     sync.WaitGroup
	// waiters and sessions are owned by the loop goroutine; operation
	// closures run there and register before any of their events can be
	// delivered.
	waiters  map[waitKey]chan dht.Event
	sessions map[dht.SessionID]int // which family delivered each offer
	order    []dht.SessionID       // sessions oldest first, for eviction
	mu       sync.Mutex            // guards each family's conn and addr, and closed
	closed   bool
}

var ErrUnknownSession = errors.New("driver: unknown signaling session")

// Listen binds an IPv4 UDP socket (e.g. ":6881" or "127.0.0.1:0") and starts
// one node on it.
func Listen(addr string, cfg dht.Config) (*Node, error) {
	f, err := bind("udp4", addr, cfg)
	if err != nil {
		return nil, err
	}
	return start([]*family{f}), nil
}

// ListenDual binds an IPv4 and an IPv6 socket (e.g. ":6881" and "[::]:6881")
// and runs a node on each, paired as siblings: each answers queries that
// want the other family from the other's table. The configs differ at least
// in ID, since a BEP 42 ID derives from that family's external address. If
// the host can't bind IPv6, the IPv4 node runs alone; if it can't bind IPv4,
// the IPv6 node does. It fails only if neither binds.
func ListenDual(addr4, addr6 string, cfg4, cfg6 dht.Config) (*Node, error) {
	var fams []*family
	f4, err4 := bind("udp4", addr4, cfg4)
	if err4 == nil {
		fams = append(fams, f4)
	}
	f6, err6 := bind("udp6", addr6, cfg6)
	if err6 == nil {
		fams = append(fams, f6)
	}
	if len(fams) == 0 {
		return nil, errors.Join(err4, err6)
	}
	if len(fams) == 2 {
		f4.node.SetSibling(f6.node)
		f6.node.SetSibling(f4.node)
	}
	return start(fams), nil
}

func bind(network, addr string, cfg dht.Config) (*family, error) {
	ua, err := net.ResolveUDPAddr(network, addr)
	if err != nil {
		return nil, err
	}
	conn, err := listenUDP(network, ua)
	if err != nil {
		return nil, err
	}
	return &family{network: network, bindAddr: ua, conn: conn, addr: localAddr(conn), node: dht.New(cfg)}, nil
}

func localAddr(c *net.UDPConn) netip.AddrPort {
	a := c.LocalAddr().(*net.UDPAddr).AddrPort()
	return netip.AddrPortFrom(a.Addr().Unmap(), a.Port())
}

func start(fams []*family) *Node {
	n := &Node{
		fams:     fams,
		inbox:    make(chan packet, inboxSize),
		ops:      make(chan func(time.Time)),
		events:   make(chan dht.Event, eventsSize),
		done:     make(chan struct{}),
		waiters:  map[waitKey]chan dht.Event{},
		sessions: map[dht.SessionID]int{},
	}
	for i, f := range fams {
		conn := f.conn // captured now: a Rebind may replace f.conn before the reader runs
		n.wg.Go(func() { n.read(i, conn) })
	}
	n.wg.Go(n.loop)
	return n
}

// Addr is the primary node's address: IPv4 when it is running.
func (n *Node) Addr() netip.AddrPort {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.fams[0].addr
}

// Addrs lists every running node's address, the primary first.
func (n *Node) Addrs() []netip.AddrPort {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]netip.AddrPort, len(n.fams))
	for i, f := range n.fams {
		out[i] = f.addr
	}
	return out
}

// Events delivers events not tied to a caller's operation, such as
// PartitionChanged, IsolationChanged and Incoming, from every node. Events
// are dropped if not consumed. The channel is closed when the node shuts
// down.
func (n *Node) Events() <-chan dht.Event { return n.events }

func (n *Node) Close() error {
	n.once.Do(func() {
		close(n.done)
		// Close the sockets here, not just in the loop: a loop blocked in a
		// write is only freed by closing its socket.
		n.mu.Lock()
		n.closed = true
		for _, f := range n.fams {
			if f.conn != nil {
				f.conn.Close()
			}
		}
		n.mu.Unlock()
	})
	n.wg.Wait()
	return nil
}

// read copies each datagram from one socket to an exact-size buffer and
// drops it if the loop is behind, bounding memory under load. It stops
// when its socket closes: at shutdown, or when Rebind replaces it.
func (n *Node) read(fam int, conn *net.UDPConn) {
	buf := make([]byte, maxPacket)
	for {
		sz, from, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case <-n.done:
				return
			default:
				continue
			}
		}
		p := packet{fam: fam, conn: conn, from: netip.AddrPortFrom(from.Addr().Unmap(), from.Port()), data: append([]byte(nil), buf[:sz]...)}
		select {
		case n.inbox <- p:
		default:
		}
	}
}

func (n *Node) loop() {
	defer close(n.events) // consumers ranging over Events stop at shutdown
	defer func() {
		for _, f := range n.fams {
			if f.conn != nil {
				f.conn.Close() // unblocks the readers
			}
		}
	}()
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		select {
		case <-n.done:
			return
		case p := <-n.inbox:
			if n.current(p) {
				n.fams[p.fam].node.HandlePacket(time.Now(), p.from, p.data)
			}
		case f := <-n.ops:
			f(time.Now())
		case <-timer.C:
			now := time.Now()
			for _, f := range n.fams {
				f.node.Tick(now)
			}
		}
		var wake time.Time
		for i, f := range n.fams {
			n.flush(i, f)
			if w := f.node.NextWakeup(); !w.IsZero() && (wake.IsZero() || w.Before(wake)) {
				wake = w
			}
		}
		if !wake.IsZero() {
			timer.Reset(max(time.Until(wake), 0))
		}
	}
}

// current reports whether p arrived on its family's present socket. A
// packet from a socket Rebind replaced belongs to the old network: a reply
// to a query sent before the change would put an old-network mapping back
// among the fresh reflections.
func (n *Node) current(p packet) bool { return p.conn == n.fams[p.fam].conn }

// flush sends one family's datagrams and routes its events.
func (n *Node) flush(fam int, f *family) {
	sends, events := f.node.Drain()
	if f.conn != nil && len(sends) > 0 { // nil only if a rebind couldn't bind this family
		// A full send buffer must not stall the loop (and with it Rebind,
		// timers and inbound packets): a datagram that can't go out in time
		// is dropped, as the network might have dropped it.
		_ = f.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		for _, s := range sends {
			f.conn.WriteToUDPAddrPort(s.Data, s.To)
		}
	}
	for _, e := range events {
		if in, ok := e.(dht.Incoming); ok {
			n.deliverIncoming(fam, in)
			continue
		}
		op, ok := opOf(e)
		if ch := n.waiters[waitKey{fam, op}]; ok && ch != nil {
			ch <- e
			delete(n.waiters, waitKey{fam, op})
			continue
		}
		select {
		case n.events <- e:
		default:
		}
	}
}

// deliverIncoming hands an offer to the application unless it was already
// delivered (the same offer through the other family's DHT is a replay:
// each node dedupes only its own). The session and its answer route are
// recorded only once the offer is actually delivered, so one dropped on a
// full channel can still arrive through the other family.
func (n *Node) deliverIncoming(fam int, in dht.Incoming) {
	if _, seen := n.sessions[in.Session]; seen {
		return
	}
	select {
	case n.events <- in:
		n.admitSession(fam, in)
	default:
	}
}

// admitSession records which family delivered an offer, reporting false
// for an offer already seen: the same offer through the other family's DHT
// is a replay, since each node dedupes only its own. An unanswered flood
// evicts the oldest sessions.
func (n *Node) admitSession(fam int, in dht.Incoming) bool {
	if _, seen := n.sessions[in.Session]; seen {
		return false
	}
	if len(n.order) >= maxSessions {
		delete(n.sessions, n.order[0])
		n.order = n.order[1:]
	}
	n.sessions[in.Session] = fam
	n.order = append(n.order, in.Session)
	return true
}

func opOf(e dht.Event) (dht.OpID, bool) {
	switch e := e.(type) {
	case dht.LookupDone:
		return e.Op, true
	case dht.GetDone:
		return e.Op, true
	case dht.PutDone:
		return e.Op, true
	case dht.Answered:
		return e.Op, true
	case dht.SignalFailed:
		return e.Op, true
	}
	return 0, false
}

// do runs f on the loop goroutine.
func (n *Node) do(ctx context.Context, f func(time.Time)) error {
	select {
	case n.ops <- f:
		return nil
	case <-n.done:
		return ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

// each runs f against every node on the loop goroutine and returns the
// errors, one per family.
func (n *Node) each(ctx context.Context, f func(fam int, d *dht.Node, now time.Time) error) ([]error, error) {
	errs := make(chan []error, 1)
	if err := n.do(ctx, func(now time.Time) {
		out := make([]error, len(n.fams))
		for i, fm := range n.fams {
			out[i] = f(i, fm.node, now)
		}
		errs <- out
	}); err != nil {
		return nil, err
	}
	return <-errs, nil
}

// anyOK returns nil if any family succeeded, else the first error.
func anyOK(errs []error) error {
	for _, err := range errs {
		if err == nil {
			return nil
		}
	}
	return errs[0]
}

// call starts an operation on every node that start accepts (start returns
// skip to leave a family out) and collects completion events until all have
// arrived or enough reports that the result is settled. It fails only if no
// node started the operation; partial reports a node that failed to start,
// whose family the result therefore doesn't cover.
func (n *Node) call(ctx context.Context, start func(fam int, d *dht.Node, now time.Time) (op dht.OpID, skip bool, err error), enough func(dht.Event) bool) (got []dht.Event, partial, err error) {
	ch := make(chan dht.Event, len(n.fams))
	type started struct {
		count int
		err   error
	}
	sc := make(chan started, 1)
	if err := n.do(ctx, func(now time.Time) {
		var s started
		for i, f := range n.fams {
			op, skip, err := start(i, f.node, now)
			switch {
			case skip:
			case err != nil:
				if s.err == nil {
					s.err = err
				}
			default:
				n.waiters[waitKey{i, op}] = ch
				s.count++
			}
		}
		sc <- s
	}); err != nil {
		return nil, nil, err
	}
	s := <-sc
	if s.count == 0 {
		if s.err == nil {
			s.err = errors.New("driver: no node for this operation")
		}
		return nil, nil, s.err
	}
	for len(got) < s.count {
		select {
		case e := <-ch:
			got = append(got, e)
			if enough != nil && enough(e) {
				return got, s.err, nil
			}
		case <-n.done:
			return got, s.err, ErrClosed
		case <-ctx.Done():
			return got, s.err, ctx.Err()
		}
	}
	return got, s.err, nil
}

// sumPuts adds up the families' store acknowledgements.
func sumPuts(got []dht.Event) dht.PutDone {
	var out dht.PutDone
	for i, e := range got {
		p := e.(dht.PutDone)
		if i == 0 {
			out = p
			continue
		}
		out.Stored += p.Stored
		out.Domestic += p.Domestic
	}
	return out
}

func unmap(a netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(a.Addr().Unmap(), a.Port())
}

func (n *Node) isFamily(fam int, a netip.Addr) bool {
	return (n.fams[fam].network == "udp4") == a.Unmap().Is4()
}

// Rebind replaces every family's socket after a network change (Wi-Fi to
// cellular, a new IP) and tells each node, which forgets the old network's
// reflections and, when listening, republishes its records so holders
// forward to the new address. Routing tables, stored items and records
// survive. A socket bound to an ephemeral port gets a new one; a fixed port
// is reused when possible, else falls back to an ephemeral one. It returns
// the families that couldn't bind; those send nothing until a later Rebind
// succeeds.
func (n *Node) Rebind(ctx context.Context) error {
	return n.rebind(ctx, func(*family) bool { return true })
}

// RebindStale retries only the families whose last rebind failed, leaving
// healthy sockets alone. It returns nil when none are stale.
func (n *Node) RebindStale(ctx context.Context) error {
	return n.rebind(ctx, func(f *family) bool { return f.stale })
}

// Stale reports whether some family's last rebind failed.
func (n *Node) Stale(ctx context.Context) (bool, error) {
	out := make(chan bool, 1)
	if err := n.do(ctx, func(time.Time) {
		stale := false
		for _, f := range n.fams {
			stale = stale || f.stale
		}
		out <- stale
	}); err != nil {
		return false, err
	}
	return <-out, nil
}

func (n *Node) rebind(ctx context.Context, which func(*family) bool) error {
	errc := make(chan error, 1)
	if err := n.do(ctx, func(now time.Time) {
		var errs []error
		for i, f := range n.fams {
			if !which(f) {
				continue
			}
			conn, err := n.rebindFamily(f)
			if err != nil {
				f.stale = true
				errs = append(errs, fmt.Errorf("rebind %s: %w", f.network, err))
				continue
			}
			f.stale = false
			n.wg.Go(func() { n.read(i, conn) })
			f.node.Rebound(now)
		}
		errc <- errors.Join(errs...)
	}); err != nil {
		return err
	}
	return <-errc
}

// rebindFamily binds a fresh socket for f, installs it, and closes the old
// one. Runs on the loop goroutine.
func (n *Node) rebindFamily(f *family) (*net.UDPConn, error) {
	ua := *f.bindAddr // a copy: the ephemeral fallback changes its port
	var conn *net.UDPConn
	var err error
	if ua.Port == 0 {
		// An ephemeral port: bind the new socket before closing the old.
		if conn, err = listenUDP(f.network, &ua); err != nil {
			// The old socket is on the old network: close it, so the family
			// sends nothing (and hears nothing stale) until a retry binds.
			n.swap(f, nil)
			return nil, err
		}
	} else {
		// A fixed port must be released first.
		n.swap(f, nil)
		if conn, err = listenUDP(f.network, &ua); err != nil {
			ua.Port = 0
			if conn, err = listenUDP(f.network, &ua); err != nil {
				return nil, err
			}
		}
	}
	if !n.swap(f, conn) {
		conn.Close()
		return nil, ErrClosed
	}
	return conn, nil
}

// swap installs conn as f's socket and closes the old one, under the lock
// Close takes, reporting false (and installing nothing) once closed.
func (n *Node) swap(f *family, conn *net.UDPConn) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return false
	}
	if f.conn != nil {
		f.conn.Close()
	}
	f.conn = conn
	if conn != nil {
		f.addr = localAddr(conn)
	}
	return true
}

// Bootstrap looks up our own ID on each node from the seeds of its family
// (a socket can't reach the other family's); with no seeds, each node
// starts from its own table. It fails if no seed is of a family we run, and
// returns the first node's result, with an error if some family couldn't
// start.
func (n *Node) Bootstrap(ctx context.Context, seeds []netip.AddrPort) (dht.LookupDone, error) {
	got, partial, err := n.call(ctx, func(fam int, d *dht.Node, now time.Time) (dht.OpID, bool, error) {
		var mine []netip.AddrPort
		for _, s := range seeds {
			if s = unmap(s); n.isFamily(fam, s.Addr()) {
				mine = append(mine, s)
			}
		}
		if len(mine) == 0 && len(seeds) > 0 {
			return 0, true, nil // seeds given, none this socket can reach
		}
		op, err := d.Bootstrap(now, mine)
		return op, false, err
	}, nil)
	if len(got) == 0 {
		return dht.LookupDone{}, err
	}
	return got[0].(dht.LookupDone), errors.Join(err, partial)
}

// Rejoin seeds each node from saved contacts of its family; see
// dht.Node.Rejoin.
func (n *Node) Rejoin(ctx context.Context, contacts []krpc.NodeInfo) (dht.LookupDone, error) {
	got, partial, err := n.call(ctx, func(fam int, d *dht.Node, now time.Time) (dht.OpID, bool, error) {
		var mine []krpc.NodeInfo
		for _, c := range contacts {
			if c.Addr = unmap(c.Addr); n.isFamily(fam, c.Addr.Addr()) {
				mine = append(mine, c)
			}
		}
		if len(mine) == 0 && len(contacts) > 0 {
			return 0, true, nil
		}
		op, err := d.Rejoin(now, mine)
		return op, false, err
	}, nil)
	if len(got) == 0 {
		return dht.LookupDone{}, err
	}
	return got[0].(dht.LookupDone), errors.Join(err, partial)
}

// Get returns the immutable value stored under target, or nil if not found,
// from whichever node finds it first. A miss while some family couldn't
// search is an error, not a conclusive "not found".
func (n *Node) Get(ctx context.Context, target krpc.NodeID) ([]byte, error) {
	got, partial, err := n.call(ctx, func(_ int, d *dht.Node, now time.Time) (dht.OpID, bool, error) {
		op, err := d.Get(now, target)
		return op, false, err
	}, func(e dht.Event) bool { return e.(dht.GetDone).Value != nil })
	for _, e := range got {
		if v := e.(dht.GetDone).Value; v != nil {
			return v, nil // content-addressed: any hit is the answer
		}
	}
	if err != nil {
		return nil, err
	}
	return nil, partial
}

// GetItem is Get returning the whole finished lookup, with how many nodes it
// queried, how many failed, and its Timing: the first node's result, or the
// first that found the value.
func (n *Node) GetItem(ctx context.Context, target krpc.NodeID) (dht.GetDone, error) {
	got, partial, err := n.call(ctx, func(_ int, d *dht.Node, now time.Time) (dht.OpID, bool, error) {
		op, err := d.Get(now, target)
		return op, false, err
	}, func(e dht.Event) bool { return e.(dht.GetDone).Value != nil })
	for _, e := range got {
		if g := e.(dht.GetDone); g.Value != nil {
			return g, nil
		}
	}
	if len(got) > 0 {
		return got[0].(dht.GetDone), errors.Join(err, partial)
	}
	return dht.GetDone{}, errors.Join(err, partial)
}

// Put stores v through every node and returns the acknowledgements summed
// across them, including any that arrived before an error.
func (n *Node) Put(ctx context.Context, v []byte) (krpc.NodeID, dht.PutDone, error) {
	var target krpc.NodeID
	got, partial, err := n.call(ctx, func(_ int, d *dht.Node, now time.Time) (dht.OpID, bool, error) {
		t, op, err := d.Put(now, v)
		target = t
		return op, false, err
	}, nil)
	if len(got) == 0 {
		return target, dht.PutDone{}, err
	}
	// Acknowledgements add up across families, and a family that finished
	// before an error still counts; a family that never started is
	// reported alongside them.
	return target, sumPuts(got), errors.Join(err, partial)
}

// GetMutable returns the newest verified item any node found, or nil if
// none was found.
// A family that couldn't search, or an error, returns the best item found so
// far together with the error: a newer one may exist there.
func (n *Node) GetMutable(ctx context.Context, key [32]byte, salt []byte) (*dht.MutableItem, error) {
	got, partial, err := n.call(ctx, func(_ int, d *dht.Node, now time.Time) (dht.OpID, bool, error) {
		op, err := d.GetMutable(now, key, salt)
		return op, false, err
	}, nil)
	var best *dht.MutableItem
	for _, e := range got {
		if it := e.(dht.GetDone).Item; it != nil && (best == nil || it.Seq > best.Seq) {
			best = it
		}
	}
	if err != nil {
		return best, err
	}
	return best, partial
}

// PutMutable stores m through every node and returns the acknowledgements
// summed across them, including any that arrived before an error.
func (n *Node) PutMutable(ctx context.Context, m dht.MutableItem, cas *int64) (dht.PutDone, error) {
	got, partial, err := n.call(ctx, func(_ int, d *dht.Node, now time.Time) (dht.OpID, bool, error) {
		op, err := d.PutMutable(now, m, cas)
		return op, false, err
	}, nil)
	if len(got) == 0 {
		return dht.PutDone{}, err
	}
	return sumPuts(got), errors.Join(err, partial)
}

// Publish keeps an immutable value stored through every node until
// Unpublish.
func (n *Node) Publish(ctx context.Context, v []byte) (krpc.NodeID, error) {
	var target krpc.NodeID
	errs, err := n.each(ctx, func(_ int, d *dht.Node, now time.Time) error {
		t, err := d.Publish(now, v)
		target = t
		return err
	})
	if err != nil {
		return target, err
	}
	return target, anyOK(errs)
}

// PublishMutable keeps a signed item stored through every node; publish a
// higher seq to update.
func (n *Node) PublishMutable(ctx context.Context, m dht.MutableItem) error {
	errs, err := n.each(ctx, func(_ int, d *dht.Node, now time.Time) error {
		_, err := d.PublishMutable(now, m)
		return err
	})
	if err != nil {
		return err
	}
	return anyOK(errs)
}

// Snapshot returns the primary node's saved-state encoding; see
// dht.Node.Snapshot.
func (n *Node) Snapshot(ctx context.Context) ([]byte, error) {
	out := make(chan []byte, 1)
	if err := n.do(ctx, func(time.Time) { out <- n.fams[0].node.Snapshot() }); err != nil {
		return nil, err
	}
	return <-out, nil
}

// Listen makes us reachable for signaling under priv's key on every node, so
// callers of either family can reach us. Offers arrive as dht.Incoming on
// Events; reply with Answer.
func (n *Node) Listen(ctx context.Context, priv crypto.Signer) error {
	// One signaling key for every family, so their records are identical.
	x, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	errs, err := n.each(ctx, func(_ int, d *dht.Node, now time.Time) error { return d.ListenKey(now, priv, x) })
	if err != nil {
		return err
	}
	return anyOK(errs)
}

// Answer replies to an offer through the node that delivered it.
func (n *Node) Answer(ctx context.Context, s dht.SessionID, payload []byte) error {
	errc := make(chan error, 1)
	if err := n.do(ctx, func(now time.Time) {
		fam, ok := n.sessions[s]
		if !ok {
			errc <- ErrUnknownSession
			return
		}
		// Kept, not deleted: a later copy of this offer through the other
		// family must still be recognized as a replay. Eviction bounds it.
		errc <- n.fams[fam].node.Answer(now, s, payload)
	}); err != nil {
		return err
	}
	return <-errc
}

// Signal sends payload to provider through every node and returns the first
// answer, or the last failure if none answers.
func (n *Node) Signal(ctx context.Context, priv crypto.Signer, provider [32]byte, payload []byte) ([]byte, error) {
	payload = append([]byte(nil), payload...) // a slower family reads it after we return
	got, partial, err := n.call(ctx, func(_ int, d *dht.Node, now time.Time) (dht.OpID, bool, error) {
		op, err := d.Signal(now, priv, provider, payload)
		return op, false, err
	}, func(e dht.Event) bool { _, ok := e.(dht.Answered); return ok })
	if err != nil && len(got) == 0 {
		return nil, err
	}
	fail := errors.New("driver: unexpected signaling event")
	for _, e := range got {
		switch e := e.(type) {
		case dht.Answered:
			return e.Payload, nil
		case dht.SignalFailed:
			fail = e.Err
		}
	}
	if err != nil {
		return nil, err
	}
	if partial != nil {
		// A family that never searched may hold the record: a miss on the
		// other isn't "no record".
		return nil, partial
	}
	return nil, fail
}

// Inspect runs f against the primary node on the loop goroutine, for status
// queries.
func (n *Node) Inspect(ctx context.Context, f func(*dht.Node)) error {
	done := make(chan struct{})
	if err := n.do(ctx, func(time.Time) { f(n.fams[0].node); close(done) }); err != nil {
		return err
	}
	<-done
	return nil
}

// InspectEach runs f against every node, the primary first, with its
// socket's address.
func (n *Node) InspectEach(ctx context.Context, f func(addr netip.AddrPort, d *dht.Node)) error {
	done := make(chan struct{})
	if err := n.do(ctx, func(time.Time) {
		for _, fm := range n.fams {
			f(fm.addr, fm.node)
		}
		close(done)
	}); err != nil {
		return err
	}
	<-done
	return nil
}
