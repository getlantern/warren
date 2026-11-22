// Package endpoint connects to peers by public key: DHT signaling exchanges
// hole-punching offers, the punch engine finds a direct path, and the caller
// gets a connected UDP socket.
//
// The path is authenticated by construction. Only the holder of the
// provider's private key can decrypt the offer, which carries the punch
// secret, and the answer is signed by that key; punch probes carry
// secret-derived IDs. So the caller knows it reached the provider, and the
// provider learns the caller's verified key.
package endpoint

import (
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/getlantern/warren/dht"
	"github.com/getlantern/warren/driver"
	"github.com/getlantern/warren/natprobe"
	"github.com/getlantern/warren/punch"
)

var ErrClosed = errors.New("endpoint: closed")

type Config struct {
	DHT dht.Config
	// DHTAddr is the DHT socket's bind address, e.g. ":6881".
	DHTAddr string
	// DataIP is the IP data sockets bind on; empty means all interfaces.
	DataIP net.IP
	// DHTAddr6, when set (e.g. "[::]:6881"), also runs an IPv6 DHT node
	// with config DHT6, paired with the IPv4 one as libtorrent pairs its
	// per-family nodes, and connections race IPv6 against IPv4. DataIP6
	// is the IP IPv6 data sockets bind on.
	DHTAddr6 string
	DHT6     dht.Config
	DataIP6  net.IP
	// HeadStart is how long both sides give an IPv6 path before also
	// punching IPv4 (happy eyeballs); the first connected path wins.
	HeadStart time.Duration
	// Profile overrides the NAT profile otherwise inferred from the DHT
	// socket's BEP 42 reflections.
	Profile *punch.Profile
	// Authorize, if set, decides which callers a listener answers.
	Authorize func(caller [32]byte) bool
	// RelayOnly never reveals this endpoint's addresses to peers: every
	// connection goes through a relay router.
	RelayOnly bool
	// MaxInbound bounds concurrent inbound punches: each holds sockets.
	MaxInbound    int
	PunchDeadline time.Duration
	GatherWait    time.Duration
}

// Conn is a punched path to a peer, usable as a net.PacketConn whose only
// peer is Remote. Just after connecting it can still receive a few
// hole-punching control datagrams (KRPC, first byte 'd'), and a relayed one
// a few 20-byte relay probes or acks; protocols layered above drop them
// (uTP shaping and QUIC both reject them), and raw users should read with
// Recv, which skips the KRPC ones.
//
// A Conn survives a network change: Migrate (run for outbound connections
// by Endpoint.Rebind) punches a fresh path and moves the connection onto
// it, while Remote, Secret and everything layered above stay the same.
type Conn struct {
	// Remote is the peer's address as the connection reports it. It is the
	// address first punched and never changes, even after Migrate moves the
	// connection to another path.
	Remote netip.AddrPort
	// PeerKey is the provider's key for an outbound connection, the
	// caller's verified key for an inbound one.
	PeerKey [32]byte
	// Secret is shared only by the two ends, for binding a later
	// cryptographic handshake (QUIC, Noise) to this path.
	Secret []byte
	// Relayed means the first path was through a DHT router relaying to
	// the peer, used when no direct path could be punched.
	Relayed bool

	p        *path
	e        *Endpoint
	resume   [16]byte
	outbound bool
	identity ed25519.PrivateKey // signs resume offers; outbound only
	// migrateSlot serializes migrations of this connection: a newer one
	// waits for one in flight and then runs, so the latest network change
	// always gets the last word (a one-slot semaphore, so a waiter can give
	// up on ctx).
	migrateSlot chan struct{}
	slotOnce    sync.Once
	migrations  uint64 // outbound: the last migration's sequence number
	// moveReqs counts migration requests, including ones that gave up
	// waiting or failed; moveDone is the count the last successful one
	// served (what it saw when it took the slot). An older success can't
	// settle a newer request, and retries pick connections with requests
	// outstanding.
	moveReqs atomic.Uint64
	moveDone atomic.Uint64

	resumesMu sync.Mutex
	resumes   []time.Time // inbound: recent resumes, for their budget
}

// maxResumesPerMinute bounds how often one inbound connection can be moved.
// Resumes have their own budget rather than the new-connection limiter's,
// which allows only a few punches a minute per caller: moving several live
// sessions to one provider after a network change must not strand some.
// Only the caller holding a session's secret can resume it.
const maxResumesPerMinute = 6

// unmoved reports whether a migration request is outstanding: one that
// failed, gave up waiting, or arrived after the last success started.
func (c *Conn) unmoved() bool { return c.moveDone.Load() < c.moveReqs.Load() }

func (c *Conn) allowResume(now time.Time) bool {
	c.resumesMu.Lock()
	defer c.resumesMu.Unlock()
	kept := c.resumes[:0]
	for _, t := range c.resumes {
		if now.Sub(t) < time.Minute {
			kept = append(kept, t)
		}
	}
	c.resumes = kept
	if len(c.resumes) >= maxResumesPerMinute {
		return false
	}
	c.resumes = append(c.resumes, now)
	return true
}

// resumeOffer encodes a migration request: the session's resume ID and the
// migration's sequence number, which orders commits on the provider.
func resumeOffer(id [16]byte, seq uint64) []byte {
	b := make([]byte, 24)
	copy(b, id[:])
	binary.BigEndian.PutUint64(b[16:], seq)
	return b
}

func parseResume(b []byte) (id [16]byte, seq uint64, ok bool) {
	if len(b) != 24 {
		return id, 0, false
	}
	return [16]byte(b[:16]), binary.BigEndian.Uint64(b[16:]), true
}

type Endpoint struct {
	cfg     Config
	node    *driver.Node
	limiter inboundLimiter
	accept  chan *Conn
	slots   chan struct{}
	done    chan struct{}
	once    sync.Once
	wg      sync.WaitGroup
	mu      sync.Mutex
	closed  bool // guards wg.Add for outbound Connects against Close's Wait

	// routes reports the local addresses the default routes use; tests
	// replace it. WatchNetwork rebinds when they change.
	routes func() [2]netip.Addr
	// rebindDHT rebinds the DHT sockets; tests replace it.
	rebindDHT func(context.Context) error
	// migratePending: the last rebind left a DHT family or a connection
	// unmoved; WatchNetwork retries.
	migratePending atomic.Bool
	// rebinding serializes whole rebind cycles (Rebind and WatchNetwork's
	// retries), as a one-slot semaphore so a waiter can give up: a later
	// network change waits and migrates again, rather than colliding with
	// an earlier cycle that might then clear its retry state after moving
	// connections to the earlier network.
	rebinding  chan struct{}
	rebindOnce sync.Once
	// rebindReqs counts Rebind calls, including ones that gave up waiting;
	// rebindDone is the count a finished cycle has served (what it saw when
	// it started). A newer request is never acknowledged by an older cycle,
	// and WatchNetwork reruns a full rebind while any is outstanding.
	rebindReqs atomic.Uint64
	rebindDone atomic.Uint64

	connsMu sync.Mutex
	// Live connections by peer key and resume ID, inbound and outbound
	// apart: an inbound resume ID derives from a secret the caller chose, so
	// it must never select an outbound slot, or another peer's.
	inConns  map[connKey]*Conn
	outConns map[connKey]*Conn

	offersMu sync.Mutex
	offers   map[[32]byte]*offerEntry // recent offers, by caller and secret
	dupes    atomic.Int64             // repeat copies seen, for tests
}

// offerEntry is one offer being answered. A copy of it through the other
// family's DHT gets the same answer through its own session, sent at once
// if the answer is ready or by the first copy when it is. Copies never
// wait, so they hold no inbound slot, and only one is answered: a caller
// replaying its own offer gets nothing more.
type offerEntry struct {
	at       time.Time
	mu       sync.Mutex
	done     chan struct{} // closed once answer is set
	answer   []byte        // nil when there is no answer
	answered int           // copies answered or queued
	pending  []dht.SessionID
}

const maxOfferCopies = 1 // one per other address family

// copyOf handles a copy of the offer: it returns the answer to send now,
// or queues the session for the first copy to answer.
func (o *offerEntry) copyOf(s dht.SessionID) (answer []byte, now bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.answered >= maxOfferCopies {
		return nil, false
	}
	o.answered++
	select {
	case <-o.done:
		return o.answer, o.answer != nil
	default:
		o.pending = append(o.pending, s)
		return nil, false
	}
}

// publish sets the answer, once, and returns the queued copies to answer.
func (o *offerEntry) publish(answer []byte) []dht.SessionID {
	o.mu.Lock()
	defer o.mu.Unlock()
	select {
	case <-o.done:
		return nil
	default:
	}
	o.answer = answer
	close(o.done)
	p := o.pending
	o.pending = nil
	if answer == nil {
		return nil
	}
	return p
}

// publishOffer sets an offer's answer and sends it to queued copies,
// returning how many it delivered.
func (e *Endpoint) publishOffer(ctx context.Context, o *offerEntry, answer []byte) int {
	delivered := 0
	for _, s := range o.publish(answer) {
		if e.node.Answer(ctx, s, answer) == nil {
			delivered++
		}
	}
	return delivered
}

// deliverQueued sends answer to copies queued so far without making it
// visible to later ones, returning how many it delivered.
func (e *Endpoint) deliverQueued(ctx context.Context, o *offerEntry, answer []byte) int {
	o.mu.Lock()
	queued := o.pending
	o.pending = nil
	o.mu.Unlock()
	delivered := 0
	for _, s := range queued {
		if e.node.Answer(ctx, s, answer) == nil {
			delivered++
		}
	}
	return delivered
}

// wantFamilies decides which legs a provider runs for an offer: IPv4 when
// the caller offered IPv4 candidates or relays, IPv6 when it offered IPv6
// candidates and we may punch directly.
func wantFamilies(o punch.Offer, has4, has6, relayOnly bool) (v4, v6 bool) {
	f4 := o.Family(false)
	v4 = has4 && (len(f4.Candidates) > 0 || len(f4.Relays) > 0 || f4.Relay.IsValid() || relayOnly)
	v6 = has6 && !relayOnly && len(o.Family(true).Candidates) > 0
	return v4, v6
}

// probeable filters candidates to the families we'll run a leg for.
func probeable(cands []netip.AddrPort, v4, v6 bool) []netip.AddrPort {
	var out []netip.AddrPort
	for _, c := range cands {
		if is4 := c.Addr().Is4(); is4 && v4 || !is4 && v6 {
			out = append(out, c)
		}
	}
	return out
}

// maxRecentOffers bounds the offer-secret memory under a flood.
const maxRecentOffers = 4096

// firstOffer returns the entry for this caller's offer with this secret,
// reporting whether it is new. Entries are keyed by caller and secret, so
// one caller can't touch another's, and remembered for as long as the DHT
// would still accept a copy of the offer (dht.OfferWindow). When full, the oldest entry makes way: a flood can't
// make us refuse offers.
func (e *Endpoint) firstOffer(caller [32]byte, secret []byte, now time.Time) (*offerEntry, bool) {
	h := sha256.New()
	h.Write(caller[:])
	h.Write(secret)
	key := [32]byte(h.Sum(nil))
	// A copy can arrive as late as the DHT still accepts the offer: a
	// slower family's signal keeps retrying after the first answer.
	ttl := max(2*(e.cfg.GatherWait+e.cfg.PunchDeadline), dht.OfferWindow)
	e.offersMu.Lock()
	defer e.offersMu.Unlock()
	if e.offers == nil {
		e.offers = map[[32]byte]*offerEntry{}
	}
	if o, ok := e.offers[key]; ok && now.Sub(o.at) < ttl {
		e.dupes.Add(1)
		return o, false
	}
	if len(e.offers) >= maxRecentOffers {
		var oldest [32]byte
		var at time.Time
		for k, o := range e.offers {
			if now.Sub(o.at) >= ttl {
				delete(e.offers, k)
				continue
			}
			if at.IsZero() || o.at.Before(at) {
				oldest, at = k, o.at
			}
		}
		if len(e.offers) >= maxRecentOffers {
			delete(e.offers, oldest)
		}
	}
	o := &offerEntry{at: now, done: make(chan struct{})}
	e.offers[key] = o
	return o, true
}

func New(cfg Config) (*Endpoint, error) {
	if cfg.MaxInbound == 0 {
		cfg.MaxInbound = 8
	}
	if cfg.PunchDeadline == 0 {
		cfg.PunchDeadline = 6 * time.Second
	}
	if cfg.GatherWait == 0 {
		cfg.GatherWait = time.Second
	}
	if cfg.HeadStart == 0 {
		cfg.HeadStart = 200 * time.Millisecond
	}
	var node *driver.Node
	var err error
	if cfg.DHTAddr6 != "" {
		node, err = driver.ListenDual(cfg.DHTAddr, cfg.DHTAddr6, cfg.DHT, cfg.DHT6)
	} else {
		node, err = driver.Listen(cfg.DHTAddr, cfg.DHT)
	}
	if err != nil {
		return nil, err
	}
	if cfg.RelayOnly {
		// Relays only run over IPv4, and a relay-only endpoint never punches
		// IPv6 directly, so without an IPv4 socket it can't connect at all.
		has4 := false
		for _, a := range node.Addrs() {
			has4 = has4 || a.Addr().Is4()
		}
		if !has4 {
			_ = node.Close()
			return nil, errors.New("endpoint: relay-only needs an IPv4 socket")
		}
	}
	e := &Endpoint{cfg: cfg, node: node, accept: make(chan *Conn, cfg.MaxInbound), slots: make(chan struct{}, cfg.MaxInbound), done: make(chan struct{})}
	e.wg.Go(e.events)
	return e, nil
}

// DHT exposes the underlying node, e.g. for Bootstrap.
func (e *Endpoint) DHT() *driver.Node { return e.node }

func (e *Endpoint) Close() error {
	e.mu.Lock()
	e.closed = true
	e.mu.Unlock()
	e.once.Do(func() { close(e.done) })
	err := e.node.Close()
	e.wg.Wait()
	// Connections punched but never accepted are still ours to close.
	for {
		select {
		case c := <-e.accept:
			_ = c.Close()
		default:
			return err
		}
	}
}

// Rebind tells the endpoint the network changed (Wi-Fi to cellular, a new
// address). The DHT sockets are replaced and, when listening, our records
// are republished so callers reach the new address.
//
// Outbound connections are migrated: each punches a fresh path to its
// provider and moves onto it (see Conn.Migrate), so sessions layered on
// them survive. Rebind waits for those migrations and reports any that
// failed. An inbound connection can't migrate itself (its caller may not be
// listening): it carries on once its caller migrates it.
func (e *Endpoint) Rebind(ctx context.Context) error {
	rebind := e.rebindDHT
	if rebind == nil {
		rebind = e.node.Rebind
	}
	e.rebindReqs.Add(1) // counted even if we give up waiting: the watcher reruns it
	if err := e.lockRebind(ctx); err != nil {
		return err
	}
	defer e.unlockRebind()
	serving := e.rebindReqs.Load()
	// Migrate even if a family failed to rebind: the others may carry the
	// new paths. Whatever fails is retried by WatchNetwork.
	dhtErr := rebind(ctx)
	migErr := e.migrateAll(ctx, false)
	e.migratePending.Store(dhtErr != nil || migErr != nil)
	if !errors.Is(dhtErr, context.Canceled) && !errors.Is(dhtErr, context.DeadlineExceeded) {
		// Served, unless canceled before the DHT rebind ran: then nothing was
		// rebound or marked stale, and the watcher must rerun it in full.
		e.rebindDone.Store(serving)
	}
	return errors.Join(dhtErr, migErr)
}

// lockRebind waits for the rebind slot, giving up when ctx ends.
func (e *Endpoint) lockRebind(ctx context.Context) error {
	e.rebindOnce.Do(func() { e.rebinding = make(chan struct{}, 1) })
	select {
	case e.rebinding <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (e *Endpoint) unlockRebind() { <-e.rebinding }

// anyUnmoved reports whether an outbound connection has a migration request
// no migration has served yet.
func (e *Endpoint) anyUnmoved() bool {
	e.connsMu.Lock()
	defer e.connsMu.Unlock()
	for _, c := range e.outConns {
		if c.unmoved() {
			return true
		}
	}
	return false
}

// migrateAll moves outbound connections onto fresh paths: every one, or
// with onlyUnmoved just those whose last attempt failed, as retries, so a
// connection that already moved, or moves while the retry waits, is left
// alone.
func (e *Endpoint) migrateAll(ctx context.Context, onlyUnmoved bool) error {
	e.connsMu.Lock()
	var out []*Conn
	for _, c := range e.outConns {
		if !onlyUnmoved || c.unmoved() {
			out = append(out, c)
		}
	}
	e.connsMu.Unlock()
	errs := make([]error, len(out))
	var wg sync.WaitGroup
	for i, c := range out {
		wg.Go(func() {
			if err := c.migrate(ctx, onlyUnmoved); err != nil {
				errs[i] = fmt.Errorf("migrating connection to %x: %w", c.PeerKey[:4], err)
			}
		})
	}
	wg.Wait()
	return errors.Join(errs...)
}

// WatchNetwork rebinds whenever the local address of the default IPv4 or
// IPv6 route changes, checking every interval (5 seconds if zero), until
// ctx ends, and retries any family whose rebind failed on each check until
// it binds. Checking sends no packets. Apps whose platform reports network
// changes (iOS NWPathMonitor, Android ConnectivityManager) should call
// Rebind from those instead, which is faster and costs nothing between
// changes.
func (e *Endpoint) WatchNetwork(ctx context.Context, interval time.Duration) {
	if interval == 0 {
		interval = 5 * time.Second
	}
	probe := e.routes
	if probe == nil {
		probe = defaultRoutes
	}
	last := probe()
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-e.done:
			return
		case <-tick.C:
		}
		if cur := probe(); cur != last {
			last = cur
			_ = e.Rebind(ctx) // whatever fails is retried below
		} else if e.rebindDone.Load() < e.rebindReqs.Load() {
			_ = e.Rebind(ctx) // a requested rebind never completed
		} else if e.migratePending.Load() || e.anyUnmoved() {
			// anyUnmoved catches an explicit Migrate that failed or was
			// canceled: it leaves its request outstanding without setting
			// migratePending.
			if e.lockRebind(ctx) != nil {
				return
			}
			var dhtErr error
			if e.migratePending.Load() {
				stale, err := e.node.Stale(ctx)
				dhtErr = err // a failed check (canceled, say) keeps the retry pending
				if err == nil && stale {
					dhtErr = e.node.RebindStale(ctx)
				}
			}
			migErr := e.migrateAll(ctx, true)
			e.migratePending.Store(dhtErr != nil || migErr != nil)
			e.unlockRebind()
		}
	}
}

// defaultRoutes returns the local address the kernel would use for each
// family's default route, or the zero address when there is none. Dialing
// UDP only picks a route; no packet is sent.
func defaultRoutes() [2]netip.Addr {
	var out [2]netip.Addr
	for i, dst := range []string{"192.0.2.1:9", "[2001:db8::1]:9"} {
		network := "udp4"
		if i == 1 {
			network = "udp6"
		}
		c, err := net.Dial(network, dst)
		if err != nil {
			continue
		}
		out[i] = c.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap()
		c.Close()
	}
	return out
}

// Listen makes this endpoint reachable under priv's key; accept connections
// with Accept.
func (e *Endpoint) Listen(ctx context.Context, priv ed25519.PrivateKey) error {
	return e.node.Listen(ctx, priv)
}

func (e *Endpoint) Accept(ctx context.Context) (*Conn, error) {
	select {
	case c := <-e.accept:
		return c, nil
	case <-e.done:
		return nil, ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Connect reaches peer by public key, signing the offer with identity.
func (e *Endpoint) Connect(ctx context.Context, identity ed25519.PrivateKey, peer [32]byte) (*Conn, error) {
	// An outbound connection is owned by the endpoint until it is returned:
	// Close cancels it and waits for its runner and sockets to be released.
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil, ErrClosed
	}
	e.wg.Add(1)
	e.mu.Unlock()
	defer e.wg.Done()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-e.done:
			cancel()
		case <-ctx.Done():
		}
	}()
	secret := make([]byte, 32)
	crand.Read(secret)
	// The legs share one claim, so only one family is ever nominated and
	// both sides keep the same path.
	legs, err := e.legs(ctx, punch.Config{Initiator: true, Secret: secret}, true, true, new(atomic.Int32))
	if err != nil {
		return nil, err
	}
	offer := offerOf(legs)
	payload, err := e.node.Signal(ctx, identity, peer, offer.Marshal())
	if err != nil {
		abortAll(legs)
		return nil, err
	}
	answer, err := punch.UnmarshalOffer(payload)
	if err != nil {
		abortAll(legs)
		return nil, err
	}
	pd, err := e.race(ctx, legs, answer, e.cfg.HeadStart)
	if err != nil {
		return nil, err
	}
	return e.newConn(pd, peer, secret, identity), nil
}

type connKey struct {
	peer   [32]byte
	resume [16]byte
}

func (c *Conn) key() connKey { return connKey{c.PeerKey, c.resume} }

// punched is a freshly punched path: its socket and the peer's address.
type punched struct {
	sock    *net.UDPConn
	remote  netip.AddrPort
	relayed bool
}

// newConn wraps a punched path as a Conn and registers it, so a resume
// offer, or Rebind for an outbound one, can move it to another path.
// identity is set only for outbound connections.
func (e *Endpoint) newConn(pd punched, peer [32]byte, secret []byte, identity ed25519.PrivateKey) *Conn {
	c := &Conn{
		Remote: pd.remote, PeerKey: peer, Secret: secret, Relayed: pd.relayed,
		p: newPath(pd.sock, pd.remote), e: e, resume: resumeID(secret),
		outbound: identity != nil, identity: identity,
	}
	e.connsMu.Lock()
	m := &e.inConns
	if c.outbound {
		m = &e.outConns
	}
	if *m == nil {
		*m = map[connKey]*Conn{}
	}
	if _, taken := (*m)[c.key()]; !taken {
		// A live connection keeps its slot: a repeat of its secret from the
		// same peer gets a connection that just can't be resumed.
		(*m)[c.key()] = c
	}
	e.connsMu.Unlock()
	return c
}

func (e *Endpoint) forget(c *Conn) {
	e.connsMu.Lock()
	defer e.connsMu.Unlock()
	m := e.inConns
	if c.outbound {
		m = e.outConns
	}
	if m[c.key()] == c {
		delete(m, c.key())
	}
}

// resumable returns the live inbound connection a resume ID names, if the
// offer comes from that connection's caller.
func (e *Endpoint) resumable(id [16]byte, caller [32]byte) *Conn {
	e.connsMu.Lock()
	defer e.connsMu.Unlock()
	return e.inConns[connKey{caller, id}]
}

// Migrate moves an outbound connection onto a freshly punched path, for
// after a network change (Endpoint.Rebind calls it) or when the peer moved
// and the connection stalled. It signals the provider again with a resume
// request derived from the connection's secret; both sides punch a new path
// and move the connection onto it. Remote, Secret and anything layered on
// the Conn (hysteria2, QUIC) carry on; datagrams in flight during the move
// are lost, as on any network change.
func (c *Conn) Migrate(ctx context.Context) error {
	return c.migrate(ctx, false)
}

// migrate runs a migration. A retry adds no request of its own: it serves
// the outstanding ones, and does nothing if a migration that held the slot
// before it already served them, so it never replaces a working path.
func (c *Conn) migrate(ctx context.Context, retry bool) error {
	if !c.outbound {
		return ErrNotCaller
	}
	if !retry {
		c.moveReqs.Add(1) // counted even if we give up or fail: retries rerun it
	}
	c.slotOnce.Do(func() { c.migrateSlot = make(chan struct{}, 1) })
	select {
	case c.migrateSlot <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-c.migrateSlot }()
	if retry && !c.unmoved() {
		return nil
	}
	serving := c.moveReqs.Load()
	e := c.e
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return ErrClosed
	}
	e.wg.Add(1)
	e.mu.Unlock()
	defer e.wg.Done()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-e.done:
			cancel()
		case <-ctx.Done():
		}
	}()
	secret := make([]byte, 32) // fresh probes for the new path
	crand.Read(secret)
	legs, err := e.legs(ctx, punch.Config{Initiator: true, Secret: secret}, true, true, new(atomic.Int32))
	if err != nil {
		return err
	}
	c.migrations++
	seq := c.migrations
	offer := offerOf(legs)
	offer.Resume = resumeOffer(c.resume, seq)
	payload, err := e.node.Signal(ctx, c.identity, c.PeerKey, offer.Marshal())
	if err != nil {
		abortAll(legs)
		return err
	}
	answer, err := punch.UnmarshalOffer(payload)
	if err != nil {
		abortAll(legs)
		return err
	}
	pd, err := e.race(ctx, legs, answer, e.cfg.HeadStart)
	if err != nil {
		return err
	}
	if !c.p.swap(seq, pd.sock, pd.remote) {
		pd.sock.Close()
		return errConnClosed
	}
	c.moveDone.Store(serving) // every request up to this one is served, however asked
	return nil
}

// leg is one address family's data socket and punch session.
type leg struct {
	v6    bool
	sess  *punch.Session
	r     *punch.Runner
	conn  *net.UDPConn
	id    int32         // this leg's claim token, when claim is set
	claim *atomic.Int32 // shared by a caller's legs; nil for a responder
}

// release gives up this leg's claim, so another family can commit, unless
// this leg already committed: the responder may have connected on it.
func (l *leg) release() {
	if l.claim != nil && !l.sess.Committed() {
		l.claim.CompareAndSwap(l.id, 0)
	}
}

func claimer(owner *atomic.Int32, id int32) func() bool {
	return func() bool { return owner.CompareAndSwap(0, id) || owner.Load() == id }
}

func (l *leg) abort() { l.r.Abort(); l.conn.Close() }

func abortAll(legs []*leg) {
	for _, l := range legs {
		l.abort()
	}
}

// families reports which address families have a running DHT node.
func (e *Endpoint) families() (v4, v6 bool) {
	for _, a := range e.node.Addrs() {
		if a.Addr().Is4() {
			v4 = true
		} else {
			v6 = true
		}
	}
	return v4, v6
}

// legs prepares a leg per family: IPv4 when we have it and wantV4 is set,
// and IPv6 when we have it, wantV6 is set, we aren't relay-only (an IPv6
// leg punches directly, revealing our address), and the IPv6 DHT node has
// contacts. A caller passes claim, which its legs
// share so that only one commits to a path. It fails only if no leg could
// be prepared.
func (e *Endpoint) legs(ctx context.Context, pc punch.Config, wantV4, wantV6 bool, claim *atomic.Int32) ([]*leg, error) {
	has4, has6 := e.families()
	type prepared struct {
		l   *leg
		err error
	}
	// The legs gather in parallel, so a second family costs no extra time
	// before punching starts.
	var wg sync.WaitGroup
	out := make([]prepared, 2)
	add := func(i int, pc punch.Config, v6 bool, id int32) {
		if claim != nil {
			pc.Claim = claimer(claim, id)
		}
		wg.Go(func() {
			l, err := e.prepare(ctx, pc, v6)
			if l != nil {
				l.id, l.claim = id, claim
			}
			out[i] = prepared{l, err}
		})
	}
	if has4 && wantV4 {
		add(0, pc, false, 1)
	}
	if has6 && wantV6 && !e.cfg.RelayOnly {
		pc6 := pc
		pc6.Relay, pc6.Relays = netip.AddrPort{}, nil
		add(1, pc6, true, 2)
	}
	wg.Wait()
	var legs []*leg
	var firstErr error
	for _, p := range out {
		switch {
		case p.l != nil:
			legs = append(legs, p.l)
		case p.err != nil && firstErr == nil:
			firstErr = p.err
		}
	}
	if len(legs) == 0 {
		if firstErr == nil {
			firstErr = errors.New("endpoint: no address family to connect over")
		}
		return nil, firstErr
	}
	return legs, nil
}

// offerOf merges the legs' offers into one: candidates of both families,
// the IPv4 profile and relays, and the IPv6 profile as Profile6.
func offerOf(legs []*leg) punch.Offer {
	var o punch.Offer
	var cands6 []netip.AddrPort
	for _, l := range legs {
		lo := l.sess.Offer(locals(l.conn))
		if o.Secret == nil {
			o.Secret = lo.Secret
		}
		if l.v6 {
			p := lo.Profile
			o.Profile6 = &p
			cands6 = lo.Candidates
			continue
		}
		o.Candidates, o.Profile, o.Relays, o.Relay = lo.Candidates, lo.Profile, lo.Relays, lo.Relay
	}
	o.Candidates = append(o.Candidates, cands6...)
	return o
}

// race punches every leg against the remote's matching family and returns
// the first connected path, closing the others. IPv4 waits headStart when
// an IPv6 leg is racing too.
func (e *Endpoint) race(ctx context.Context, legs []*leg, remote punch.Offer, headStart time.Duration) (punched, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		v6  bool
		c   punched
		err error
	}
	v6Racing := false
	for _, l := range legs {
		if l.v6 && len(remote.Family(true).Candidates) > 0 {
			v6Racing = true
		}
	}
	results := make(chan result, len(legs))
	running := 0
	for _, l := range legs {
		fr := remote.Family(l.v6)
		if len(fr.Candidates) == 0 && !fr.Relay.IsValid() && len(fr.Relays) == 0 {
			l.abort() // the peer offered no path of this family
			continue
		}
		var delay time.Duration
		if !l.v6 && v6Racing {
			delay = headStart
			l.sess.DeferRelay() // a relay probe would commit the path before IPv6 has had its chance
		}
		running++
		go func() {
			if delay > 0 {
				select {
				case <-time.After(delay):
				case <-ctx.Done():
					l.abort()
					results <- result{l.v6, punched{}, ctx.Err()}
					return
				}
			}
			c, err := e.finish(ctx, l.r, l.conn, fr)
			if err != nil {
				l.release() // a failed leg mustn't block the other family
			}
			results <- result{l.v6, c, err}
		}()
	}
	if running == 0 {
		return punched{}, errors.New("endpoint: no address family in common with the peer")
	}
	var won punched
	var err4, err6 error
	for range running {
		r := <-results
		switch {
		case r.err == nil && won.sock == nil:
			won = r.c
			cancel() // the other family stops and releases its sockets
		case r.err == nil:
			r.c.sock.Close()
		case r.v6:
			err6 = r.err
		default:
			err4 = r.err
		}
	}
	if won.sock != nil {
		return won, nil
	}
	if err4 != nil {
		return punched{}, err4
	}
	return punched{}, err6
}

// prepare binds a fresh data socket for one family and learns its public
// address from that family's DHT contacts, which answer pings with the
// BEP 42 ip field.
func (e *Endpoint) prepare(ctx context.Context, pc punch.Config, v6 bool) (*leg, error) {
	network, ip := "udp4", e.cfg.DataIP
	if v6 {
		network, ip = "udp6", e.cfg.DataIP6
	}
	conn, err := net.ListenUDP(network, &net.UDPAddr{IP: ip})
	if err != nil {
		return nil, err
	}
	var reflections []dht.Reflection
	var contacts []netip.AddrPort
	var local netip.AddrPort
	found := false
	if err := e.node.InspectEach(ctx, func(addr netip.AddrPort, d *dht.Node) {
		if addr.Addr().Is4() == v6 || found {
			return
		}
		found, local = true, addr
		reflections = d.Reflections()
		for _, c := range d.Contacts(maxRelayCandidates) {
			contacts = append(contacts, c.Addr)
		}
	}); err != nil {
		conn.Close()
		return nil, err
	}
	if !found {
		conn.Close()
		return nil, errors.New("endpoint: no DHT node for this address family")
	}
	if v6 && len(contacts) == 0 {
		// A host with an IPv6 stack but no IPv6 peers (no route, or none
		// bootstrapped) has nothing to reflect off or reach.
		conn.Close()
		return nil, errors.New("endpoint: no IPv6 DHT contacts")
	}
	reflectors := contacts[:min(3, len(contacts))]
	if pc.Initiator && !v6 {
		// Routers relay by default. Offer several, so a provider that only
		// trusts routers it knows can likely find one among them.
		pc.Relays = contacts
	}
	pc.Local = e.profile(reflections, local, v6)
	pc.RelayOnly = e.cfg.RelayOnly
	pc.Deadline = e.cfg.PunchDeadline
	var seed [32]byte
	crand.Read(seed[:])
	pc.Rand = rand.New(rand.NewChaCha8(seed))
	sess := punch.New(pc)
	r := punch.NewRunner(sess, conn)
	if err := r.Gather(ctx, reflectors, e.cfg.GatherWait); err != nil {
		r.Abort()
		conn.Close()
		return nil, err
	}
	return &leg{v6: v6, sess: sess, r: r, conn: conn}, nil
}

func (e *Endpoint) finish(ctx context.Context, r *punch.Runner, conn *net.UDPConn, remote punch.Offer) (punched, error) {
	c, addr, err := r.Punch(ctx, remote)
	if err != nil {
		conn.Close()
		return punched{}, err
	}
	if c != conn {
		conn.Close() // a birthday socket won; the gathering socket is spare
	}
	return punched{sock: c, remote: addr, relayed: r.Relayed()}, nil
}

// events answers incoming offers, each on its own bounded worker.
func (e *Endpoint) events() {
	for {
		select {
		case <-e.done:
			return
		case ev, ok := <-e.node.Events():
			if !ok {
				return
			}
			if in, ok := ev.(dht.Incoming); ok {
				e.incoming(in)
			}
		}
	}
}

// incoming admits one offer. Copies of an offer through the other family's
// DHT are handled before taking a slot: they never punch, and the DHT won't
// deliver a dropped one again. A new offer gets a slot and its own worker,
// or is dropped at capacity.
func (e *Endpoint) incoming(in dht.Incoming) {
	if e.cfg.Authorize != nil && !e.cfg.Authorize(in.Caller) {
		return
	}
	offer, err := punch.UnmarshalOffer(in.Payload)
	if err != nil || len(offer.Secret) < 16 {
		return
	}
	entry, first := e.firstOffer(in.Caller, offer.Secret, time.Now())
	if !first {
		if answer, now := entry.copyOf(in.Session); now {
			e.wg.Go(func() {
				ctx, cancel := context.WithTimeout(context.Background(), e.cfg.GatherWait)
				defer cancel()
				_ = e.node.Answer(ctx, in.Session, answer)
			})
		}
		return
	}
	if len(offer.Resume) > 0 {
		// A resume naming no live connection of this caller is answered at
		// once, empty, even when every punch slot is busy: it would never
		// punch, and the caller shouldn't wait out signaling.
		if id, _, ok := parseResume(offer.Resume); !ok || e.resumable(id, in.Caller) == nil {
			e.wg.Go(func() {
				ctx, cancel := context.WithTimeout(context.Background(), e.cfg.GatherWait)
				defer cancel()
				e.answerEmpty(ctx, in, entry)
			})
			return
		}
	}
	select {
	case e.slots <- struct{}{}:
	default:
		entry.publish(nil) // at capacity: no answer, so queued copies get none
		return             // the caller times out or retries
	}
	e.wg.Go(func() {
		defer func() { <-e.slots }()
		e.inbound(in, offer, entry)
	})
}

func (e *Endpoint) inbound(in dht.Incoming, offer punch.Offer, entry *offerEntry) {
	ctx, cancel := context.WithTimeout(context.Background(), e.cfg.GatherWait+e.cfg.PunchDeadline+2*time.Second)
	defer cancel()
	go func() {
		select {
		case <-e.done:
			cancel()
		case <-ctx.Done():
		}
	}()
	// A dual-stack caller signals the same offer through each family's DHT;
	// its secret identifies it. events() answered any copy that arrived
	// first; this, the first copy, punches and charges once.
	defer e.publishOffer(ctx, entry, nil) // any early return leaves copies unanswered
	// A resume offer moves a live connection of this caller onto the path it
	// punches. One that names no such connection gets an empty answer, so
	// the caller fails at once rather than punching for nothing.
	var resumed *Conn
	var resumeSeq uint64
	if len(offer.Resume) > 0 {
		id, seq, ok := parseResume(offer.Resume)
		if ok {
			resumed, resumeSeq = e.resumable(id, in.Caller), seq
		}
		if resumed == nil || !resumed.allowResume(time.Now()) {
			e.answerEmpty(ctx, in, entry)
			return
		}
	}
	// A caller can list anyone's address as its candidate; bound how often
	// we will probe a network on a stranger's word.
	has4, has6 := e.families()
	want4, wantV6 := wantFamilies(offer, has4, has6, e.cfg.RelayOnly)
	if !want4 && !wantV6 {
		// No family in common: an empty answer lets the caller fail at once
		// instead of waiting out signaling.
		e.answerEmpty(ctx, in, entry)
		return
	}
	heavy := false
	if err := e.node.InspectEach(ctx, func(addr netip.AddrPort, d *dht.Node) {
		v6 := !addr.Addr().Is4()
		if v6 && !wantV6 || !v6 && !want4 {
			return
		}
		fo := offer.Family(v6)
		strategy, _, _ := punch.Plan(e.profile(d.Reflections(), addr, v6), fo.Profile, fo.Candidates, true)
		heavy = heavy || strategy == punch.Spray || strategy == punch.Open || strategy == punch.DoubleBirthday
	}); err != nil {
		return
	}
	offered := offer.Relays
	if len(offered) == 0 && offer.Relay.IsValid() {
		offered = []netip.AddrPort{offer.Relay}
	}
	var relay, charged netip.AddrPort
	if err := e.node.Inspect(ctx, func(d *dht.Node) {
		var own []netip.AddrPort
		for _, c := range d.Contacts(maxRelayCandidates) {
			own = append(own, c.Addr)
		}
		relay, charged = chooseRelay(e.cfg.RelayOnly, offered, own, d.Knows)
	}); err != nil {
		return
	}
	if e.cfg.RelayOnly && !relay.IsValid() {
		return // no router we trust to relay through: refuse rather than leak
	}
	// Charge only what a leg we'll run can probe.
	probed := probeable(offer.Candidates, want4, wantV6)
	if !want4 {
		charged = netip.AddrPort{} // relays only run over IPv4
	}
	if !e.limiter.allow(in.Caller, probed, charged, heavy, resumed != nil, time.Now()) {
		return
	}
	// The relay chosen here is final: the IPv4 session uses exactly this
	// one (or none).
	legs, err := e.legs(ctx, punch.Config{Relay: relay}, want4, wantV6, nil)
	if err != nil {
		return
	}
	answer := offerOf(legs)
	ab := answer.Marshal()
	// Answer our own session first, then the queued copy. Keep the legs if
	// either delivery worked. Until one has, the answer isn't visible to
	// later copies, which mustn't send the caller toward legs we close.
	if err := e.node.Answer(ctx, in.Session, ab); err == nil {
		e.publishOffer(ctx, entry, ab)
	} else if e.deliverQueued(ctx, entry, ab) == 0 {
		e.publishOffer(ctx, entry, nil)
		abortAll(legs)
		return
	} else {
		e.publishOffer(ctx, entry, ab)
	}
	// The IPv4 leg waits out the same head start as the caller's, so when
	// IPv6 wins quickly a heavy IPv4 strategy is canceled before it sprays.
	pd, err := e.race(ctx, legs, offer, e.cfg.HeadStart)
	if err != nil {
		return
	}
	if resumed != nil {
		if !resumed.p.swap(resumeSeq, pd.sock, pd.remote) {
			pd.sock.Close() // closed meanwhile, or a newer migration got there first
		}
		return
	}
	c := e.newConn(pd, in.Caller, offer.Secret, nil)
	select {
	case e.accept <- c:
	default:
		_ = c.Close() // nobody is accepting
	}
}

// answerEmpty answers an offer we won't punch for with an empty offer, so
// the caller fails at once instead of waiting out signaling.
func (e *Endpoint) answerEmpty(ctx context.Context, in dht.Incoming, entry *offerEntry) {
	empty := punch.Offer{}
	b := empty.Marshal()
	e.publishOffer(ctx, entry, b)
	_ = e.node.Answer(ctx, in.Session, b)
}

// profile infers our NAT profile from the DHT socket's reflections: the
// same NAT maps the data sockets.
func (e *Endpoint) profile(refl []dht.Reflection, local netip.AddrPort, v6 bool) punch.Profile {
	if e.cfg.Profile != nil && !v6 {
		return *e.cfg.Profile
	}
	var obs []natprobe.Observation
	for _, r := range refl {
		obs = append(obs, natprobe.Observation{Order: r.Order, Local: local, Dest: r.From, Mapped: r.Mapped})
	}
	return ProfileOf(natprobe.Analyze(local, obs))
}

// ProfileOf converts a natprobe analysis into what punch offers carry.
func ProfileOf(a natprobe.Analysis) punch.Profile {
	switch a.Mapping {
	case natprobe.MappingEndpointIndependent:
		return punch.Profile{Mapping: punch.MappingIndependent}
	case natprobe.MappingEndpointDependent:
		p := punch.Profile{Mapping: punch.MappingDependent, Allocation: punch.AllocRandom}
		switch a.Allocation {
		case natprobe.AllocationSequential:
			p.Allocation, p.Step = punch.AllocSequential, uint16(max(a.Step, 1))
		case natprobe.AllocationBlock:
			p.Allocation, p.BlockLo, p.BlockHi = punch.AllocBlock, a.BlockLo, a.BlockHi
		}
		return p
	}
	return punch.Profile{}
}

// locals lists the data socket's own addresses as candidates, for peers on
// the same network.
func locals(c *net.UDPConn) []netip.AddrPort {
	a := c.LocalAddr().(*net.UDPAddr).AddrPort()
	ip := a.Addr()
	if ip.IsUnspecified() {
		network, dst := "udp4", "192.0.2.1:9"
		if !ip.Unmap().Is4() {
			network, dst = "udp6", "[2001:db8::1]:9"
		}
		probe, err := net.Dial(network, dst) // no packets sent
		if err != nil {
			return nil
		}
		ip = probe.LocalAddr().(*net.UDPAddr).AddrPort().Addr()
		probe.Close()
	}
	return []netip.AddrPort{netip.AddrPortFrom(ip.Unmap(), a.Port())}
}

const maxRelayCandidates = 8

// chooseRelay picks, as the listener, the relay both sides will use. A relay
// learns both addresses, so a relay-only listener uses only a router it
// authenticated itself: the first offered one it knows, or else its own
// closest contact, which a caller that doesn't keep its address private will
// follow. Otherwise the caller's first choice stands.
//
// charge is the address the inbound limiter budgets for the relay. A relay
// taken on the caller's word is a third party we would contact for a
// stranger, so it is budgeted like any probed host. A relay-only listener
// relays only through routers it already knows, which a caller cannot aim
// at anyone; budgeting those by address would let three offers a minute
// lock out every caller that falls back to our own closest router.
func chooseRelay(relayOnly bool, offered, own []netip.AddrPort, knows func(netip.AddrPort) bool) (relay, charge netip.AddrPort) {
	if !relayOnly {
		if len(offered) > 0 {
			return offered[0], offered[0]
		}
		return netip.AddrPort{}, netip.AddrPort{}
	}
	for _, r := range offered {
		if knows(r) {
			return r, netip.AddrPort{}
		}
	}
	if len(own) > 0 {
		return own[0], netip.AddrPort{}
	}
	return netip.AddrPort{}, netip.AddrPort{}
}
