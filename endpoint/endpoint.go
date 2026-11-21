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
	"errors"
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

// Conn is a punched path to a peer. Just after connecting, the socket can
// still receive a few hole-punching control datagrams (KRPC, first byte
// 'd'), such as duplicate final acknowledgements, and a relayed one a few
// 20-byte relay probes or acks. Protocols layered above drop them (uTP
// shaping and QUIC both reject them); raw users should read with Recv,
// which skips the KRPC ones, and ignore the relay ones.
type Conn struct {
	*net.UDPConn
	Remote netip.AddrPort
	// PeerKey is the provider's key for an outbound connection, the
	// caller's verified key for an inbound one.
	PeerKey [32]byte
	// Secret is shared only by the two ends, for binding a later
	// cryptographic handshake (QUIC, Noise) to this path.
	Secret []byte
	// Relayed means Remote is a DHT router relaying to the peer, used when
	// no direct path could be punched.
	Relayed bool
}

func (c *Conn) Send(b []byte) error {
	_, err := c.WriteToUDPAddrPort(b, c.Remote)
	return err
}

// Recv reads the next datagram from the peer, skipping datagrams from other
// addresses and leftover hole-punching control traffic.
func (c *Conn) Recv(b []byte) (int, error) {
	for {
		n, from, err := c.ReadFromUDPAddrPort(b)
		if err != nil {
			return 0, err
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		if from != c.Remote || (n > 0 && b[0] == 'd') {
			continue
		}
		return n, nil
	}
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

	offersMu sync.Mutex
	offers   map[[32]byte]time.Time // recent offer secrets, by hash
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

// firstOffer reports whether this caller's offer with this secret is new,
// recording it. Entries are keyed by caller and secret, so one caller can't
// touch another's, and remembered for twice a punch's lifetime, longer than
// any copy of the same offer could still arrive through another DHT. When
// full, the oldest entry makes way: a flood can't make us refuse offers.
func (e *Endpoint) firstOffer(caller [32]byte, secret []byte, now time.Time) bool {
	h := sha256.New()
	h.Write(caller[:])
	h.Write(secret)
	key := [32]byte(h.Sum(nil))
	ttl := 2 * (e.cfg.GatherWait + e.cfg.PunchDeadline)
	e.offersMu.Lock()
	defer e.offersMu.Unlock()
	if e.offers == nil {
		e.offers = map[[32]byte]time.Time{}
	}
	if at, ok := e.offers[key]; ok && now.Sub(at) < ttl {
		return false
	}
	if len(e.offers) >= maxRecentOffers {
		var oldest [32]byte
		var at time.Time
		for k, t := range e.offers {
			if now.Sub(t) >= ttl {
				delete(e.offers, k)
				continue
			}
			if at.IsZero() || t.Before(at) {
				oldest, at = k, t
			}
		}
		if len(e.offers) >= maxRecentOffers {
			delete(e.offers, oldest)
		}
	}
	e.offers[key] = now
	return true
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
			c.Close()
		default:
			return err
		}
	}
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
	return e.race(ctx, legs, answer, peer, secret, e.cfg.HeadStart)
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

// release gives up this leg's claim, so another family can commit.
func (l *leg) release() {
	if l.claim != nil {
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
func (e *Endpoint) race(ctx context.Context, legs []*leg, remote punch.Offer, peer [32]byte, secret []byte, headStart time.Duration) (*Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		v6  bool
		c   *Conn
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
		if l.v6 && len(fr.Candidates) == 0 {
			l.abort() // the peer offered no IPv6 path
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
					results <- result{l.v6, nil, ctx.Err()}
					return
				}
			}
			c, err := e.finish(ctx, l.r, l.conn, fr, peer, secret)
			if err != nil {
				l.release() // a failed leg mustn't block the other family
			}
			results <- result{l.v6, c, err}
		}()
	}
	if running == 0 {
		return nil, errors.New("endpoint: no address family in common with the peer")
	}
	var won *Conn
	var err4, err6 error
	for range running {
		r := <-results
		switch {
		case r.err == nil && won == nil:
			won = r.c
			cancel() // the other family stops and releases its sockets
		case r.err == nil:
			r.c.Close()
		case r.v6:
			err6 = r.err
		default:
			err4 = r.err
		}
	}
	if won != nil {
		return won, nil
	}
	if err4 != nil {
		return nil, err4
	}
	return nil, err6
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

func (e *Endpoint) finish(ctx context.Context, r *punch.Runner, conn *net.UDPConn, remote punch.Offer, peer [32]byte, secret []byte) (*Conn, error) {
	c, addr, err := r.Punch(ctx, remote)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if c != conn {
		conn.Close() // a birthday socket won; the gathering socket is spare
	}
	return &Conn{UDPConn: c, Remote: addr, PeerKey: peer, Secret: secret, Relayed: r.Relayed()}, nil
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
			in, ok := ev.(dht.Incoming)
			if !ok {
				continue
			}
			if e.cfg.Authorize != nil && !e.cfg.Authorize(in.Caller) {
				continue
			}
			select {
			case e.slots <- struct{}{}:
			default:
				continue // at capacity; the caller times out or retries
			}
			e.wg.Go(func() {
				defer func() { <-e.slots }()
				e.inbound(in)
			})
		}
	}
}

func (e *Endpoint) inbound(in dht.Incoming) {
	ctx, cancel := context.WithTimeout(context.Background(), e.cfg.GatherWait+e.cfg.PunchDeadline+2*time.Second)
	defer cancel()
	go func() {
		select {
		case <-e.done:
			cancel()
		case <-ctx.Done():
		}
	}()
	offer, err := punch.UnmarshalOffer(in.Payload)
	if err != nil || len(offer.Secret) < 16 {
		return
	}
	if !e.firstOffer(in.Caller, offer.Secret, time.Now()) {
		// A dual-stack caller signals the same offer through each family's
		// DHT; its secret identifies it. Punch and charge for it once.
		return
	}
	// A caller can list anyone's address as its candidate; bound how often
	// we will probe a network on a stranger's word.
	has4, has6 := e.families()
	want4, wantV6 := wantFamilies(offer, has4, has6, e.cfg.RelayOnly)
	if !want4 && !wantV6 {
		// No family in common: an empty answer lets the caller fail at once
		// instead of waiting out signaling.
		empty := punch.Offer{}
		_ = e.node.Answer(ctx, in.Session, empty.Marshal())
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
	if !e.limiter.allow(in.Caller, probed, charged, heavy, time.Now()) {
		return
	}
	// The relay chosen here is final: the IPv4 session uses exactly this
	// one (or none).
	legs, err := e.legs(ctx, punch.Config{Relay: relay}, want4, wantV6, nil)
	if err != nil {
		return
	}
	answer := offerOf(legs)
	if err := e.node.Answer(ctx, in.Session, answer.Marshal()); err != nil {
		abortAll(legs)
		return
	}
	// The IPv4 leg waits out the same head start as the caller's, so when
	// IPv6 wins quickly a heavy IPv4 strategy is canceled before it sprays.
	c, err := e.race(ctx, legs, offer, in.Caller, offer.Secret, e.cfg.HeadStart)
	if err != nil {
		return
	}
	select {
	case e.accept <- c:
	default:
		c.Close() // nobody is accepting
	}
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
