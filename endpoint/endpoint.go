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
	"errors"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
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
// 'd'), such as duplicate final acknowledgements. Protocols layered above
// drop them (uTP shaping and QUIC both reject them); raw users should read
// with Recv, which skips them.
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
	node, err := driver.Listen(cfg.DHTAddr, cfg.DHT)
	if err != nil {
		return nil, err
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
	sess, r, conn, err := e.prepare(ctx, punch.Config{Initiator: true, Secret: secret})
	if err != nil {
		return nil, err
	}
	offer := sess.Offer(locals(conn))
	payload, err := e.node.Signal(ctx, identity, peer, offer.Marshal())
	if err != nil {
		r.Abort()
		conn.Close()
		return nil, err
	}
	answer, err := punch.UnmarshalOffer(payload)
	if err != nil {
		r.Abort()
		conn.Close()
		return nil, err
	}
	return e.finish(ctx, r, conn, answer, peer, secret)
}

// prepare binds a fresh data socket and learns its public address from DHT
// contacts, which answer pings with the BEP 42 ip field.
func (e *Endpoint) prepare(ctx context.Context, pc punch.Config) (*punch.Session, *punch.Runner, *net.UDPConn, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: e.cfg.DataIP})
	if err != nil {
		return nil, nil, nil, err
	}
	var reflections []dht.Reflection
	var contacts []netip.AddrPort
	if err := e.node.Inspect(ctx, func(d *dht.Node) {
		reflections = d.Reflections()
		for _, c := range d.Contacts(maxRelayCandidates) {
			contacts = append(contacts, c.Addr)
		}
	}); err != nil {
		conn.Close()
		return nil, nil, nil, err
	}
	reflectors := contacts[:min(3, len(contacts))]
	if pc.Initiator {
		// Routers relay by default. Offer several, so a provider that only
		// trusts routers it knows can likely find one among them.
		pc.Relays = contacts
	}
	pc.Local = e.profile(reflections)
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
		return nil, nil, nil, err
	}
	return sess, r, conn, nil
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
	// A caller can list anyone's address as its candidate; bound how often
	// we will probe a network on a stranger's word.
	var refl []dht.Reflection
	if err := e.node.Inspect(ctx, func(d *dht.Node) { refl = d.Reflections() }); err != nil {
		return
	}
	strategy, _, _ := punch.Plan(e.profile(refl), offer.Profile, offer.Candidates, true)
	heavy := strategy == punch.Spray || strategy == punch.Open || strategy == punch.DoubleBirthday
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
	if !e.limiter.allow(in.Caller, offer.Candidates, charged, heavy, time.Now()) {
		return
	}
	// The relay chosen here is final: the session uses exactly this one (or
	// none).
	sess, r, conn, err := e.prepare(ctx, punch.Config{Relay: relay})
	if err != nil {
		return
	}
	answer := sess.Offer(locals(conn))
	if err := e.node.Answer(ctx, in.Session, answer.Marshal()); err != nil {
		r.Abort()
		conn.Close()
		return
	}
	c, err := e.finish(ctx, r, conn, offer, in.Caller, offer.Secret)
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
func (e *Endpoint) profile(refl []dht.Reflection) punch.Profile {
	if e.cfg.Profile != nil {
		return *e.cfg.Profile
	}
	local := e.node.Addr()
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
		probe, err := net.Dial("udp4", "192.0.2.1:9") // no packets sent
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
