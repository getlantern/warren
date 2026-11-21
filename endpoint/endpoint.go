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

// Conn is a punched path to a peer.
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

type Endpoint struct {
	cfg     Config
	node    *driver.Node
	limiter inboundLimiter
	accept  chan *Conn
	slots   chan struct{}
	done    chan struct{}
	once    sync.Once
	wg      sync.WaitGroup
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
	e.once.Do(func() { close(e.done) })
	err := e.node.Close()
	e.wg.Wait()
	return err
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
	secret := make([]byte, 32)
	crand.Read(secret)
	sess, r, conn, err := e.prepare(ctx, punch.Config{Initiator: true, Secret: secret})
	if err != nil {
		return nil, err
	}
	offer := sess.Offer(locals(conn))
	payload, err := e.node.Signal(ctx, identity, peer, offer.Marshal())
	if err != nil {
		conn.Close()
		return nil, err
	}
	answer, err := punch.UnmarshalOffer(payload)
	if err != nil {
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
	var reflectors []netip.AddrPort
	if err := e.node.Inspect(ctx, func(d *dht.Node) {
		reflections = d.Reflections()
		for _, c := range d.Contacts(3) {
			reflectors = append(reflectors, c.Addr)
		}
	}); err != nil {
		conn.Close()
		return nil, nil, nil, err
	}
	if pc.Initiator && len(reflectors) > 0 {
		// Routers relay by default; our closest contact is the fallback.
		pc.Relay = reflectors[0]
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
	spray := offer.Profile.Mapping == punch.MappingDependent
	if !e.limiter.allow(in.Caller, offer.Candidates, offer.Relay, spray, time.Now()) {
		return
	}
	if e.cfg.RelayOnly && offer.Relay.IsValid() {
		// The caller picks the relay, and a relay learns our address. Keeping
		// that address from the caller means accepting only a router we
		// already authenticated ourselves.
		known := false
		if err := e.node.Inspect(ctx, func(d *dht.Node) { known = d.Knows(offer.Relay) }); err != nil || !known {
			offer.Relay = netip.AddrPort{}
		}
	}
	sess, r, conn, err := e.prepare(ctx, punch.Config{})
	if err != nil {
		return
	}
	answer := sess.Offer(locals(conn))
	if err := e.node.Answer(ctx, in.Session, answer.Marshal()); err != nil {
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
	for i, r := range refl {
		obs = append(obs, natprobe.Observation{Order: i, Local: local, Dest: r.From, Mapped: r.Mapped})
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
