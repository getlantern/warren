package punch

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"net/netip"
	"slices"
	"time"

	"github.com/getlantern/warren/dht"
	"github.com/getlantern/warren/krpc"
)

var (
	ErrRelayNeeded = errors.New("punch: no direct strategy for this NAT pair")
	ErrTimeout     = errors.New("punch: deadline passed without a path")
	ErrNoSecret    = errors.New("punch: initiator offer carried no secret")
)

type Config struct {
	// Secret is shared through encrypted signaling. The initiator supplies
	// it; the responder takes it from the initiator's offer.
	Secret    []byte
	Initiator bool
	Local     Profile
	Rand      *rand.Rand
	Deadline  time.Duration
	// NoDoubleBirthday disables punching when both sides map dependently,
	// as HyperDHT does.
	NoDoubleBirthday bool
	SprayPerTick     int
	MaxProbes        int
	// Relays, for the initiator, are DHT routers to fall back to when no
	// direct path is found, in preference order; Relay alone means one.
	// For the responder, Relay is its choice among the initiator's (or of
	// its own, when it keeps its address private), echoed in its answer.
	// Left unset, a responder takes the initiator's first, unless it is
	// RelayOnly, in which case it uses no relay at all.
	Relays []netip.AddrPort
	Relay  netip.AddrPort
	// RelayOnly keeps our addresses from the peer: the offer carries no
	// candidates and we never probe the peer directly, so it only ever sees
	// the relay router. It requires a relay.
	RelayOnly bool
}

func (c *Config) defaults() {
	if c.Deadline == 0 {
		c.Deadline = 6 * time.Second
	}
	if c.SprayPerTick == 0 {
		c.SprayPerTick = 8 // every 20 ms: 400 probes/s
	}
	if c.MaxProbes == 0 {
		c.MaxProbes = 4000
	}
}

type Send struct {
	Socket int
	To     netip.AddrPort
	Data   []byte
}

type Event interface{ isEvent() }

// Reflected reports socket 0's public address as a reflector saw it.
type Reflected struct{ Addr netip.AddrPort }

// Connected reports the nominated path. The runner keeps that socket and
// closes the others.
type Connected struct {
	Socket   int
	Remote   netip.AddrPort
	Strategy Strategy
	Probes   int
	// Relayed means Remote is a relay router forwarding to the peer.
	Relayed bool
}

type Failed struct {
	Err      error
	Strategy Strategy
	Probes   int
}

func (Reflected) isEvent() {}
func (Connected) isEvent() {}
func (Failed) isEvent()    {}

const (
	sprayTick    = 20 * time.Millisecond
	directTick   = 100 * time.Millisecond
	openTick     = 250 * time.Millisecond
	nominateTick = 100 * time.Millisecond

	// nominateAttempts unanswered nominations on a proven pair mean the
	// responder's final acks were lost after it handed off its socket.
	nominateAttempts = 5
	finalAckCopies   = 3

	maxBirthdayPairs = 256
	birthdayPerTick  = 64
)

type pair struct {
	socket int
	addr   netip.AddrPort
}

type Session struct {
	cfg Config

	sockets   int
	reflexive []netip.AddrPort
	reflectT  map[uint16]bool
	nextT     uint16
	gatherID  krpc.NodeID

	started              bool
	done                 bool
	myID, peerID, nomID  krpc.NodeID
	strategy             Strategy
	target               portRange
	remote               Offer
	remoteIP             netip.Addr
	deadline             time.Time
	nextDirect, nextOpen time.Time
	nextSpray, nextNom   time.Time
	sprayed              map[uint16]bool
	pairs                []pair // double birthday: fixed (socket, port) probes
	pairNext             int
	// sentTo maps probe transaction IDs to where they went. Under dependent
	// mapping a reply arrives from a different port than the one probed, so
	// the initiator keeps sending to the probed destination; replying to the
	// reply's source would mint a fresh mapping on every round trip.
	sentTo     map[uint16]pair
	nomTids    map[uint16]bool
	nomSent    int
	proven     bool // the nominated pair carried a reply to our own probe
	probes     int
	nominating bool
	nominated  pair
	selected   pair

	sends  []Send
	events []Event

	// Relay fallback.
	relay      netip.AddrPort
	relayInfo  krpc.NodeID
	relayToken []byte
	relayBound bool
	relayT     map[uint16]bool
	nextRelay  time.Time // next bind step or probe
	relayFrom  time.Time // when probing starts
	relayProbe []byte
	relayAck   []byte
	peerProbe  []byte
	peerAck    []byte
	// relayProven: the responder's probe reached the initiator through the
	// relay. relayUnanswered counts the initiator's probes since then.
	relayProven     bool
	relayUnanswered int
	nextAnnounce    time.Time // next re-announce while the peer is unheard
}

func New(cfg Config) *Session {
	cfg.defaults()
	s := &Session{cfg: cfg, sockets: 1, reflectT: map[uint16]bool{}, sprayed: map[uint16]bool{}, sentTo: map[uint16]pair{}, nomTids: map[uint16]bool{}, relayT: map[uint16]bool{}}
	binary.LittleEndian.PutUint64(s.gatherID[:], cfg.Rand.Uint64())
	binary.LittleEndian.PutUint64(s.gatherID[8:], cfg.Rand.Uint64())
	return s
}

// Sockets is how many sockets the runner must provide, numbered from 0.
// Socket 0 gathers candidates; the rest are opened for birthday punching.
func (s *Session) Sockets() int { return s.sockets }

func (s *Session) Drain() ([]Send, []Event) {
	a, b := s.sends, s.events
	s.sends, s.events = nil, nil
	return a, b
}

func (s *Session) tid() uint16 { s.nextT++; return s.nextT }

func (s *Session) query(socket int, to netip.AddrPort, id krpc.NodeID) uint16 {
	return s.queryArgs(socket, to, "ping", krpc.Args{ID: id})
}

func (s *Session) queryArgs(socket int, to netip.AddrPort, q string, a krpc.Args) uint16 {
	t := s.tid()
	var tb [2]byte
	binary.BigEndian.PutUint16(tb[:], t)
	m := krpc.Msg{T: tb[:], Y: krpc.Query, Q: q, A: a, V: dht.DefaultVersion}
	s.sends = append(s.sends, Send{Socket: socket, To: to, Data: krpc.AppendMarshal(nil, &m)})
	return t
}

func (s *Session) reply(socket int, to netip.AddrPort, q *krpc.Msg) {
	m := krpc.Msg{T: q.T, Y: krpc.Response, IP: to, V: dht.DefaultVersion, R: krpc.Return{ID: s.myID, P: int(to.Port())}}
	s.sends = append(s.sends, Send{Socket: socket, To: to, Data: krpc.AppendMarshal(nil, &m)})
}

// Reflect pings DHT nodes from socket 0 to learn its public address from the
// BEP 42 ip field of their replies.
func (s *Session) Reflect(reflectors []netip.AddrPort) {
	for _, r := range reflectors {
		s.reflectT[s.query(0, r, s.gatherID)] = true
	}
}

// Offer builds this side's offer: reflexive candidates first, then local ones.
func (s *Session) Offer(locals []netip.AddrPort) Offer {
	o := Offer{Profile: s.cfg.Local}
	if !s.cfg.RelayOnly {
		o.Candidates = append(append([]netip.AddrPort(nil), s.reflexive...), locals...)
	}
	if s.cfg.Initiator {
		o.Secret = s.cfg.Secret
		o.Relays = s.relayCandidates()
	} else {
		o.Relay = s.cfg.Relay
	}
	return o
}

func (s *Session) relayCandidates() []netip.AddrPort {
	if len(s.cfg.Relays) > 0 {
		return s.cfg.Relays
	}
	if s.cfg.Relay.IsValid() {
		return []netip.AddrPort{s.cfg.Relay}
	}
	return nil
}

// chooseRelay settles which relay both sides bind to. The responder decides
// and names its choice in the answer; the initiator follows it, unless it
// keeps its own address private and the choice is not one it offered.
func (s *Session) chooseRelay(remote Offer) netip.AddrPort {
	if !s.cfg.Initiator {
		if s.cfg.Relay.IsValid() {
			return s.cfg.Relay
		}
		if s.cfg.RelayOnly {
			// Never fall back to the initiator's candidates: they are
			// unauthenticated, and a relay learns our address.
			return netip.AddrPort{}
		}
		if len(remote.Relays) > 0 {
			return remote.Relays[0]
		}
		return remote.Relay
	}
	cands := s.relayCandidates()
	switch {
	case remote.Relay.IsValid() && (slices.Contains(cands, remote.Relay) || !s.cfg.RelayOnly):
		return remote.Relay
	case !remote.Relay.IsValid() && len(cands) > 0:
		return cands[0] // the responder didn't choose, so it took our first
	}
	return netip.AddrPort{}
}

func probeID(secret []byte, label string) krpc.NodeID {
	h := sha256.New()
	h.Write([]byte("warren/punch/v1 " + label))
	h.Write(secret)
	return krpc.NodeID(h.Sum(nil))
}

// Start begins punching toward the peer's offer.
func (s *Session) Start(now time.Time, remote Offer) {
	secret := s.cfg.Secret
	if !s.cfg.Initiator {
		secret = remote.Secret
	}
	if len(secret) < 16 {
		s.fail(ErrNoSecret)
		return
	}
	me, peer := "responder", "initiator"
	if s.cfg.Initiator {
		me, peer = peer, me
	}
	s.myID, s.peerID, s.nomID = probeID(secret, me), probeID(secret, peer), probeID(secret, "nominate")
	s.remote = remote
	for _, c := range remote.Candidates {
		if a := c.Addr(); a.IsGlobalUnicast() && !a.IsPrivate() {
			s.remoteIP = a
			break
		}
	}
	if !s.remoteIP.IsValid() && len(remote.Candidates) > 0 {
		s.remoteIP = remote.Candidates[0].Addr() // same LAN or host
	}
	var extra int
	s.strategy, s.target, extra = Plan(s.cfg.Local, remote.Profile, remote.Candidates, !s.cfg.NoDoubleBirthday)
	s.relay = s.chooseRelay(remote)
	sprays := s.strategy == Spray || s.strategy == DoubleBirthday
	// A responder sprays only a public address. The initiator chose to call
	// this peer; a responder acts on a stranger's offer, and spraying a
	// non-public address would probe its own LAN or localhost.
	publicTarget := s.remoteIP.IsGlobalUnicast() && !s.remoteIP.IsPrivate()
	noDirect := s.cfg.RelayOnly || len(remote.Candidates) == 0 || s.strategy == Relay ||
		(sprays && !s.remoteIP.IsValid()) || (sprays && !s.cfg.Initiator && !publicTarget)
	if noDirect && !s.relay.IsValid() {
		s.fail(ErrRelayNeeded)
		return
	}
	if noDirect {
		s.strategy, extra = Relay, 0
	}
	s.sockets = 1 + extra
	s.started = true
	s.deadline = now.Add(s.cfg.Deadline)
	if s.relay.IsValid() {
		s.startRelay(now, secret, me, peer)
	}
	s.Tick(now)
}

func (s *Session) fail(err error) {
	s.done = true
	s.events = append(s.events, Failed{Err: err, Strategy: s.strategy, Probes: s.probes})
}

// NextWakeup reports only the timers the current state services; a stale
// timer the state ignores would wake the runner forever without progress.
func (s *Session) NextWakeup() time.Time {
	if !s.started || s.done {
		return time.Time{}
	}
	timers := []time.Time{s.nextDirect}
	switch {
	case s.nominating:
		timers = []time.Time{s.nextNom}
	case s.strategy == Spray:
		timers = append(timers, s.nextSpray)
	case s.strategy == Open || s.strategy == DoubleBirthday:
		timers = append(timers, s.nextOpen)
	}
	if s.relay.IsValid() && !s.nominating && !s.nextRelay.IsZero() {
		timers = append(timers, s.nextRelay)
	}
	if !s.nominating && s.reannouncing() {
		timers = append(timers, s.nextAnnounce)
	}
	w := s.deadline
	for _, t := range timers {
		if !t.IsZero() && t.Before(w) {
			w = t
		}
	}
	return w
}

func (s *Session) Tick(now time.Time) {
	if !s.started || s.done {
		return
	}
	if !now.Before(s.deadline) {
		s.fail(ErrTimeout)
		return
	}
	s.tickRelay(now)
	if s.nominating {
		if !now.Before(s.nextNom) {
			if s.nomSent >= nominateAttempts && s.proven {
				// The peer answered one of our probes on this pair, so the
				// path works both ways; repeated silence means its final ack
				// was lost after it handed the socket to the application,
				// which can no longer answer. A wrong guess fails loudly in
				// the authenticated handshake that follows.
				s.connect(s.nominated)
				return
			}
			s.nomTids[s.query(s.nominated.socket, s.nominated.addr, s.nomID)] = true
			s.nomSent++
			s.nextNom = now.Add(nominateTick)
		}
		return
	}
	if !now.Before(s.nextDirect) && !s.cfg.RelayOnly {
		for _, c := range s.remote.Candidates {
			s.probe(0, c)
		}
		s.nextDirect = now.Add(directTick)
	}
	switch s.strategy {
	case Open:
		if !now.Before(s.nextOpen) {
			for i := 1; i < s.sockets; i++ {
				for _, c := range s.remote.Candidates[:min(2, len(s.remote.Candidates))] {
					s.probe(i, c)
				}
			}
			s.nextOpen = now.Add(openTick)
		}
	case Spray:
		if !now.Before(s.nextSpray) {
			for range s.cfg.SprayPerTick {
				if p, ok := s.freshPort(); ok {
					s.probe(0, netip.AddrPortFrom(s.remoteIP, p))
				}
			}
			s.nextSpray = now.Add(sprayTick)
		}
	case DoubleBirthday:
		if !now.Before(s.nextOpen) {
			s.doubleBirthday()
			s.nextOpen = now.Add(directTick)
		}
	}
}

// doubleBirthday probes a fixed set of (socket, port) pairs, re-sending on
// the same pairs instead of always picking new ports. With dependent mapping,
// every new destination costs a NAT port, and a carrier NAT's per-subscriber
// quota may be only a couple of thousand, shared with everything else on the
// device. About size/8 pairs a side gives ~size/64 expected hits; repeating
// them covers the window where one side probes before the other's mapping
// exists.
func (s *Session) doubleBirthday() {
	if s.pairs == nil {
		budget := min(max(s.target.size()/8, 64), maxBirthdayPairs)
		for k := range budget {
			p, ok := s.freshPort()
			if !ok {
				break
			}
			s.pairs = append(s.pairs, pair{1 + k%(s.sockets-1), netip.AddrPortFrom(s.remoteIP, p)})
		}
	}
	for range min(len(s.pairs), birthdayPerTick) {
		p := s.pairs[s.pairNext%len(s.pairs)]
		s.pairNext++
		s.probe(p.socket, p.addr)
	}
}

func (s *Session) probe(socket int, to netip.AddrPort) {
	if s.probes >= s.cfg.MaxProbes {
		return
	}
	s.probes++
	s.sentTo[s.query(socket, to, s.myID)] = pair{socket, to}
}

// freshPort picks an untried port in the target range, cycling once the
// range is exhausted.
func (s *Session) freshPort() (uint16, bool) {
	size := s.target.size()
	if size <= 0 {
		return 0, false
	}
	if len(s.sprayed) >= size {
		clear(s.sprayed)
	}
	for {
		p := s.target.lo + uint16(s.cfg.Rand.IntN(size))
		if !s.sprayed[p] {
			s.sprayed[p] = true
			return p, true
		}
	}
}

func (s *Session) HandlePacket(now time.Time, socket int, from netip.AddrPort, data []byte) {
	if len(data) > 0 && data[0] != 'd' {
		s.relayData(socket, from, data)
		return
	}
	var m krpc.Msg
	if krpc.Unmarshal(data, &m) != nil {
		return
	}
	switch m.Y {
	case krpc.Response:
		if len(m.T) != 2 {
			return
		}
		t := binary.BigEndian.Uint16(m.T)
		if socket == 0 && s.relayT[t] {
			delete(s.relayT, t)
			s.relayReply(now, &m)
			return
		}
		if socket == 0 && s.reflectT[t] && m.IP.IsValid() {
			delete(s.reflectT, t)
			if !containsAddr(s.reflexive, m.IP) {
				s.reflexive = append(s.reflexive, m.IP)
				s.events = append(s.events, Reflected{Addr: m.IP})
			}
			return
		}
		if !s.started || m.R.ID != s.peerID {
			return
		}
		switch {
		case s.done:
		case s.nominating && s.nomTids[t] && socket == s.nominated.socket:
			s.connect(s.nominated)
		case s.nominating:
			// A reply to one of our own probes on the nominated socket, even
			// one that lands after an inbound probe triggered the nomination,
			// proves our packets reach the peer too.
			if sent, ok := s.sentTo[t]; ok && sent.socket == s.nominated.socket {
				s.proven = true
			}
		case s.cfg.Initiator && !s.nominating:
			p := pair{socket, from}
			if sent, ok := s.sentTo[t]; ok && sent.socket == socket {
				p = sent
			}
			s.nominate(now, p)
			s.proven = true // a reply to our own probe: both directions work
		}
	case krpc.Query:
		if !s.started || m.Q != "ping" {
			return
		}
		p := pair{socket, from}
		switch m.A.ID {
		case s.peerID:
			s.reply(socket, from, &m)
			if s.cfg.Initiator && !s.nominating && !s.done {
				s.nominate(now, p)
			}
		case s.nomID:
			if s.cfg.Initiator || (s.done && socket != s.selected.socket) {
				return
			}
			// Once connected the socket belongs to the application, which
			// cannot answer a retried nomination, so send the final ack in
			// triplicate to make losing all of it unlikely.
			for range finalAckCopies {
				s.reply(socket, from, &m)
			}
			if !s.done {
				s.connect(p)
			}
		}
	}
}

func (s *Session) nominate(now time.Time, p pair) {
	s.nominating, s.nominated = true, p
	s.nomTids[s.query(p.socket, p.addr, s.nomID)] = true
	s.nomSent = 1
	s.nextNom = now.Add(nominateTick)
}

func (s *Session) connect(p pair) {
	s.done, s.selected = true, p
	s.events = append(s.events, Connected{Socket: p.socket, Remote: p.addr, Strategy: s.strategy, Probes: s.probes})
}

func containsAddr(as []netip.AddrPort, a netip.AddrPort) bool {
	for _, x := range as {
		if x == a {
			return true
		}
	}
	return false
}
