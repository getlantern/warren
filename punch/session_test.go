package punch

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"testing"
	"time"

	"github.com/getlantern/warren/krpc"
)

// A responder acting on a stranger's offer must never spray a non-public
// address: that would port-scan its own LAN or localhost on request.
func TestResponderNeverSpraysPrivate(t *testing.T) {
	for _, cand := range []string{"192.168.1.1:9", "127.0.0.1:9", "10.0.0.5:9"} {
		s := New(Config{Local: Profile{Mapping: MappingIndependent}, Rand: rand.New(rand.NewPCG(1, 1))})
		now := time.Unix(1_800_000_000, 0)
		s.Start(now, Offer{
			Secret:     []byte("0123456789abcdef"),
			Candidates: []netip.AddrPort{netip.MustParseAddrPort(cand)},
			Profile:    Profile{Mapping: MappingDependent, Allocation: AllocRandom},
		})
		for range 50 {
			now = now.Add(20 * time.Millisecond)
			s.Tick(now)
		}
		sends, events := s.Drain()
		ports := map[uint16]bool{}
		for _, snd := range sends {
			ports[snd.To.Port()] = true
		}
		if len(ports) > 1 {
			t.Errorf("%s: responder probed %d ports", cand, len(ports))
		}
		if len(events) == 0 {
			t.Errorf("%s: no outcome", cand)
		} else if f, ok := events[0].(Failed); !ok || f.Err != ErrRelayNeeded {
			t.Errorf("%s: outcome %+v, want ErrRelayNeeded without a relay", cand, events[0])
		}
	}
}

// wire delivers datagrams between two sessions; drop decides which of B's
// sends are lost.
func runPair(t *testing.T, a, b *Session, start time.Time, drop func(Send) bool) (Event, Event) {
	t.Helper()
	addrA, addrB := netip.MustParseAddrPort("198.51.100.1:40000"), netip.MustParseAddrPort("203.0.113.1:40000")
	var evA, evB Event
	now := start
	for range 400 {
		now = now.Add(10 * time.Millisecond)
		a.Tick(now)
		b.Tick(now)
		for range 3 {
			sa, ea := a.Drain()
			sb, eb := b.Drain()
			// Decide losses when B sends, not when its datagrams arrive:
			// anything B sent before handing off its socket still travels.
			kept := sb[:0]
			for _, s := range sb {
				if !drop(s) {
					kept = append(kept, s)
				}
			}
			sb = kept
			for _, e := range ea {
				if _, ok := e.(Connected); ok || evA == nil {
					evA = e
				}
			}
			for _, e := range eb {
				if _, ok := e.(Connected); ok || evB == nil {
					evB = e
				}
			}
			for _, s := range sa {
				if s.To == addrB {
					b.HandlePacket(now, 0, addrA, s.Data)
				}
			}
			for _, s := range sb {
				if s.To == addrA {
					a.HandlePacket(now, 0, addrB, s.Data)
				}
			}
		}
		if _, ok := evA.(Connected); ok {
			break
		}
	}
	return evA, evB
}

// If every copy of the responder's final ack is lost, the responder has
// handed its socket off and cannot answer again; the initiator must still
// connect on a pair it already proved, not time out.
func TestLostFinalAckStillConnects(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	open := Profile{Mapping: MappingIndependent}
	a := New(Config{Initiator: true, Secret: secret, Local: open, Rand: rand.New(rand.NewPCG(1, 1))})
	b := New(Config{Local: open, Rand: rand.New(rand.NewPCG(2, 2))})
	now := time.Unix(1_800_000_000, 0)
	b.Start(now, Offer{Secret: secret, Candidates: []netip.AddrPort{netip.MustParseAddrPort("198.51.100.1:40000")}, Profile: open})
	a.Start(now, Offer{Candidates: []netip.AddrPort{netip.MustParseAddrPort("203.0.113.1:40000")}, Profile: open})
	handedOff := false
	evA, evB := runPair(t, a, b, now, func(s Send) bool {
		if b.done {
			handedOff = true
			return true // after Connected, B's socket belongs to the application
		}
		return false
	})
	if !handedOff {
		t.Fatal("test never reached the handoff")
	}
	if _, ok := evB.(Connected); !ok {
		t.Fatalf("responder: %+v", evB)
	}
	if _, ok := evA.(Connected); !ok {
		t.Fatalf("initiator did not connect after losing the final ack: %+v", evA)
	}
}

// RelayOnly must keep our addresses out of the offer and never probe the
// peer's candidates, even with NATs that could punch directly.
func TestRelayOnlyHidesAddresses(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	relay := netip.MustParseAddrPort("2.176.0.9:6881")
	s := New(Config{Initiator: true, Secret: secret, Local: Profile{Mapping: MappingIndependent}, Rand: rand.New(rand.NewPCG(3, 3)), Relay: relay, RelayOnly: true})
	if o := s.Offer([]netip.AddrPort{netip.MustParseAddrPort("192.168.1.5:40000")}); len(o.Candidates) != 0 {
		t.Fatalf("relay-only offer carries candidates %v", o.Candidates)
	}
	peer := netip.MustParseAddrPort("203.0.113.1:40000")
	now := time.Unix(1_800_000_000, 0)
	s.Start(now, Offer{Candidates: []netip.AddrPort{peer}, Profile: Profile{Mapping: MappingIndependent}})
	for range 300 {
		now = now.Add(20 * time.Millisecond)
		s.Tick(now)
		sends, _ := s.Drain()
		for _, snd := range sends {
			if snd.To != relay {
				t.Fatalf("relay-only session sent to %v", snd.To)
			}
		}
	}
}

// Both sides must bind the same relay: the responder's choice, which a
// relay-only initiator accepts only from among its own candidates.
func TestRelayAgreement(t *testing.T) {
	a, b, theirs := netip.MustParseAddrPort("2.176.0.1:6881"), netip.MustParseAddrPort("2.176.0.2:6881"), netip.MustParseAddrPort("9.9.9.9:6881")
	secret := []byte("0123456789abcdef0123456789abcdef")
	init := func(relayOnly bool) *Session {
		return New(Config{Initiator: true, Secret: secret, Relays: []netip.AddrPort{a, b}, RelayOnly: relayOnly, Rand: rand.New(rand.NewPCG(5, 5))})
	}
	if o := init(false).Offer(nil); len(o.Relays) != 2 || o.Relays[0] != a {
		t.Fatalf("initiator offer relays %v", o.Relays)
	}
	resp := New(Config{Relay: b, Rand: rand.New(rand.NewPCG(6, 6))})
	if o := resp.Offer(nil); o.Relay != b {
		t.Fatalf("responder answer relay %v, want its choice", o.Relay)
	}
	for _, tc := range []struct {
		relayOnly bool
		answer    netip.AddrPort
		want      netip.AddrPort
	}{
		{false, b, b},                    // follow the responder's pick
		{true, b, b},                     // relay-only: one we offered, accept
		{true, theirs, netip.AddrPort{}}, // relay-only: not ours, refuse
		{false, theirs, theirs},          // not private: trust the responder
		{false, netip.AddrPort{}, a},     // responder didn't choose: it took our first
	} {
		if got := init(tc.relayOnly).chooseRelay(Offer{Relay: tc.answer}); got != tc.want {
			t.Errorf("relayOnly=%v answer=%v: got %v, want %v", tc.relayOnly, tc.answer, got, tc.want)
		}
	}
	if got := New(Config{Rand: rand.New(rand.NewPCG(7, 7))}).chooseRelay(Offer{Relays: []netip.AddrPort{a, b}}); got != a {
		t.Errorf("responder without a choice: got %v, want the initiator's first", got)
	}
}

// A relay-only responder with no relay of its own choosing must not fall
// back to the initiator's unauthenticated candidates.
func TestRelayOnlyResponderIgnoresOfferedRelays(t *testing.T) {
	s := New(Config{RelayOnly: true, Rand: rand.New(rand.NewPCG(8, 8))})
	offered := Offer{Relays: []netip.AddrPort{netip.MustParseAddrPort("6.6.6.6:6881")}, Relay: netip.MustParseAddrPort("6.6.6.7:6881")}
	if got := s.chooseRelay(offered); got.IsValid() {
		t.Fatalf("relay-only responder fell back to the caller's relay %v", got)
	}
}

// relayPair runs two sessions through a fake router that hands out a token,
// accepts the announce, and forwards non-KRPC datagrams between the two
// announcers. dropToA decides, at send time, whether the router loses a
// datagram it forwards to A.
func relayPair(t *testing.T, a, b *Session, router netip.AddrPort, start time.Time, dropToA func([]byte) bool) (Event, Event) {
	return relayPairForget(t, a, b, router, start, dropToA, false)
}

// relayPairForget is relayPair with a router that, if forgetB, answers B's
// first announce but drops it, as a router evicting B's half-formed pair
// does.
func relayPairForget(t *testing.T, a, b *Session, router netip.AddrPort, start time.Time, dropToA func([]byte) bool, forgetB bool) (Event, Event) {
	t.Helper()
	addrA, addrB := netip.MustParseAddrPort("198.51.100.1:40000"), netip.MustParseAddrPort("203.0.113.1:40000")
	announced := map[netip.AddrPort]bool{}
	var evA, evB Event
	now := start
	route := func(from netip.AddrPort, s Send) {
		if s.To != router {
			return
		}
		var m krpc.Msg
		if s.Data[0] == 'd' && krpc.Unmarshal(s.Data, &m) == nil && m.Y == krpc.Query {
			r := krpc.Msg{T: m.T, Y: krpc.Response, R: krpc.Return{Token: []byte("tokn")}}
			if m.Q == "announce_peer" {
				if forgetB && from == addrB {
					forgetB = false
				} else {
					announced[from] = true
				}
			}
			to := a
			if from == addrB {
				to = b
			}
			to.HandlePacket(now, 0, router, krpc.AppendMarshal(nil, &r))
			return
		}
		if !announced[addrA] || !announced[addrB] {
			return
		}
		if from == addrA {
			b.HandlePacket(now, 0, router, s.Data)
		} else if !dropToA(s.Data) {
			a.HandlePacket(now, 0, router, s.Data)
		}
	}
	for range 1000 {
		now = now.Add(10 * time.Millisecond)
		a.Tick(now)
		b.Tick(now)
		for range 3 {
			sa, ea := a.Drain()
			sb, eb := b.Drain()
			for _, e := range ea {
				if _, ok := e.(Connected); ok || evA == nil {
					evA = e
				}
			}
			for _, e := range eb {
				if _, ok := e.(Connected); ok || evB == nil {
					evB = e
				}
			}
			for _, s := range sa {
				route(addrA, s)
			}
			for _, s := range sb {
				route(addrB, s)
			}
		}
		if _, ok := evA.(Connected); ok {
			break
		}
		if _, ok := evA.(Failed); ok {
			break
		}
	}
	return evA, evB
}

// If the router loses every copy of the responder's ack, the responder has
// already handed its socket off; the initiator must still connect.
func TestRelayLostAckBurstStillConnects(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	router := netip.MustParseAddrPort("2.176.0.9:6881")
	a := New(Config{Initiator: true, Secret: secret, RelayOnly: true, Relays: []netip.AddrPort{router}, Rand: rand.New(rand.NewPCG(1, 1))})
	b := New(Config{RelayOnly: true, Relay: router, Rand: rand.New(rand.NewPCG(2, 2))})
	now := time.Unix(1_800_000_000, 0)
	offerA := a.Offer(nil)
	b.Start(now, offerA)
	a.Start(now, b.Offer(nil))
	ack := relayMAC(secret, "ack responder", 2)
	evA, evB := relayPair(t, a, b, router, now, func(d []byte) bool { return bytes.Equal(d, ack) })
	if c, ok := evB.(Connected); !ok || !c.Relayed {
		t.Fatalf("responder: %+v", evB)
	}
	if c, ok := evA.(Connected); !ok || !c.Relayed {
		t.Fatalf("initiator did not connect after losing every relay ack: %+v", evA)
	}
}

// A sequential window that would cross the top of the port space must fall
// back to the full range rather than truncate or wrap to port 0.
func TestSequentialWindowAtTopOfPortSpace(t *testing.T) {
	seq := Profile{Mapping: MappingDependent, Allocation: AllocSequential, Step: 1}
	full := portRange{1024, 65535}
	for _, last := range []uint16{65100, 65534, 65535} {
		cands := []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("203.0.113.1"), last)}
		if got := targetRange(seq, cands); got != full {
			t.Errorf("last port %d: got %+v, want the full range", last, got)
		}
	}
	cands := []netip.AddrPort{netip.MustParseAddrPort("203.0.113.1:40000")}
	if got := targetRange(seq, cands); got != (portRange{40001, 40000 + predictWindow}) {
		t.Errorf("mid-range window %+v", got)
	}
}

// A router that evicts the responder's half-formed pair after accepting its
// announce must not strand the session: both sides re-announce until they
// hear each other, so the pair is rebuilt.
func TestRelayEvictedBindingRebuilt(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	router := netip.MustParseAddrPort("2.176.0.9:6881")
	a := New(Config{Initiator: true, Secret: secret, RelayOnly: true, Relays: []netip.AddrPort{router}, Rand: rand.New(rand.NewPCG(3, 3))})
	b := New(Config{RelayOnly: true, Relay: router, Rand: rand.New(rand.NewPCG(4, 4))})
	now := time.Unix(1_800_000_000, 0)
	b.Start(now, a.Offer(nil))
	a.Start(now, b.Offer(nil))
	evA, evB := relayPairForget(t, a, b, router, now, func([]byte) bool { return false }, true)
	if c, ok := evA.(Connected); !ok || !c.Relayed {
		t.Fatalf("initiator after the router forgot the responder's binding: %+v", evA)
	}
	if c, ok := evB.(Connected); !ok || !c.Relayed {
		t.Fatalf("responder: %+v", evB)
	}
}

// A late reply to a retried get_peers must not mark the relay bound: only
// the announce's reply does.
func TestRelayBoundOnlyByAnnounceReply(t *testing.T) {
	router := netip.MustParseAddrPort("2.176.0.9:6881")
	s := New(Config{RelayOnly: true, Relay: router, Rand: rand.New(rand.NewPCG(6, 6))})
	now := time.Unix(1_800_000_000, 0)
	s.Start(now, Offer{Secret: []byte("0123456789abcdef0123456789abcdef")})
	getPeers := func() [][]byte {
		sends, _ := s.Drain()
		var tids [][]byte
		for _, snd := range sends {
			var m krpc.Msg
			if krpc.Unmarshal(snd.Data, &m) == nil && m.Q == "get_peers" {
				tids = append(tids, m.T)
			}
		}
		return tids
	}
	first := getPeers()
	s.Tick(now.Add(600 * time.Millisecond)) // retry
	retry := getPeers()
	if len(first) != 1 || len(retry) != 1 {
		t.Fatalf("get_peers sent %d then %d", len(first), len(retry))
	}
	reply := func(tid []byte) {
		r := krpc.Msg{T: tid, Y: krpc.Response, R: krpc.Return{Token: []byte("tokn")}}
		s.HandlePacket(now.Add(700*time.Millisecond), 0, router, krpc.AppendMarshal(nil, &r))
	}
	reply(first[0])
	reply(retry[0])
	if s.relayBound {
		t.Fatal("a get_peers reply marked the relay bound")
	}
}

// A relay reply forged from another address must not advance the bind.
func TestRelayReplyMustComeFromRelay(t *testing.T) {
	router := netip.MustParseAddrPort("2.176.0.9:6881")
	s := New(Config{RelayOnly: true, Relay: router, Rand: rand.New(rand.NewPCG(7, 7))})
	now := time.Unix(1_800_000_000, 0)
	s.Start(now, Offer{Secret: []byte("0123456789abcdef0123456789abcdef")})
	sends, _ := s.Drain()
	var tid []byte
	for _, snd := range sends {
		var m krpc.Msg
		if krpc.Unmarshal(snd.Data, &m) == nil && m.Q == "get_peers" {
			tid = m.T
		}
	}
	r := krpc.Msg{T: tid, Y: krpc.Response, R: krpc.Return{Token: []byte("tokn")}}
	s.HandlePacket(now, 0, netip.MustParseAddrPort("6.6.6.6:6881"), krpc.AppendMarshal(nil, &r))
	if s.relayToken != nil {
		t.Fatal("a reply from a stranger set the relay token")
	}
}

// Offers are parsed into canonical addresses: an 18-byte IPv4-mapped
// candidate or relay comes out unmapped (so it matches what sockets and
// routing tables hold), and a relay with port 0 is dropped.
func TestUnmarshalOfferCanonicalAddresses(t *testing.T) {
	mapped := func(a string, port uint16) string {
		ip := netip.MustParseAddr(a).As16()
		ip[10], ip[11] = 0xff, 0xff
		return string(ip[:]) + string([]byte{byte(port >> 8), byte(port)})
	}
	v4 := func(a string, port uint16) string {
		ip := netip.MustParseAddr(a).As4()
		return string(ip[:]) + string([]byte{byte(port >> 8), byte(port)})
	}
	str := func(s string) string { return fmt.Sprintf("%d:%s", len(s), s) }
	raw := "d1:cl" + str(mapped("203.0.113.5", 4000)) + "e" +
		"1:p" + str(string(make([]byte, 8))) +
		"1:r" + str(v4("198.51.100.7", 0)) +
		"2:rsl" + str(mapped("198.51.100.8", 6881)) + "e" +
		"e"
	o, err := UnmarshalOffer([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(o.Candidates) != 1 || o.Candidates[0] != netip.MustParseAddrPort("203.0.113.5:4000") {
		t.Fatalf("candidates %v, want the unmapped 203.0.113.5:4000", o.Candidates)
	}
	if len(o.Relays) != 1 || o.Relays[0] != netip.MustParseAddrPort("198.51.100.8:6881") {
		t.Fatalf("relays %v, want the unmapped 198.51.100.8:6881", o.Relays)
	}
	if o.Relay.IsValid() {
		t.Fatalf("a port-0 relay %v was accepted", o.Relay)
	}
}

// Two initiator sessions sharing a claim (one per address family) punch two
// responders in lockstep: only one responder is ever nominated, and it is
// the path the initiator keeps.
func TestSharedClaimCommitsOnePath(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	open := Profile{Mapping: MappingIndependent}
	owner := 0
	claim := func(id int) func() bool {
		return func() bool {
			if owner == 0 {
				owner = id
			}
			return owner == id
		}
	}
	type pairT struct {
		a, b         *Session
		addrA, addrB netip.AddrPort
		evA, evB     Event
	}
	mk := func(id int, addrA, addrB string) *pairT {
		p := &pairT{
			a:     New(Config{Initiator: true, Secret: secret, Local: open, Claim: claim(id), Rand: rand.New(rand.NewPCG(uint64(id), 1))}),
			b:     New(Config{Local: open, Rand: rand.New(rand.NewPCG(uint64(id), 2))}),
			addrA: netip.MustParseAddrPort(addrA), addrB: netip.MustParseAddrPort(addrB),
		}
		now := time.Unix(1_800_000_000, 0)
		p.b.Start(now, Offer{Secret: secret, Candidates: []netip.AddrPort{p.addrA}, Profile: open})
		p.a.Start(now, Offer{Candidates: []netip.AddrPort{p.addrB}, Profile: open})
		return p
	}
	pairs := []*pairT{mk(1, "198.51.100.1:40000", "203.0.113.1:40000"), mk(2, "[2001:db8::a]:40000", "[2001:db8::b]:40000")}
	now := time.Unix(1_800_000_000, 0)
	for range 400 {
		now = now.Add(10 * time.Millisecond)
		for _, p := range pairs {
			p.a.Tick(now)
			p.b.Tick(now)
		}
		for range 3 {
			for _, p := range pairs { // both families exchange in the same instant
				sa, ea := p.a.Drain()
				sb, eb := p.b.Drain()
				for _, e := range ea {
					if _, ok := e.(Connected); ok {
						p.evA = e
					}
				}
				for _, e := range eb {
					if _, ok := e.(Connected); ok {
						p.evB = e
					}
				}
				for _, s := range sa {
					if s.To == p.addrB {
						p.b.HandlePacket(now, 0, p.addrA, s.Data)
					}
				}
				for _, s := range sb {
					if s.To == p.addrA {
						p.a.HandlePacket(now, 0, p.addrB, s.Data)
					}
				}
			}
		}
	}
	responders, kept := 0, -1
	for i, p := range pairs {
		if p.evB != nil {
			responders++
		}
		if p.evA != nil {
			kept = i
		}
	}
	if responders != 1 {
		t.Fatalf("%d responders were nominated, want exactly one", responders)
	}
	if kept < 0 || pairs[kept].evB == nil {
		t.Fatalf("the initiator kept pair %d, which its responder never connected on", kept)
	}
}

// A deferred relay session holds its probes until halfway to the deadline,
// even when relaying is its only strategy, so a racing IPv6 session gets
// its chance before the relay commits the responder.
func TestDeferRelayHoldsProbes(t *testing.T) {
	router := netip.MustParseAddrPort("2.176.0.9:6881")
	s := New(Config{Initiator: true, Secret: []byte("0123456789abcdef0123456789abcdef"), RelayOnly: true, Relays: []netip.AddrPort{router}, Rand: rand.New(rand.NewPCG(11, 11))})
	s.DeferRelay()
	now := time.Unix(1_800_000_000, 0)
	s.Start(now, Offer{Relay: router})
	s.relayToken, s.relayBound = []byte("tokn"), true // bound at once
	probe := relayMAC([]byte("0123456789abcdef0123456789abcdef"), "probe initiator", 4)
	probed := false
	for t2 := now; t2.Before(now.Add(s.cfg.Deadline/2 + 200*time.Millisecond)); t2 = t2.Add(10 * time.Millisecond) {
		s.Tick(t2)
		sends, _ := s.Drain()
		for _, snd := range sends {
			if !bytes.Equal(snd.Data, probe) {
				continue
			}
			if t2.Before(now.Add(s.cfg.Deadline / 2)) {
				t.Fatalf("relay probe sent %v after start, before half the deadline", t2.Sub(now))
			}
			probed = true
		}
	}
	if !probed {
		t.Fatal("a deferred relay session never probed once half the deadline passed")
	}
}
