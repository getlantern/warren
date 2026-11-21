package punch

import (
	"math/rand/v2"
	"net/netip"
	"testing"
	"time"
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
