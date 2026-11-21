package dht

import (
	"net/netip"
	"testing"
	"time"

	"github.com/getlantern/warren/krpc"
)

// announce sends get_peers then announce_peer from 'from', as a relay
// binding does.
func announce(t *testing.T, n *Node, from netip.AddrPort, info krpc.NodeID) {
	t.Helper()
	announceAt(t, n, t0, from, info)
}

func announceAt(t *testing.T, n *Node, at time.Time, from netip.AddrPort, info krpc.NodeID) {
	t.Helper()
	q := func(m krpc.Msg) *krpc.Msg {
		m.T, m.Y = []byte("aa"), krpc.Query
		n.HandlePacket(at, from, krpc.AppendMarshal(nil, &m))
		sends, _ := n.Drain()
		for _, s := range sends {
			var r krpc.Msg
			if s.To == from && krpc.Unmarshal(s.Data, &r) == nil && r.Y != krpc.Query {
				return &r
			}
		}
		return nil
	}
	r := q(krpc.Msg{Q: "get_peers", A: krpc.Args{ID: outsiderID(rng(50)), InfoHash: &info}})
	ok := q(krpc.Msg{Q: "announce_peer", A: krpc.Args{ID: outsiderID(rng(51)), InfoHash: &info, Token: r.R.Token, Port: 6881, ImpliedPort: true}})
	if ok == nil || ok.Y != krpc.Response {
		t.Fatalf("announce rejected: %+v", ok)
	}
}

func relayed(n *Node, from netip.AddrPort, b []byte) []Send {
	n.HandlePacket(t0, from, b)
	s, _ := n.Drain()
	return s
}

var utpLike = append([]byte{0x01, 0}, make([]byte, 100)...) // ST_DATA, version 1

func TestRelayPairsAndForwards(t *testing.T) {
	r := New(Config{ID: outsiderID(rng(52)), Rand: rng(53)})
	a, b, c := addr(1), addr(2), addr(3)
	info := krpc.NodeID{7}

	if s := relayed(r, a, utpLike); len(s) != 0 {
		t.Fatal("forwarded for an unpaired address")
	}
	announce(t, r, a, info)
	if s := relayed(r, a, utpLike); len(s) != 0 {
		t.Fatal("forwarded before the pair formed")
	}
	announce(t, r, b, info)
	if r.RelayPairs() != 1 {
		t.Fatalf("pairs = %d", r.RelayPairs())
	}
	if s := relayed(r, a, utpLike); len(s) != 1 || s[0].To != b {
		t.Fatalf("a→b: %+v", s)
	}
	if s := relayed(r, b, utpLike); len(s) != 1 || s[0].To != a {
		t.Fatalf("b→a: %+v", s)
	}
	// A third announcer cannot join or hijack the pair.
	announce(t, r, c, info)
	if s := relayed(r, c, utpLike); len(s) != 0 {
		t.Fatal("third party relayed through an existing pair")
	}
}

func TestRelayByteBudget(t *testing.T) {
	r := New(Config{ID: outsiderID(rng(54)), Rand: rng(55), RelayRate: 10_000})
	a, b := addr(1), addr(2)
	announce(t, r, a, krpc.NodeID{8})
	announce(t, r, b, krpc.NodeID{8})
	pkt := append([]byte{0x01, 0}, make([]byte, 998)...)
	sent := 0
	for range 100 {
		sent += len(relayed(r, a, pkt)) // all within one instant
	}
	if sent > 11 {
		t.Fatalf("forwarded %d KB in an instant with a 10 KB/s budget", sent)
	}
}

func TestReadOnlyAndOptOutDoNotRelay(t *testing.T) {
	for _, cfg := range []Config{{ReadOnly: true}, {DisableRelay: true}} {
		cfg.ID, cfg.Rand = outsiderID(rng(56)), rng(57)
		r := New(cfg)
		if r.relaying() {
			t.Fatalf("%+v relays", cfg)
		}
	}
}

func TestRelayPairLimit(t *testing.T) {
	r := New(Config{ID: outsiderID(rng(58)), Rand: rng(59), MaxRelayPairs: 2})
	for i := range 4 {
		info := krpc.NodeID{byte(i + 1)}
		announce(t, r, addr(10+2*i), info)
		announce(t, r, addr(11+2*i), info)
	}
	if got := r.RelayPairs(); got != 2 {
		t.Fatalf("relaying %d pairs, limit 2", got)
	}
	_ = time.Second
}

// One bound address announcing many fresh info-hashes must not fill the
// pair table with empty pairs and lock out legitimate sessions.
func TestRelayBoundAddressCannotFillTable(t *testing.T) {
	r := New(Config{ID: outsiderID(rng(58)), Rand: rng(59)})
	a := addr(1)
	for i := range 4*r.cfg.MaxRelayPairs + 8 {
		announce(t, r, a, krpc.NodeID{9, byte(i), byte(i >> 8)})
	}
	if got := len(r.rel.pairs); got != 1 {
		t.Fatalf("one address created %d pairs", got)
	}
	announce(t, r, addr(2), krpc.NodeID{10})
	announce(t, r, addr(3), krpc.NodeID{10})
	if r.RelayPairs() != 1 {
		t.Fatalf("a legitimate pair could not form: %d active", r.RelayPairs())
	}
	announce(t, r, a, krpc.NodeID{9, 0, 0}) // refreshing its own pair still works
	if p := r.rel.byAddr[a]; p == nil || p != r.rel.pairs[krpc.NodeID{9, 0, 0}] {
		t.Fatal("bound address lost its own pair")
	}
}

// Tokens are per IP, so one host announcing fresh info-hashes from many
// source ports is held to a few half-formed pairs.
func TestRelayOneHostManyPortsHeldToPendingCap(t *testing.T) {
	r := New(Config{ID: outsiderID(rng(60)), Rand: rng(61)})
	host := netip.MustParseAddr("5.5.5.1")
	for i := range 4 * r.cfg.MaxRelayPairs {
		announce(t, r, netip.AddrPortFrom(host, uint16(10000+i)), krpc.NodeID{11, byte(i)})
	}
	if got := len(r.rel.pairs); got != maxPendingPerSource {
		t.Fatalf("one host holds %d half-formed pairs, want the cap %d", got, maxPendingPerSource)
	}
}

// A flood fills the table with half-formed pairs and keeps going, but a
// real session still pairs: eviction takes from the heaviest source, and
// never a pair younger than evictGrace.
func TestRelayFullTableEvictsFromFlood(t *testing.T) {
	r := New(Config{ID: outsiderID(rng(62)), Rand: rng(63)})
	flood := func(at time.Time, round int) {
		for i := range 4 * r.cfg.MaxRelayPairs {
			src := netip.AddrFrom4([4]byte{6, byte(round), byte(i % 8), 1}) // 8 fresh sources a round
			announceAt(t, r, at, netip.AddrPortFrom(src, uint16(1000*round+i)), krpc.NodeID{13, byte(round), byte(i)})
		}
	}
	flood(t0, 0)
	if got := len(r.rel.pairs); got != 4*r.cfg.MaxRelayPairs {
		t.Fatalf("flood filled %d slots", got)
	}
	listenAt := t0.Add(3 * time.Second)
	announceAt(t, r, listenAt, addr(2), krpc.NodeID{12})
	flood(listenAt, 1)                                                    // the flood keeps announcing
	announceAt(t, r, listenAt.Add(time.Second), addr(3), krpc.NodeID{12}) // the caller arrives
	if r.RelayPairs() != 1 {
		t.Fatalf("the real session was evicted by the flood: %d active", r.RelayPairs())
	}
	if len(r.rel.pairs) > 4*r.cfg.MaxRelayPairs {
		t.Fatalf("table grew to %d", len(r.rel.pairs))
	}
}

// Eviction must not depend on map order: with equal activity times, the
// same pair goes every time.
func TestRelayEvictionDeterministic(t *testing.T) {
	victim := func() krpc.NodeID {
		r := New(Config{ID: outsiderID(rng(70)), Rand: rng(71)})
		for i := range 4 * r.cfg.MaxRelayPairs {
			announce(t, r, netip.AddrPortFrom(netip.AddrFrom4([4]byte{7, 7, byte(i), 1}), 6881), krpc.NodeID{20, byte(i)})
		}
		before := map[krpc.NodeID]bool{}
		for k := range r.rel.pairs {
			before[k] = true
		}
		announceAt(t, r, t0.Add(3*time.Second), addr(9), krpc.NodeID{21})
		for k := range before {
			if r.rel.pairs[k] == nil {
				return k
			}
		}
		t.Fatal("nothing evicted")
		return krpc.NodeID{}
	}
	first := victim()
	for range 20 {
		if v := victim(); v != first {
			t.Fatalf("evicted %x, then %x", first[:2], v[:2])
		}
	}
}

// One host pairing with itself holds at most one slot, IPv4 or IPv6 /64.
func TestRelaySelfPairsLimited(t *testing.T) {
	selfPair := func(r *Node, a, b netip.AddrPort, tag byte, i int) {
		announce(t, r, a, krpc.NodeID{tag, byte(i)})
		announce(t, r, b, krpc.NodeID{tag, byte(i)})
	}
	r := New(Config{ID: outsiderID(rng(64)), Rand: rng(65)})
	v4 := netip.MustParseAddr("5.5.5.1")
	for i := range r.cfg.MaxRelayPairs {
		selfPair(r, netip.AddrPortFrom(v4, uint16(20000+2*i)), netip.AddrPortFrom(v4, uint16(20001+2*i)), 14, i)
	}
	if got := r.RelayPairs(); got != maxSelfPairs {
		t.Fatalf("one IPv4 host self-paired %d times, want %d", got, maxSelfPairs)
	}
	for i := range r.cfg.MaxRelayPairs {
		a := netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 15: byte(2*i + 1)})
		b := netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 15: byte(2*i + 2)})
		selfPair(r, netip.AddrPortFrom(a, 6881), netip.AddrPortFrom(b, 6881), 15, i)
	}
	if got := r.RelayPairs(); got != 2*maxSelfPairs {
		t.Fatalf("an IPv4 host and one IPv6 /64 hold %d self-pairs, want %d", got, 2*maxSelfPairs)
	}
}

// Many sessions from one address to different peers (a busy client, a
// relay-only listener, or subscribers sharing a CGNAT IP): completed pairs
// aren't capped per source, while concurrent half-formed ones are, at
// maxPendingPerSource.
func TestRelayBusySourceKeepsFallback(t *testing.T) {
	r := New(Config{ID: outsiderID(rng(66)), Rand: rng(67)})
	me := netip.MustParseAddr("5.5.5.1")
	n := maxPendingPerSource
	for i := range n { // all announce before any peer does
		announce(t, r, netip.AddrPortFrom(me, uint16(40000+i)), krpc.NodeID{16, byte(i)})
	}
	for i := range n {
		announce(t, r, addr(10+i), krpc.NodeID{16, byte(i)})
	}
	if got := r.RelayPairs(); got != n {
		t.Fatalf("%d concurrent sessions from one address formed %d pairs", n, got)
	}
	for i := range n + 1 { // completed pairs free the half-formed budget
		announce(t, r, netip.AddrPortFrom(me, uint16(41000+i)), krpc.NodeID{18, byte(i)})
	}
	if pending, _ := r.rel.count(relaySource(netip.AddrPortFrom(me, 0))); pending != n {
		t.Fatalf("one address holds %d half-formed pairs, want the cap %d", pending, n)
	}
}

// Refreshing half-formed pairs can't pin the table: grace runs from
// creation, and a half-formed pair expires at maxPendingAge regardless.
func TestRelayRefreshesCannotPinTable(t *testing.T) {
	r := New(Config{ID: outsiderID(rng(78)), Rand: rng(79)})
	var keys []netip.AddrPort
	for i := range 4 * r.cfg.MaxRelayPairs {
		a := netip.AddrPortFrom(netip.AddrFrom4([4]byte{8, 8, byte(i), 1}), 6881)
		keys = append(keys, a)
		announce(t, r, a, krpc.NodeID{24, byte(i)})
	}
	at := t0.Add(3 * time.Second)
	for i, a := range keys { // every pair refreshed just now
		announceAt(t, r, at, a, krpc.NodeID{24, byte(i)})
	}
	announceAt(t, r, at, addr(2), krpc.NodeID{25})
	announceAt(t, r, at, addr(3), krpc.NodeID{25})
	if r.RelayPairs() != 1 {
		t.Fatal("refreshed half-formed pairs locked a real session out")
	}

	r = New(Config{ID: outsiderID(rng(80)), Rand: rng(81)})
	for i := range 3 {
		for at := time.Duration(0); at < maxPendingAge; at += 10 * time.Second { // refreshed well within relayIdle
			announceAt(t, r, t0.Add(at), addr(20+i), krpc.NodeID{26, byte(i)})
		}
	}
	r.expireRelays(t0.Add(maxPendingAge))
	if n := len(r.rel.pairs); n != 0 {
		t.Fatalf("%d refreshed half-formed pairs outlived maxPendingAge", n)
	}
}

// Zoned (link-local) senders count against their source like any other.
func TestRelaySourceCountsZonedSenders(t *testing.T) {
	r := New(Config{ID: outsiderID(rng(68)), Rand: rng(69)})
	ll := netip.MustParseAddr("fe80::1").WithZone("en0")
	for i := range 2 * maxPendingPerSource {
		announce(t, r, netip.AddrPortFrom(ll, uint16(30000+i)), krpc.NodeID{17, byte(i)})
	}
	if got := len(r.rel.pairs); got != maxPendingPerSource {
		t.Fatalf("a zoned source holds %d pairs, want the cap %d", got, maxPendingPerSource)
	}
}

// A member's re-announce must not throw away the byte budget that refilled
// while the pair was quiet.
func TestRelayReannounceKeepsRefill(t *testing.T) {
	r := New(Config{ID: outsiderID(rng(76)), Rand: rng(77), RelayRate: 1000})
	a, b := addr(1), addr(2)
	announce(t, r, a, krpc.NodeID{23})
	announce(t, r, b, krpc.NodeID{23})
	pkt := append([]byte{0x01, 0}, make([]byte, 998)...) // the whole 1000-byte budget
	relayed(r, a, pkt)
	later := t0.Add(1100 * time.Millisecond)
	announceAt(t, r, later, a, krpc.NodeID{23}) // a re-announces after the budget refilled
	r.HandlePacket(later, a, pkt)
	if s, _ := r.Drain(); len(s) != 1 {
		t.Fatalf("a refilled budget was lost to a re-announce: forwarded %d", len(s))
	}
}
