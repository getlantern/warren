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
	r := query(t, n, from, krpc.Msg{Q: "get_peers", A: krpc.Args{ID: outsiderID(rng(50)), InfoHash: &info}})
	ok := query(t, n, from, krpc.Msg{Q: "announce_peer", A: krpc.Args{ID: outsiderID(rng(51)), InfoHash: &info, Token: r.R.Token, Port: 6881, ImpliedPort: true}})
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
// source ports must not fill the table either.
func TestRelayOneHostManyPortsCannotFillTable(t *testing.T) {
	r := New(Config{ID: outsiderID(rng(60)), Rand: rng(61)})
	host := netip.MustParseAddr("5.5.5.1")
	for i := range 4 * r.cfg.MaxRelayPairs {
		announce(t, r, netip.AddrPortFrom(host, uint16(10000+i)), krpc.NodeID{11, byte(i)})
	}
	if got, want := len(r.rel.pairs), v4Limits[0].pending; got != want {
		t.Fatalf("one host holds %d half-formed pairs, want the cap %d", got, want)
	}
	announce(t, r, addr(2), krpc.NodeID{12})
	announce(t, r, addr(3), krpc.NodeID{12})
	if r.RelayPairs() != 1 {
		t.Fatalf("a legitimate pair could not form: %d active", r.RelayPairs())
	}
}

// One host pairing with itself, or spreading over its IPv6 /48, holds at
// most its share of the active slots, leaving room for everyone else.
func TestRelaySourceCannotHoldActiveSlots(t *testing.T) {
	selfPair := func(r *Node, a, b netip.AddrPort, tag byte, i int) {
		announce(t, r, a, krpc.NodeID{tag, byte(i)})
		announce(t, r, b, krpc.NodeID{tag, byte(i)})
	}
	r := New(Config{ID: outsiderID(rng(62)), Rand: rng(63)})
	v4 := netip.MustParseAddr("5.5.5.1")
	for i := range r.cfg.MaxRelayPairs {
		selfPair(r, netip.AddrPortFrom(v4, uint16(20000+2*i)), netip.AddrPortFrom(v4, uint16(20001+2*i)), 13, i)
	}
	if got, want := r.RelayPairs(), v4Limits[0].complete; got != want {
		t.Fatalf("one IPv4 host self-paired %d times, want the cap %d", got, want)
	}

	r = New(Config{ID: outsiderID(rng(66)), Rand: rng(67)})
	for i := range r.cfg.MaxRelayPairs { // a different /64 each time, one /48
		a := netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, byte(i), 15: 1})
		b := netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, byte(i), 15: 2})
		selfPair(r, netip.AddrPortFrom(a, 6881), netip.AddrPortFrom(b, 6881), 14, i)
	}
	if got, want := r.RelayPairs(), v6Limits[1].complete; got != want {
		t.Fatalf("one IPv6 /48 holds %d pairs, want the cap %d", got, want)
	}
}

// A busy client binds a relay on every dial; five dials to five peers in a
// minute through the same router must all keep their fallback.
func TestRelayBusyClientKeepsFallback(t *testing.T) {
	r := New(Config{ID: outsiderID(rng(68)), Rand: rng(69)})
	me := netip.MustParseAddr("5.5.5.1")
	for i := range 5 {
		info := krpc.NodeID{16, byte(i)}
		announce(t, r, netip.AddrPortFrom(me, uint16(40000+i)), info)
		announce(t, r, addr(10+i), info)
	}
	if got := r.RelayPairs(); got != 5 {
		t.Fatalf("a client's 5 dials formed %d pairs", got)
	}
}

// Pairs that never forward anything (the direct path won) free their slot
// sooner than pairs in use.
func TestRelayUnusedPairsExpireSooner(t *testing.T) {
	r := New(Config{ID: outsiderID(rng(70)), Rand: rng(71)})
	announce(t, r, addr(1), krpc.NodeID{17})
	announce(t, r, addr(2), krpc.NodeID{17})
	announce(t, r, addr(3), krpc.NodeID{18})
	announce(t, r, addr(4), krpc.NodeID{18})
	relayed(r, addr(3), utpLike) // pair 18 carries traffic
	r.expireRelays(t0.Add(relayUnusedIdle))
	if r.rel.pairs[krpc.NodeID{17}] != nil {
		t.Fatal("an unused pair outlived relayUnusedIdle")
	}
	if r.rel.pairs[krpc.NodeID{18}] == nil {
		t.Fatal("a pair in use expired early")
	}
}

// Zoned (link-local) senders count against their source like any other.
func TestRelaySourceCountsZonedSenders(t *testing.T) {
	r := New(Config{ID: outsiderID(rng(64)), Rand: rng(65)})
	ll := netip.MustParseAddr("fe80::1").WithZone("en0")
	for i := range 4 * v6Limits[0].pending {
		announce(t, r, netip.AddrPortFrom(ll, uint16(30000+i)), krpc.NodeID{15, byte(i)})
	}
	if got, want := len(r.rel.pairs), v6Limits[0].pending; got != want {
		t.Fatalf("a zoned source holds %d pairs, want the cap %d", got, want)
	}
}
