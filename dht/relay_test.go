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
	if got := len(r.rel.pairs); got != maxPairsPerSource {
		t.Fatalf("one host holds %d half-formed pairs, want the cap %d", got, maxPairsPerSource)
	}
	announce(t, r, addr(2), krpc.NodeID{12})
	announce(t, r, addr(3), krpc.NodeID{12})
	if r.RelayPairs() != 1 {
		t.Fatalf("a legitimate pair could not form: %d active", r.RelayPairs())
	}
}

// One host pairing with itself from two ports, or spreading over its IPv6
// /64, must not hold more than its share of relay pairs.
func TestRelaySourceCannotHoldActiveSlots(t *testing.T) {
	r := New(Config{ID: outsiderID(rng(62)), Rand: rng(63)})
	v4 := netip.MustParseAddr("5.5.5.1")
	for i := range r.cfg.MaxRelayPairs {
		info := krpc.NodeID{13, byte(i)}
		announce(t, r, netip.AddrPortFrom(v4, uint16(20000+2*i)), info)
		announce(t, r, netip.AddrPortFrom(v4, uint16(20001+2*i)), info)
	}
	if got := r.RelayPairs(); got != maxPairsPerSource {
		t.Fatalf("one IPv4 host self-paired %d times, want the cap %d", got, maxPairsPerSource)
	}
	for i := range r.cfg.MaxRelayPairs {
		a := netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, byte(i), 1})
		b := netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, byte(i), 2})
		info := krpc.NodeID{14, byte(i)}
		announce(t, r, netip.AddrPortFrom(a, 6881), info)
		announce(t, r, netip.AddrPortFrom(b, 6881), info)
	}
	if got := r.RelayPairs(); got != 2*maxPairsPerSource {
		t.Fatalf("an IPv4 host and one IPv6 /64 hold %d pairs, want %d", got, 2*maxPairsPerSource)
	}
}
