package dht

import (
	"crypto/ed25519"
	"net/netip"
	"testing"
	"time"

	"github.com/getlantern/warren/krpc"
)

// Mutable operations on an empty routing table finish synchronously; they
// must still be configured and report completion, not panic.
func TestMutableOpsOnEmptyTable(t *testing.T) {
	n := New(Config{ID: outsiderID(rng(70)), Rand: rng(71)})
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	op, err := n.GetMutable(t0, [32]byte(priv.Public().(ed25519.PublicKey)), nil)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := NewMutable(priv, nil, 1, ImmutableValue([]byte("x")))
	op2, err := n.PutMutable(t0, m, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, events := n.Drain()
	var gotGet, gotPut bool
	for _, e := range events {
		switch e := e.(type) {
		case GetDone:
			gotGet = gotGet || e.Op == op
		case PutDone:
			gotPut = gotPut || e.Op == op2
		}
	}
	if !gotGet || !gotPut {
		t.Fatalf("completion events: get %v put %v", gotGet, gotPut)
	}
}

// Referrals keep IPv4 and IPv6 contacts in their own fields and honor want.
func TestReferralsSplitByFamily(t *testing.T) {
	r := rng(72)
	n := New(Config{ID: outsiderID(r), Rand: rng(73)})
	for i := 1; i <= 6; i++ {
		n.main.heard(outsiderID(r), addr(i), t0)
		n.main.heard(outsiderID(r), netip.AddrPortFrom(netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, byte(i), 15: 1}), 6881), t0)
	}
	target := outsiderID(r)
	check := func(from netip.AddrPort, want []string, v4, v6 bool) {
		t.Helper()
		resp := query(t, n, from, krpc.Msg{Q: "find_node", A: krpc.Args{ID: outsiderID(r), Target: &target, Want: want}})
		for _, ni := range resp.R.Nodes {
			if !ni.Addr.Addr().Unmap().Is4() {
				t.Errorf("IPv6 contact in nodes: %v", ni.Addr)
			}
		}
		for _, ni := range resp.R.Nodes6 {
			if ni.Addr.Addr().Is4() {
				t.Errorf("IPv4 contact in nodes6: %v", ni.Addr)
			}
		}
		if (len(resp.R.Nodes) > 0) != v4 || (len(resp.R.Nodes6) > 0) != v6 {
			t.Errorf("from %v want %v: %d v4, %d v6", from, want, len(resp.R.Nodes), len(resp.R.Nodes6))
		}
	}
	check(addr(100), nil, true, false)
	check(addr(100), []string{"n4", "n6"}, true, true)
	check(netip.MustParseAddrPort("[2001:db8::99]:1"), nil, false, true)
}

// Reflections are ordered by when we first contacted each destination, the
// moment the NAT created its mapping, not by reply arrival, and a reused
// destination is recorded once.
func TestReflectionsOrderedByMappingCreation(t *testing.T) {
	n := New(Config{ID: outsiderID(rng(74)), Rand: rng(75)})
	for i := 1; i <= 3; i++ {
		n.send(t0, addr(i), "ping", krpc.Args{}, &txn{kind: txPing})
	}
	n.reflect(addr(3), netip.MustParseAddrPort("203.0.113.1:1003"), t0)
	n.reflect(addr(1), netip.MustParseAddrPort("203.0.113.1:1001"), t0)
	n.reflect(addr(1), netip.MustParseAddrPort("203.0.113.1:1001"), t0)
	refl := n.Reflections()
	if len(refl) != 2 {
		t.Fatalf("%d reflections, want 2 (one per destination)", len(refl))
	}
	if refl[0].Order != 2 || refl[1].Order != 0 {
		t.Fatalf("orders %d, %d; want creation order 2, 0", refl[0].Order, refl[1].Order)
	}
	n.reflect(addr(9), netip.MustParseAddrPort("203.0.113.1:1009"), t0)
	if got := n.Reflections()[2].Order; got != -1 {
		t.Fatalf("never-contacted destination has order %d, want -1", got)
	}
}

var _ = time.Second
