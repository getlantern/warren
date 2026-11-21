package endpoint

import (
	"net/netip"
	"testing"
	"time"
)

var now = time.Unix(1_800_000_000, 0)

func ap(s string) []netip.AddrPort { return []netip.AddrPort{netip.MustParseAddrPort(s)} }

func caller(i byte) [32]byte { return [32]byte{i} }

func TestLimiterPerNetwork(t *testing.T) {
	var l inboundLimiter
	for i := range perNetworkMax {
		if !l.allow(caller(byte(i)), ap("203.0.113.9:4000"), netip.AddrPort{}, false, now) {
			t.Fatalf("punch %d refused", i)
		}
	}
	if l.allow(caller(99), ap("203.0.113.200:5000"), netip.AddrPort{}, false, now) {
		t.Fatal("another address in the same /24 passed the per-network limit")
	}
	if !l.allow(caller(99), ap("198.51.100.1:1"), netip.AddrPort{}, false, now) {
		t.Fatal("an unrelated network was refused")
	}
	if !l.allow(caller(0), ap("203.0.113.9:4000"), netip.AddrPort{}, false, now.Add(limitWindow)) {
		t.Fatal("limit did not reset after the window")
	}
}

// Non-public candidates, which a responder probes directly but never
// sprays, are budgeted per address, as is the relay.
func TestLimiterCountsPrivateAndRelay(t *testing.T) {
	var l inboundLimiter
	for i := range perNetworkMax {
		l.allow(caller(byte(i)), ap("192.168.1.1:80"), netip.AddrPort{}, false, now)
	}
	if l.allow(caller(50), ap("192.168.1.1:22"), netip.AddrPort{}, false, now) {
		t.Fatal("a private address escaped the limit")
	}
	if !l.allow(caller(51), ap("192.168.1.2:22"), netip.AddrPort{}, false, now) {
		t.Fatal("a different private address was refused")
	}
	var r inboundLimiter
	relay := netip.MustParseAddrPort("2.176.0.9:6881")
	for i := range perNetworkMax {
		r.allow(caller(byte(i)), ap(fmtAddr(i)), relay, false, now)
	}
	if r.allow(caller(60), ap("198.18.0.1:1"), relay, false, now) {
		t.Fatal("the relay's budget was not enforced")
	}
}

func fmtAddr(i int) string {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, byte(10 + i), 1}), 1).String()
}

func TestLimiterPerCallerBeforeGlobal(t *testing.T) {
	var l inboundLimiter
	attacker := caller(7)
	for i := range perCallerMax {
		l.allow(attacker, ap(fmtAddr(i)), netip.AddrPort{}, true, now)
	}
	// The attacker's own budget is spent; its refused attempts must not eat
	// the shared spray budget.
	for i := range 100 {
		if l.allow(attacker, ap(fmtAddr(50+i%100)), netip.AddrPort{}, true, now) {
			t.Fatal("caller exceeded its own budget")
		}
	}
	if len(l.heavy) != perCallerMax {
		t.Fatalf("refused attempts charged the global budget: %d", len(l.heavy))
	}
	if !l.allow(caller(8), ap("192.0.2.77:1"), netip.AddrPort{}, true, now) {
		t.Fatal("another caller was locked out")
	}
}

func TestLimiterGlobalSprayBudget(t *testing.T) {
	var l inboundLimiter
	for i := range heavyMax {
		l.allow(caller(byte(i)), ap(netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, byte(i), 1}), 1).String()), netip.AddrPort{}, true, now)
	}
	if l.allow(caller(200), ap("192.0.2.1:1"), netip.AddrPort{}, true, now) {
		t.Fatal("global spray budget not enforced")
	}
	if !l.allow(caller(201), ap("192.0.2.2:1"), netip.AddrPort{}, false, now) {
		t.Fatal("a direct-only punch was refused by the spray budget")
	}
}

func TestLimiterGlobalAllBudget(t *testing.T) {
	var l inboundLimiter
	for i := range allMax {
		l.allow(caller(byte(i)), ap(netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, byte(18 + i/200), byte(i), 1}), 1).String()), netip.AddrPort{}, false, now)
	}
	if l.allow(caller(250), ap("192.0.2.9:1"), netip.AddrPort{}, false, now) {
		t.Fatal("direct punches have no global budget")
	}
}

// Refused attempts from ever-new keys and addresses must not grow the tables.
func TestLimiterRefusalsDoNotGrow(t *testing.T) {
	var l inboundLimiter
	for i := range heavyMax {
		l.allow(caller(byte(i)), ap(netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, byte(i), 1}), 1).String()), netip.AddrPort{}, true, now)
	}
	before := len(l.callers) + len(l.nets)
	for i := range 5000 {
		var k [32]byte
		k[0], k[1] = byte(i), byte(i>>8)
		l.allow(k, ap(netip.AddrPortFrom(netip.AddrFrom4([4]byte{100, byte(i >> 8), byte(i), 1}), 1).String()), netip.AddrPort{}, true, now)
	}
	if after := len(l.callers) + len(l.nets); after != before {
		t.Fatalf("refused attempts grew the tables from %d to %d entries", before, after)
	}
}

// Relays are budgeted by exact address, so independent routers in one /24
// don't lock each other out, and by network in a looser bucket, so naming
// relays across a victim /24 is still capped.
func TestLimiterRelayBudgets(t *testing.T) {
	var l inboundLimiter
	r1 := netip.MustParseAddrPort("2.176.0.9:6881")
	for i := range perNetworkMax {
		l.allow(caller(byte(i)), ap(fmtAddr(i)), r1, false, now)
	}
	if l.allow(caller(69), ap("198.18.4.1:1"), r1, false, now) {
		t.Fatal("one relay address exceeded its own budget")
	}
	if !l.allow(caller(70), ap("198.18.5.1:1"), netip.MustParseAddrPort("2.176.0.10:6881"), false, now) {
		t.Fatal("a different router in the same /24 was refused")
	}
	var v inboundLimiter
	allowed := 0
	for i := range 2 * relayNetMax {
		relay := netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, byte(i + 1)}), 6881)
		if v.allow(caller(byte(i)), ap(fmtAddr(i)), relay, false, now) {
			allowed++
		}
	}
	if allowed != relayNetMax {
		t.Fatalf("relays across one /24 allowed %d punches, want the network cap %d", allowed, relayNetMax)
	}
}

func TestChooseRelay(t *testing.T) {
	a, b, own := netip.MustParseAddrPort("2.176.0.1:6881"), netip.MustParseAddrPort("2.176.0.2:6881"), netip.MustParseAddrPort("2.176.0.9:6881")
	knowsB := func(r netip.AddrPort) bool { return r == b }
	none := func(netip.AddrPort) bool { return false }
	var zero netip.AddrPort
	mine := []netip.AddrPort{own}
	for _, tc := range []struct {
		name          string
		relayOnly     bool
		offered       []netip.AddrPort
		own           []netip.AddrPort
		knows         func(netip.AddrPort) bool
		relay, charge netip.AddrPort
	}{
		{"caller's first, charged", false, []netip.AddrPort{a, b}, mine, none, a, a},
		{"no offer", false, nil, mine, none, zero, zero},
		{"relay-only, known offered relay, uncharged", true, []netip.AddrPort{a, b}, mine, knowsB, b, zero},
		{"relay-only, own fallback, uncharged", true, []netip.AddrPort{a}, mine, none, own, zero},
		{"relay-only, nothing trusted: no relay", true, []netip.AddrPort{a}, nil, none, zero, zero},
	} {
		relay, charge := chooseRelay(tc.relayOnly, tc.offered, tc.own, tc.knows)
		if relay != tc.relay || charge != tc.charge {
			t.Errorf("%s: got (%v, %v), want (%v, %v)", tc.name, relay, charge, tc.relay, tc.charge)
		}
	}
}

// A relay-only listener that falls back to its own closest router for every
// caller must not lock itself out after a handful of offers: that router is
// one we chose, so it is not budgeted by address.
func TestRelayOnlyFallbackNotLockedOut(t *testing.T) {
	var l inboundLimiter
	own := netip.MustParseAddrPort("2.176.0.9:6881")
	unknown := []netip.AddrPort{netip.MustParseAddrPort("6.6.6.6:6881")}
	none := func(netip.AddrPort) bool { return false }
	for i := range 2 * perNetworkMax {
		relay, charge := chooseRelay(true, unknown, []netip.AddrPort{own}, none)
		if relay != own {
			t.Fatalf("relay-only fallback chose %v, want our own %v", relay, own)
		}
		if !l.allow(caller(byte(i)), ap(fmtAddr(i)), charge, false, now) {
			t.Fatalf("caller %d refused: the listener's own fallback relay was rate limited", i)
		}
	}
	if _, charge := chooseRelay(false, unknown, nil, none); charge != unknown[0] {
		t.Fatal("a relay taken on the caller's word must still be budgeted")
	}
}
