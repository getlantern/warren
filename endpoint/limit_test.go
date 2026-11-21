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
	if len(l.sprays) != perCallerMax {
		t.Fatalf("refused attempts charged the global budget: %d", len(l.sprays))
	}
	if !l.allow(caller(8), ap("192.0.2.77:1"), netip.AddrPort{}, true, now) {
		t.Fatal("another caller was locked out")
	}
}

func TestLimiterGlobalSprayBudget(t *testing.T) {
	var l inboundLimiter
	for i := range globalMax {
		l.allow(caller(byte(i)), ap(netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, byte(i), 1}), 1).String()), netip.AddrPort{}, true, now)
	}
	if l.allow(caller(200), ap("192.0.2.1:1"), netip.AddrPort{}, true, now) {
		t.Fatal("global spray budget not enforced")
	}
	if !l.allow(caller(201), ap("192.0.2.2:1"), netip.AddrPort{}, false, now) {
		t.Fatal("a direct-only punch was refused by the spray budget")
	}
}
