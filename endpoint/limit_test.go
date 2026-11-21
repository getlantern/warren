package endpoint

import (
	"net/netip"
	"testing"
	"time"
)

func TestInboundLimiter(t *testing.T) {
	var l inboundLimiter
	now := time.Unix(1_800_000_000, 0)
	victim := []netip.AddrPort{netip.MustParseAddrPort("203.0.113.9:4000")}
	sameNet := []netip.AddrPort{netip.MustParseAddrPort("203.0.113.200:5000")}
	for i := range perNetworkMax {
		if !l.allow(victim, now) {
			t.Fatalf("punch %d refused", i)
		}
	}
	if l.allow(sameNet, now) {
		t.Fatal("another address in the same /24 was allowed past the limit")
	}
	if !l.allow([]netip.AddrPort{netip.MustParseAddrPort("198.51.100.1:1")}, now) {
		t.Fatal("an unrelated network was refused")
	}
	if !l.allow(victim, now.Add(limitWindow)) {
		t.Fatal("limit did not reset after the window")
	}
	var g inboundLimiter
	for i := range globalMax {
		g.allow([]netip.AddrPort{netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, byte(i), 1}), 1)}, now)
	}
	if g.allow([]netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:1")}, now) {
		t.Fatal("global limit not enforced")
	}
}
