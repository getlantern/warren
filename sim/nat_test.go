package sim

import (
	"math/rand/v2"
	"net/netip"
	"testing"
	"time"
)

// A step that doesn't divide evenly into the block visits only some ports;
// allocation must still terminate and use the remaining ports.
func TestSequentialAllocatorNonCoprimeStep(t *testing.T) {
	n := NewNAT(NATConfig{Public: netip.MustParseAddr("5.5.5.5"), Mapping: EndpointDependentMapping,
		Alloc: SequentialPorts, Step: 2, BlockLo: 2048, BlockHi: 2048 + 2047}, rand.New(rand.NewPCG(1, 1)))
	local := netip.MustParseAddrPort("192.168.0.2:4000")
	now := time.Unix(1_800_000_000, 0)
	done := make(chan int, 1)
	go func() {
		ok := 0
		for i := range 2048 {
			if _, good := n.Outbound(local, netip.AddrPortFrom(netip.AddrFrom4([4]byte{9, 9, byte(i >> 8), byte(i)}), 1), now); good {
				ok++
			}
		}
		done <- ok
	}()
	select {
	case ok := <-done:
		if ok != 2048 {
			t.Fatalf("allocated %d of 2048 ports", ok)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("allocator looped forever")
	}
}

// A port-preserving NAT preserves only ports inside its allocation range;
// outside it, it allocates in range, so the quota counts the right ports.
func TestPortPreservingStaysInRange(t *testing.T) {
	n := NewNAT(NATConfig{Public: netip.MustParseAddr("5.5.5.5"), Mapping: EndpointIndependentMapping,
		Alloc: PortPreserving, BlockLo: 2048, BlockHi: 2049}, rand.New(rand.NewPCG(2, 2)))
	now := time.Unix(1_800_000_000, 0)
	dst := netip.MustParseAddrPort("9.9.9.9:1")
	for _, lp := range []uint16{4000, 4001} {
		m, ok := n.Outbound(netip.AddrPortFrom(netip.MustParseAddr("192.168.0.2"), lp), dst, now)
		if !ok || m.Port() < 2048 || m.Port() > 2049 {
			t.Fatalf("local port %d mapped to %v (ok=%v), want a port in 2048–2049", lp, m, ok)
		}
	}
	if m, ok := n.Outbound(netip.MustParseAddrPort("192.168.0.2:2048"), dst, now); ok {
		t.Fatalf("a third mapping fit in a two-port range: %v", m)
	}
}

// A range reaching below 1024 is clamped, so allocation fails when the
// usable ports run out instead of spinning forever.
func TestRangeBelow1024Terminates(t *testing.T) {
	n := NewNAT(NATConfig{Public: netip.MustParseAddr("5.5.5.5"), Mapping: EndpointDependentMapping, Alloc: RandomPorts, BlockHi: 1100}, rand.New(rand.NewPCG(3, 3)))
	now := time.Unix(1_800_000_000, 0)
	local := netip.MustParseAddrPort("192.168.0.2:4000")
	done := make(chan int, 1)
	go func() {
		ok := 0
		for i := range 200 {
			if _, good := n.Outbound(local, netip.AddrPortFrom(netip.AddrFrom4([4]byte{9, 9, byte(i >> 8), byte(i)}), 1), now); good {
				ok++
			}
		}
		done <- ok
	}()
	select {
	case ok := <-done:
		if ok != 77 {
			t.Fatalf("allocated %d mappings, want the 77 usable ports 1024–1100", ok)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("allocator spun forever")
	}
}
