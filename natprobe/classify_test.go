package natprobe

import (
	"fmt"
	"math"
	"math/rand/v2"
	"net/netip"
	"testing"
)

var local = netip.MustParseAddrPort("192.168.1.10:40000")

func obsWith(ports []uint16, startOrder int) []Observation {
	var obs []Observation
	for i, p := range ports {
		obs = append(obs, Observation{
			Order:  startOrder + i,
			Local:  local,
			Dest:   netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}), 6881),
			Mapped: netip.AddrPortFrom(netip.MustParseAddr("203.0.113.7"), p),
		})
	}
	return obs
}

func TestEndpointIndependentPreserving(t *testing.T) {
	a := Analyze(local, obsWith([]uint16{40000, 40000, 40000, 40000, 51111}, 0))
	if a.Mapping != MappingEndpointIndependent || !a.PortPreserving {
		t.Fatalf("got %+v", a)
	}
}

func TestSequentialWithGapsAndJitter(t *testing.T) {
	// Step 2, with a lost reply at order 3 and another subscriber's mapping
	// interleaved once.
	obs := obsWith([]uint16{20000, 20002, 20004}, 0)
	obs = append(obs, obsWith([]uint16{20010, 20012, 20014, 20016}, 4)...)
	a := Analyze(local, obs)
	if a.Allocation != AllocationSequential || a.Step != 2 {
		t.Fatalf("got %+v", a)
	}
}

func TestPortBlock(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	var ports []uint16
	for range 12 {
		ports = append(ports, uint16(34816+r.IntN(2048)))
	}
	a := Analyze(local, obsWith(ports, 0))
	if a.Allocation != AllocationBlock || a.BlockLo != 34816 || a.BlockHi != 34816+2047 {
		t.Fatalf("got %+v", a)
	}
	if a.NarrowedOdds < 0.99 || a.FullRangeOdds > 0.3 {
		t.Errorf("odds: narrowed %.3f full %.3f", a.NarrowedOdds, a.FullRangeOdds)
	}
}

func TestRandom(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	var ports []uint16
	for range 12 {
		ports = append(ports, uint16(1024+r.IntN(64512)))
	}
	if a := Analyze(local, obsWith(ports, 0)); a.Allocation != AllocationRandom {
		t.Fatalf("got %+v", a)
	}
}

// Uniformly random allocation must almost never be mistaken for structure.
func TestRandomFalsePositiveRate(t *testing.T) {
	r := rand.New(rand.NewPCG(5, 6))
	misclassified := 0
	const trials = 10000
	for range trials {
		var ports []uint16
		for range 8 {
			ports = append(ports, uint16(1024+r.IntN(64512)))
		}
		if Analyze(local, obsWith(ports, 0)).Allocation != AllocationRandom {
			misclassified++
		}
	}
	if misclassified > trials/1000 {
		t.Fatalf("%d/%d random NATs misclassified", misclassified, trials)
	}
}

func TestBirthdayOdds(t *testing.T) {
	for _, tc := range []struct {
		sockets, probes int
		want            float64
	}{
		{256, 256, 0.64},
		{256, 2048, 0.9997},
	} {
		got := BirthdayOdds(tc.sockets, tc.probes, portSpace)
		if math.Abs(got-tc.want) > 0.005 {
			t.Errorf("BirthdayOdds(%d,%d) = %.4f, want ≈%.4f", tc.sockets, tc.probes, got, tc.want)
		}
	}
}

func ExampleBirthdayOdds() {
	fmt.Printf("%.3f %.3f\n", BirthdayOdds(64, 256, portSpace), BirthdayOdds(64, 256, 2048))
	// Output: 0.224 1.000
}

// A NAT that preserves the port but uses a different public IP per
// destination gives no reusable endpoint, so it is endpoint-dependent.
func TestSamePortDifferentIPsIsDependent(t *testing.T) {
	obs := obsWith([]uint16{40000, 40000, 40000, 40000, 40000, 40000}, 0)
	for i := range obs {
		obs[i].Mapped = netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, byte(10 + i)}), 40000)
	}
	if a := Analyze(local, obs); a.Mapping != MappingEndpointDependent {
		t.Fatalf("same port across %d public IPs classified %s", len(obs), a.Mapping)
	}
}
