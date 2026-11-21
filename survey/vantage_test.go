package survey

import (
	"net/netip"
	"runtime"
	"testing"

	"github.com/getlantern/warren/krpc"
)

// A flood of queries from distinct (spoofable) sources must neither grow
// the contacted set past its cap nor queue or spawn unbounded probes.
func TestInboundQueriesBounded(t *testing.T) {
	oldC, oldQ := maxContacted, maxAltQueue
	maxContacted, maxAltQueue = 50, 10
	defer func() { maxContacted, maxAltQueue = oldC, oldQ }()
	v, err := NewVantage(Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	before := runtime.NumGoroutine()
	q := &krpc.Msg{T: []byte{0, 1}, Y: krpc.Query, Q: "ping"}
	for i := range 500 {
		from := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, byte(i >> 8), byte(i)}), 9)
		v.serve(v.a, from, q)
	}
	if n := len(v.contacted); n > maxContacted {
		t.Fatalf("contacted grew to %d, cap %d", n, maxContacted)
	}
	if n := len(v.alt); n > maxAltQueue {
		t.Fatalf("alt queue holds %d, cap %d", n, maxAltQueue)
	}
	if g := runtime.NumGoroutine() - before; g > 5 {
		t.Fatalf("serving 500 queriers started %d goroutines", g)
	}
}
