package sim

import (
	"net/netip"
	"testing"
	"time"
)

// An idle network must stay quiet. Guards against feedback loops such as two
// nodes in each other's replacement caches verifying each other forever.
// Steady state is ~12, dominated by 15-minute bucket refreshes.
func TestIdleTraffic(t *testing.T) {
	w := build(1, scenarios[2], sizes{ir: 120, abroad: 40, readers: 20})
	w.join(20 * time.Minute)
	sent := 0
	w.s.OnSend = func(*Node, netip.AddrPort, []byte) { sent++ }
	w.s.RunUntil(w.s.Now.Add(10 * time.Minute))
	perNodeMinute := float64(sent) / float64(len(w.s.Nodes())) / 10
	t.Logf("steady state: %.1f datagrams per node per minute", perNodeMinute)
	if perNodeMinute > 30 {
		t.Fatalf("idle traffic %.1f datagrams/node/minute exceeds 30; the ping storm this guards against ran at ~600", perNodeMinute)
	}
}
