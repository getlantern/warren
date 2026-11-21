package sim

import (
	"testing"
	"time"
)

// Identical seeds must produce identical runs, or scenario comparisons are noise.
func TestDeterministic(t *testing.T) {
	run := func() (int, int) {
		w := build(7, scenarios[2], sizes{ir: 60, abroad: 20, readers: 10})
		w.join(20 * time.Minute)
		w.publish(10, 5)
		w.s.RunUntil(w.s.Now.Add(5 * time.Minute))
		return w.s.Delivered, w.read(w.itemsIR, 20).ok
	}
	d1, ok1 := run()
	d2, ok2 := run()
	if d1 != d2 || ok1 != ok2 {
		t.Fatalf("runs diverged: delivered %d vs %d, reads %d vs %d", d1, d2, ok1, ok2)
	}
}

func TestPublishAndRead(t *testing.T) {
	w := build(3, scenarios[0], sizes{ir: 80, abroad: 30, readers: 20})
	w.join(30 * time.Minute)
	w.publish(20, 10)
	w.s.RunUntil(w.s.Now.Add(5 * time.Minute))
	if r := w.read(w.itemsIR, 50); r.rate() < 0.95 {
		t.Fatalf("domestic reads %d/%d", r.ok, r.total)
	}
	if r := w.read(w.itemsAb, 30); r.rate() < 0.95 {
		t.Fatalf("foreign-published reads %d/%d", r.ok, r.total)
	}
	for _, n := range w.readersIR {
		if c, _ := n.DHT.RoutingSize(); c == 0 {
			t.Fatalf("read-only node %s has an empty routing table", n.Addr)
		}
	}
	// Read-only phones must never appear in anyone's routing table.
	for _, n := range w.s.Nodes() {
		for _, r := range w.readersIR {
			if n.DHT.Knows(r.Addr) {
				t.Fatalf("%s holds read-only node %s in its table", n.Addr, r.Addr)
			}
		}
	}
}
