package dht

import (
	"net/netip"
	"testing"
	"time"
)

func TestIsolationLifecycle(t *testing.T) {
	var s isolation
	now := t0
	foreign := netip.MustParseAddrPort("45.0.0.1:6881")
	s.heard(false, now)
	s.heard(true, now)

	// Foreign failures alone, while foreign nodes still answered recently,
	// are ordinary churn.
	for range isoMinForeignFails {
		s.foreignFailed(foreign)
	}
	if s.eval(now.Add(time.Minute)) {
		t.Fatal("isolated before foreign silence")
	}

	// Foreign silence plus fresh domestic answers is isolation.
	now = now.Add(isoForeignSilence)
	s.heard(true, now)
	if !s.eval(now) || !s.isolated {
		t.Fatal("not isolated")
	}

	// Probes are rate limited and draw from failed foreign contacts.
	if a, ok := s.probeDue(now); !ok || a != foreign {
		t.Fatalf("probe = %v %v", a, ok)
	}
	if _, ok := s.probeDue(now.Add(time.Second)); ok {
		t.Fatal("probe not rate limited")
	}

	// One foreign answer ends it.
	s.heard(false, now.Add(time.Minute))
	if !s.eval(now.Add(time.Minute)) || s.isolated {
		t.Fatal("isolation did not end")
	}
}

// Losing everything (no domestic answers either) is our own network being
// down, not a border closing.
func TestTotalOutageIsNotIsolation(t *testing.T) {
	var s isolation
	s.heard(true, t0)
	for range isoMinForeignFails {
		s.foreignFailed(netip.MustParseAddrPort("45.0.0.1:6881"))
	}
	if s.eval(t0.Add(10 * time.Minute)) {
		t.Fatal("total outage treated as isolation")
	}
}
