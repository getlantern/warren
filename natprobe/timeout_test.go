package natprobe

import (
	"net/netip"
	"testing"
	"time"
)

func gapResult(gap time.Duration, changed bool) GapResult {
	before := netip.MustParseAddrPort("203.0.113.7:40000")
	after := before
	if changed {
		after = netip.MustParseAddrPort("203.0.113.7:51234")
	}
	return GapResult{Gap: gap, Before: before, After: after, OK: true, Changed: changed}
}

func TestCarrierTimeoutDetected(t *testing.T) {
	r := analyzeTimeouts([]GapResult{
		gapResult(20*time.Second, false),
		gapResult(40*time.Second, false),
		gapResult(60*time.Second, true),
		gapResult(90*time.Second, true),
	})
	if !r.Detectable || r.Expired != 60*time.Second || r.AliveAt != 40*time.Second {
		t.Fatalf("got %+v", r)
	}
	if k := KeepaliveFor(r, 25*time.Second); k != 32*time.Second {
		t.Errorf("keepalive %v, want 32s (80%% of the longest surviving gap)", k)
	}
}

func TestShortTimeoutFloor(t *testing.T) {
	r := analyzeTimeouts([]GapResult{gapResult(20*time.Second, true)})
	if k := KeepaliveFor(r, 25*time.Second); k != 10*time.Second {
		t.Errorf("keepalive %v, want the 10s floor", k)
	}
}

func TestPreservingNATIsUndetectable(t *testing.T) {
	r := analyzeTimeouts([]GapResult{gapResult(20*time.Second, false), gapResult(180*time.Second, false)})
	if r.Detectable || KeepaliveFor(r, 25*time.Second) != 25*time.Second {
		t.Fatalf("got %+v", r)
	}
}

func TestFailedGapsIgnored(t *testing.T) {
	r := analyzeTimeouts([]GapResult{{Gap: 20 * time.Second}, gapResult(40*time.Second, true)})
	if r.Expired != 40*time.Second || r.AliveAt != 0 {
		t.Fatalf("got %+v", r)
	}
}
