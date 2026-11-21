package natprobe

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/getlantern/warren/krpc"
)

// DefaultGaps are the idle periods tested. RFC 4787 asks for at least two
// minutes; carrier NATs often use 30–60 seconds.
var DefaultGaps = []time.Duration{20 * time.Second, 40 * time.Second, 60 * time.Second, 90 * time.Second, 120 * time.Second, 180 * time.Second}

type GapResult struct {
	Gap           time.Duration  `json:"gap_ns"`
	Before, After netip.AddrPort `json:"-"`
	OK            bool           `json:"ok"`
	Changed       bool           `json:"changed"`
}

type TimeoutResult struct {
	Gaps []GapResult `json:"gaps"`
	// Expired is the shortest gap after which the mapping changed; zero if
	// it never did.
	Expired time.Duration `json:"expired_ns"`
	// AliveAt is the longest gap shorter than Expired that kept the mapping.
	AliveAt time.Duration `json:"alive_at_ns"`
	// Detectable is false when no gap changed the mapping: either it lives
	// longer than the longest gap, or the NAT reuses the same port for a new
	// mapping. Telling those apart needs a cooperating vantage that sends
	// unsolicited packets after the gap.
	Detectable bool `json:"detectable"`
}

// MappingTimeout estimates how long the NAT keeps an idle UDP mapping, using
// reflector (a Mainline node that returns the BEP 42 ip field). Every gap
// runs on its own socket in parallel, so the probe takes about as long as the
// longest gap.
func MappingTimeout(ctx context.Context, reflector netip.AddrPort, gaps []time.Duration) (TimeoutResult, error) {
	if len(gaps) == 0 {
		gaps = DefaultGaps
	}
	p := &prober{cfg: Config{QueryTimeout: 3 * time.Second}, rep: &Report{Versions: map[string]int{}}}
	p.cfg.defaults()
	results := make([]GapResult, len(gaps))
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	for i, gap := range gaps {
		s, err := p.open(i, true)
		if err != nil {
			// Stop and join the probes already running: each holds a socket
			// for its whole gap, and running out of sockets is the likely
			// cause of this error.
			cancel()
			wg.Wait()
			return TimeoutResult{}, err
		}
		wg.Go(func() {
			defer s.close()
			results[i] = probeGap(ctx, s, reflector, gap, p.cfg.QueryTimeout)
		})
	}
	wg.Wait()
	r := analyzeTimeouts(results)
	if !slices.ContainsFunc(results, func(g GapResult) bool { return g.OK }) {
		return r, errors.New("natprobe: reflector never reported our address")
	}
	return r, ctx.Err()
}

func probeGap(ctx context.Context, s *sock, to netip.AddrPort, gap, timeout time.Duration) GapResult {
	g := GapResult{Gap: gap}
	m, err := s.query(ctx, to, "ping", krpc.Args{}, timeout)
	if err != nil || !m.IP.IsValid() {
		return g
	}
	g.Before = m.IP
	select {
	case <-time.After(gap):
	case <-ctx.Done():
		return g
	}
	m, err = s.query(ctx, to, "ping", krpc.Args{}, timeout)
	if err != nil || !m.IP.IsValid() {
		return g
	}
	g.After, g.OK = m.IP, true
	g.Changed = g.After != g.Before
	return g
}

func analyzeTimeouts(gaps []GapResult) TimeoutResult {
	r := TimeoutResult{Gaps: gaps}
	for _, g := range gaps {
		if g.OK && g.Changed && (r.Expired == 0 || g.Gap < r.Expired) {
			r.Expired = g.Gap
		}
	}
	r.Detectable = r.Expired > 0
	for _, g := range gaps {
		if g.OK && !g.Changed && (r.Expired == 0 || g.Gap < r.Expired) && g.Gap > r.AliveAt {
			r.AliveAt = g.Gap
		}
	}
	return r
}

// KeepaliveFor picks a keepalive interval for this NAT: comfortably inside
// the longest gap known to keep the mapping, never below 10 seconds, and the
// fallback when the timeout could not be measured.
func KeepaliveFor(r TimeoutResult, fallback time.Duration) time.Duration {
	if !r.Detectable {
		return fallback
	}
	k := r.Expired / 2
	if r.AliveAt > 0 {
		k = r.AliveAt * 4 / 5
	}
	return max(k, 10*time.Second)
}
