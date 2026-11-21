package dht

import (
	"net/netip"
	"time"
)

// isolation tracks whether the border has closed: domestic contacts keep
// answering while foreign ones have stopped. Unlike health, which reacts to a
// change and then adapts, isolation is a durable state that lasts as long as
// the shutdown, and it ends as soon as any foreign node answers again.
type isolation struct {
	isolated     bool
	since        time.Time
	lastForeign  time.Time
	lastDomestic time.Time
	foreignFails int
	probes       []netip.AddrPort
	nextProbe    int
	lastProbe    time.Time
}

const (
	isoMinForeignFails = 16
	isoForeignSilence  = 3 * time.Minute
	isoDomesticFresh   = 2 * time.Minute
	isoProbeInterval   = 2 * time.Minute
	isoMaxProbes       = 8
)

func (s *isolation) heard(domestic bool, now time.Time) {
	if domestic {
		s.lastDomestic = now
		return
	}
	s.lastForeign, s.foreignFails = now, 0
}

func (s *isolation) foreignFailed(a netip.AddrPort) {
	s.foreignFails++
	for _, p := range s.probes {
		if p == a {
			return
		}
	}
	if len(s.probes) < isoMaxProbes {
		s.probes = append(s.probes, a)
	} else {
		s.probes[s.foreignFails%isoMaxProbes] = a
	}
}

func (s *isolation) eval(now time.Time) (changed bool) {
	switch {
	case !s.isolated && s.foreignFails >= isoMinForeignFails &&
		now.Sub(s.lastForeign) >= isoForeignSilence && now.Sub(s.lastDomestic) <= isoDomesticFresh:
		s.isolated, s.since = true, now
		return true
	case s.isolated && s.lastForeign.After(s.since):
		s.isolated = false
		return true
	}
	return false
}

// probeDue returns a remembered foreign contact to ping, at most every
// isoProbeInterval, so recovery is noticed even though lookups skip foreign
// candidates while isolated.
func (s *isolation) probeDue(now time.Time) (netip.AddrPort, bool) {
	if len(s.probes) == 0 || now.Sub(s.lastProbe) < isoProbeInterval {
		return netip.AddrPort{}, false
	}
	s.lastProbe = now
	a := s.probes[s.nextProbe%len(s.probes)]
	s.nextProbe++
	return a, true
}
