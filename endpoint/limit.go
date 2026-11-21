package endpoint

import (
	"net/netip"
	"sync"
	"time"
)

// inboundLimiter bounds how often a listener punches toward a network on a
// caller's say-so. Offers are signed but anyone can make a key, and a punch
// sends thousands of probes to the caller's claimed candidates, so without
// limits a forged offer naming a victim would make this node a reflector.
type inboundLimiter struct {
	mu     sync.Mutex
	recent map[netip.Prefix][]time.Time
	all    []time.Time
}

const (
	limitWindow    = time.Minute
	perNetworkMax  = 3
	globalMax      = 30
	maxTrackedNets = 1024
)

func networkOf(a netip.Addr) netip.Prefix {
	a = a.Unmap()
	bits := 24
	if a.Is6() {
		bits = 48
	}
	p, _ := a.Prefix(bits)
	return p
}

func prune(ts []time.Time, now time.Time) []time.Time {
	i := 0
	for i < len(ts) && now.Sub(ts[i]) >= limitWindow {
		i++
	}
	return ts[i:]
}

// allow reports whether to punch toward these candidates now, and records
// the punch if so.
func (l *inboundLimiter) allow(cands []netip.AddrPort, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.recent == nil {
		l.recent = map[netip.Prefix][]time.Time{}
	}
	l.all = prune(l.all, now)
	if len(l.all) >= globalMax {
		return false
	}
	var nets []netip.Prefix
	for _, c := range cands {
		if a := c.Addr(); a.IsGlobalUnicast() && !a.IsPrivate() {
			p := networkOf(a)
			l.recent[p] = prune(l.recent[p], now)
			if len(l.recent[p]) >= perNetworkMax {
				return false
			}
			nets = append(nets, p)
		}
	}
	if len(l.recent) > maxTrackedNets {
		for p, ts := range l.recent {
			if len(prune(ts, now)) == 0 {
				delete(l.recent, p)
			}
		}
	}
	for _, p := range nets {
		l.recent[p] = append(l.recent[p], now)
	}
	l.all = append(l.all, now)
	return true
}
