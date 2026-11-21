package endpoint

import (
	"net/netip"
	"sync"
	"time"
)

// inboundLimiter bounds how often a listener punches on a caller's say-so.
// Offers are signed, but anyone can mint a key, and a punch sends probes to
// the caller's claimed candidates, so without limits a forged offer naming a
// victim (or the listener's own LAN) would make this node a reflector.
//
// Budgets are checked in order, and nothing is charged unless all pass:
//   - per caller key, so one key cannot use up the shared budgets;
//   - per probed network: public candidates by /24 (/48 for IPv6), non-public
//     ones and the relay by exact address;
//   - global budgets: a tight one for punches whose planned strategy sends
//     many probes (spraying, opening many sockets, double birthday) and a
//     looser one for all punches, since even direct probing sends packets.
//
// Keys are free, so a determined attacker can still exhaust the global spray
// budget and delay legitimate hard-NAT callers; Config.Authorize is the
// defense for a listener under attack.
type inboundLimiter struct {
	mu      sync.Mutex
	callers map[[32]byte][]time.Time
	nets    map[netip.Prefix][]time.Time
	all     []time.Time
	heavy   []time.Time
}

const (
	limitWindow   = time.Minute
	perCallerMax  = 3
	perNetworkMax = 3
	// Global budgets: punches that may send many probes (spraying or opening
	// many sockets), and all punches including direct ones.
	heavyMax   = 30
	allMax     = 120
	maxTracked = 4096
)

func networkOf(a netip.Addr) netip.Prefix {
	a = a.Unmap()
	bits := a.BitLen() // non-public: the exact address
	if a.IsGlobalUnicast() && !a.IsPrivate() {
		bits = 24
		if a.Is6() {
			bits = 48
		}
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

// allow reports whether to punch now for caller toward cands (and through
// relay), recording the punch if so. heavy says the planned strategy sends
// many probes. Checks read into locals and nothing is written unless the
// punch is allowed, so refused attempts cannot grow the tables.
func (l *inboundLimiter) allow(caller [32]byte, cands []netip.AddrPort, relay netip.AddrPort, heavy bool, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.callers == nil {
		l.callers, l.nets = map[[32]byte][]time.Time{}, map[netip.Prefix][]time.Time{}
	}
	if len(l.callers)+len(l.nets) > maxTracked {
		l.sweep(now)
		if len(l.callers)+len(l.nets) > maxTracked {
			return false // still full of live entries: refuse rather than grow
		}
	}
	callerTs := prune(l.callers[caller], now)
	if len(callerTs) >= perCallerMax {
		return false
	}
	seen := map[netip.Prefix]bool{}
	var nets []netip.Prefix
	var netTs [][]time.Time
	keys := make([]netip.Prefix, 0, len(cands)+1)
	for _, c := range cands {
		keys = append(keys, networkOf(c.Addr()))
	}
	if relay.IsValid() {
		// A relay is one router, budgeted by exact address: routers sharing
		// a /24 are independent volunteers.
		a := relay.Addr().Unmap()
		p, _ := a.Prefix(a.BitLen())
		keys = append(keys, p)
	}
	for _, p := range keys {
		if !p.IsValid() || seen[p] {
			continue
		}
		seen[p] = true
		ts := prune(l.nets[p], now)
		if len(ts) >= perNetworkMax {
			return false
		}
		nets, netTs = append(nets, p), append(netTs, ts)
	}
	all, heavyTs := prune(l.all, now), prune(l.heavy, now)
	if len(all) >= allMax || (heavy && len(heavyTs) >= heavyMax) {
		return false
	}

	l.callers[caller] = append(callerTs, now)
	for i, p := range nets {
		l.nets[p] = append(netTs[i], now)
	}
	l.all = append(all, now)
	if heavy {
		l.heavy = append(heavyTs, now)
	} else {
		l.heavy = heavyTs
	}
	return true
}

func (l *inboundLimiter) sweep(now time.Time) {
	for k, ts := range l.callers {
		if len(prune(ts, now)) == 0 {
			delete(l.callers, k)
		}
	}
	for k, ts := range l.nets {
		if len(prune(ts, now)) == 0 {
			delete(l.nets, k)
		}
	}
}
