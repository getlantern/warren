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
//   - a global budget, charged only for punches that may spray (a peer behind
//     dependent mapping), since direct probing costs a handful of packets.
//
// Keys are free, so a determined attacker can still exhaust the global spray
// budget and delay legitimate hard-NAT callers; Config.Authorize is the
// defense for a listener under attack.
type inboundLimiter struct {
	mu      sync.Mutex
	callers map[[32]byte][]time.Time
	nets    map[netip.Prefix][]time.Time
	sprays  []time.Time
}

const (
	limitWindow   = time.Minute
	perCallerMax  = 3
	perNetworkMax = 3
	globalMax     = 30
	maxTracked    = 4096
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
// relay), recording the punch if so. spray says the punch may spray.
func (l *inboundLimiter) allow(caller [32]byte, cands []netip.AddrPort, relay netip.AddrPort, spray bool, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.callers == nil {
		l.callers, l.nets = map[[32]byte][]time.Time{}, map[netip.Prefix][]time.Time{}
	}
	l.callers[caller] = prune(l.callers[caller], now)
	if len(l.callers[caller]) >= perCallerMax {
		return false
	}
	seen := map[netip.Prefix]bool{}
	var nets []netip.Prefix
	targets := append([]netip.AddrPort(nil), cands...)
	if relay.IsValid() {
		targets = append(targets, relay)
	}
	for _, c := range targets {
		p := networkOf(c.Addr())
		if !p.IsValid() || seen[p] {
			continue
		}
		seen[p] = true
		l.nets[p] = prune(l.nets[p], now)
		if len(l.nets[p]) >= perNetworkMax {
			return false
		}
		nets = append(nets, p)
	}
	l.sprays = prune(l.sprays, now)
	if spray && len(l.sprays) >= globalMax {
		return false
	}

	l.callers[caller] = append(l.callers[caller], now)
	for _, p := range nets {
		l.nets[p] = append(l.nets[p], now)
	}
	if spray {
		l.sprays = append(l.sprays, now)
	}
	if len(l.callers)+len(l.nets) > maxTracked {
		l.sweep(now)
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
