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
	// relayNets budgets the networks relays sit in, separately and more
	// loosely than candidate networks: routers sharing a /24 are independent
	// volunteers, but a victim network still has a ceiling.
	relayNets map[netip.Prefix][]time.Time
	all       []time.Time
	heavy     []time.Time
}

const (
	limitWindow   = time.Minute
	perCallerMax  = 3
	perNetworkMax = 3
	relayNetMax   = 3 * perNetworkMax
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
//
// resume marks a punch that moves an existing session: it skips the
// per-caller budget (the session has its own) and, when light, the
// per-network and per-relay-address ones (the relay network bucket still
// applies), so several sessions moving to one new network aren't stranded. A heavy resume still counts against every network it probes,
// and every resume against the global budgets: owning a session must not
// buy unlimited sprays at addresses of the caller's choosing.
func (l *inboundLimiter) allow(caller [32]byte, cands []netip.AddrPort, relay netip.AddrPort, heavy, resume bool, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.callers == nil {
		l.callers, l.nets, l.relayNets = map[[32]byte][]time.Time{}, map[netip.Prefix][]time.Time{}, map[netip.Prefix][]time.Time{}
	}
	if l.tracked() > maxTracked {
		l.sweep(now)
		if l.tracked() > maxTracked {
			return false // still full of live entries: refuse rather than grow
		}
	}
	callerTs := prune(l.callers[caller], now)
	if !resume && len(callerTs) >= perCallerMax {
		return false
	}
	if resume && !heavy {
		cands = nil // a light resume isn't charged per network
	}
	seen := map[netip.Prefix]bool{}
	var nets []netip.Prefix
	var netTs [][]time.Time
	keys := make([]netip.Prefix, 0, len(cands)+1)
	for _, c := range cands {
		keys = append(keys, networkOf(c.Addr()))
	}
	var relayNet netip.Prefix
	var relayNetTs []time.Time
	if relay.IsValid() {
		// A relay is budgeted twice: by exact address like any probed host,
		// and by its network in the looser relay bucket.
		a := relay.Addr().Unmap()
		if p, _ := a.Prefix(a.BitLen()); !resume || heavy {
			keys = append(keys, p) // a light resume keeps only the network bucket
		}
		relayNet = networkOf(a)
		relayNetTs = prune(l.relayNets[relayNet], now)
		if len(relayNetTs) >= relayNetMax {
			return false
		}
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

	if !resume {
		l.callers[caller] = append(callerTs, now)
	}
	for i, p := range nets {
		l.nets[p] = append(netTs[i], now)
	}
	if relayNet.IsValid() {
		l.relayNets[relayNet] = append(relayNetTs, now)
	}
	l.all = append(all, now)
	if heavy {
		l.heavy = append(heavyTs, now)
	} else {
		l.heavy = heavyTs
	}
	return true
}

func (l *inboundLimiter) tracked() int { return len(l.callers) + len(l.nets) + len(l.relayNets) }

func (l *inboundLimiter) sweep(now time.Time) {
	for k, ts := range l.relayNets {
		if len(prune(ts, now)) == 0 {
			delete(l.relayNets, k)
		}
	}
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
