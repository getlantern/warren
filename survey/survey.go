// Package survey measures, from a Lantern-run vantage on public Mainline, how
// many DHT nodes in a region could serve as routers: nodes that answer
// unsolicited traffic. That supply decides whether a community overlay
// survives a shutdown, since phones behind CGNAT can only be read-only.
//
// Two measurements need only one host:
//
//   - Cold reachability: ping nodes learned only from other nodes' referrals,
//     which have never sent us anything. A reply means the node accepts
//     unsolicited traffic from a new address.
//   - Port filtering: when a node queries socket A, ping it back from socket B
//     on another port. A reply means its NAT does not filter by port.
//
// Telling address-dependent from endpoint-independent filtering needs a
// second vantage IP. Only per-label counters are kept; addresses are used in
// memory to address probes and are never recorded.
package survey

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
)

// Labeler maps an address to a region label such as "IR". Nodes outside every
// configured region get "other".
type Labeler func(netip.Addr) string

// PrefixLabeler labels addresses by CIDR lists, e.g. {"IR": [...]}.
func PrefixLabeler(regions map[string][]netip.Prefix) Labeler {
	return func(a netip.Addr) string {
		a = a.Unmap()
		for label, ps := range regions {
			for _, p := range ps {
				if p.Contains(a) {
					return label
				}
			}
		}
		return "other"
	}
}

type Counts struct {
	ColdProbed, ColdAnswered       int
	InboundSeen, AltProbed, AltAns int
}

type Tally struct {
	mu sync.Mutex
	m  map[string]*Counts
}

func NewTally() *Tally { return &Tally{m: map[string]*Counts{}} }

func (t *Tally) update(label string, f func(*Counts)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.m[label]
	if c == nil {
		c = &Counts{}
		t.m[label] = c
	}
	f(c)
}

func (t *Tally) Snapshot() map[string]Counts {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := map[string]Counts{}
	for k, v := range t.m {
		out[k] = *v
	}
	return out
}

func pct(n, d int) string {
	if d == 0 {
		return "   –"
	}
	return fmt.Sprintf("%3.0f%%", 100*float64(n)/float64(d))
}

func (t *Tally) String() string {
	snap := t.Snapshot()
	var labels []string
	for k := range snap {
		labels = append(labels, k)
	}
	slices.Sort(labels)
	var b strings.Builder
	fmt.Fprintf(&b, "%-8s %22s %26s\n", "region", "cold reachable", "answers from other port")
	for _, l := range labels {
		c := snap[l]
		fmt.Fprintf(&b, "%-8s %s of %6d probed   %s of %6d inbound\n",
			l, pct(c.ColdAnswered, c.ColdProbed), c.ColdProbed, pct(c.AltAns, c.AltProbed), c.AltProbed)
	}
	return b.String()
}
