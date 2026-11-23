package sim

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getlantern/warren/dht"
	"github.com/getlantern/warren/krpc"
	"github.com/getlantern/warren/overlay"
)

var (
	start    = time.Unix(1_800_000_000, 0)
	farsi    = overlay.NewKey("fa")
	homeNet  = netip.MustParsePrefix("2.176.0.0/12")
	domestic = func(a netip.Addr) bool { return homeNet.Contains(a) }
)

type scenario struct {
	name             string
	domesticCopies   bool
	detectPartitions bool
	isolation        bool
}

var scenarios = []scenario{
	{"plain", false, false, false},
	{"+domestic", true, false, false},
	{"+detect", true, true, false},
	{"+isolation", true, true, true},
}

type world struct {
	s         *Sim
	routersIR []*Node
	routersAb []*Node
	readersIR []*Node
	itemsIR   []krpc.NodeID
	itemsAb   []krpc.NodeID
	results   map[*Node]map[dht.OpID]chan done
}

type done struct {
	g  dht.GetDone
	at time.Time
}

type sizes struct {
	name                string
	ir, abroad, readers int
	// churn is the fraction of domestic routers that go offline, spread
	// over the first half hour after the cut.
	churn float64
}

func build(seed uint64, sc scenario, sz sizes) *world {
	s := New(seed, start)
	w := &world{s: s, results: map[*Node]map[dht.OpID]chan done{}}
	s.OnEvent = func(n *Node, e dht.Event) {
		if g, ok := e.(dht.GetDone); ok {
			if ch := w.results[n][g.Op]; ch != nil {
				ch <- done{g, s.Now}
			}
		}
	}
	mk := func(a netip.AddrPort, dom, ro bool) *Node {
		var id krpc.NodeID
		for i := range id {
			id[i] = byte(s.Rand().Uint32())
		}
		return s.Add(a, dom, dht.Config{
			ID:                 farsi.Tag(krpc.SecureID(a.Addr(), id)),
			Community:          &farsi,
			ReadOnly:           ro,
			Domestic:           domestic,
			DomesticCopies:     sc.domesticCopies,
			PartitionDetection: sc.detectPartitions,
			IsolationMode:      sc.isolation,
		})
	}
	for i := range sz.ir {
		a := netip.AddrPortFrom(netip.AddrFrom4([4]byte{2, byte(176 + (i>>8)&15), byte(i), byte(10 + s.Rand().IntN(200))}), 6881)
		w.routersIR = append(w.routersIR, mk(a, true, false))
	}
	for i := range sz.abroad {
		a := netip.AddrPortFrom(netip.AddrFrom4([4]byte{45, byte(i >> 8), byte(i), 7}), 6881)
		w.routersAb = append(w.routersAb, mk(a, false, false))
	}
	for i := range sz.readers {
		a := netip.AddrPortFrom(netip.AddrFrom4([4]byte{2, byte(191), byte(i), 99}), 40000+uint16(i))
		w.readersIR = append(w.readersIR, mk(a, true, true))
	}
	return w
}

// join bootstraps every node from a few foreign seeds (like Lantern-run
// nodes), staggered over ten minutes, then lets the network settle.
func (w *world) join(settle time.Duration) {
	seeds := []netip.AddrPort{w.routersAb[0].Addr, w.routersAb[1].Addr, w.routersAb[2].Addr}
	all := slices.Concat(w.routersAb, w.routersIR, w.readersIR)
	w.s.Rand().Shuffle(len(all), func(i, j int) { all[i], all[j] = all[j], all[i] })
	for i, n := range all {
		w.s.RunUntil(start.Add(time.Duration(i) * 10 * time.Minute / time.Duration(len(all))))
		w.s.Do(n, func(now time.Time) { n.DHT.Bootstrap(now, seeds) })
	}
	w.s.RunUntil(start.Add(settle))
}

func (w *world) publish(nIR, nAb int) {
	for i := range nIR {
		n := w.routersIR[i*len(w.routersIR)/nIR]
		w.s.Do(n, func(now time.Time) {
			t, _ := n.DHT.Publish(now, dht.ImmutableValue(fmt.Appendf(nil, "ir-%d", i)))
			w.itemsIR = append(w.itemsIR, t)
		})
	}
	for i := range nAb {
		n := w.routersAb[3+i*(len(w.routersAb)-3)/nAb]
		w.s.Do(n, func(now time.Time) {
			t, _ := n.DHT.Publish(now, dht.ImmutableValue(fmt.Appendf(nil, "ab-%d", i)))
			w.itemsAb = append(w.itemsAb, t)
		})
	}
}

type readStats struct {
	ok, total int
	latencies []time.Duration
}

func (r readStats) rate() float64 { return float64(r.ok) / float64(r.total) }
func (r readStats) p50() time.Duration {
	if len(r.latencies) == 0 {
		return 0
	}
	slices.Sort(r.latencies)
	return r.latencies[len(r.latencies)/2]
}

// read issues reads from domestic nodes (half read-only phones, half routers)
// for random items and waits for them all.
func (w *world) read(items []krpc.NodeID, count int) readStats {
	type pending struct {
		ch    chan done
		start time.Time
	}
	var ps []pending
	for i := range count {
		var n *Node
		for n == nil || n.Offline {
			if i%2 == 0 {
				n = w.readersIR[w.s.Rand().IntN(len(w.readersIR))]
			} else {
				n = w.routersIR[w.s.Rand().IntN(len(w.routersIR))]
			}
		}
		target := items[w.s.Rand().IntN(len(items))]
		w.s.Do(n, func(now time.Time) {
			op, err := n.DHT.Get(now, target)
			if err != nil {
				return
			}
			ch := make(chan done, 1)
			if w.results[n] == nil {
				w.results[n] = map[dht.OpID]chan done{}
			}
			w.results[n][op] = ch
			ps = append(ps, pending{ch, now})
		})
		w.s.RunUntil(w.s.Now.Add(200 * time.Millisecond))
	}
	w.s.RunUntil(w.s.Now.Add(45 * time.Second))
	var st readStats
	st.total = count
	for _, p := range ps {
		select {
		case d := <-p.ch:
			if d.g.Value != nil {
				st.ok++
				st.latencies = append(st.latencies, d.at.Sub(p.start))
			}
		default:
		}
	}
	return st
}

type row struct {
	label string
	ir    readStats
	ab    readStats
}

func runShutdown(seed uint64, sc scenario, sz sizes) []row {
	w := build(seed, sc, sz)
	w.join(60 * time.Minute)
	w.publish(60, 20)
	w.s.RunUntil(w.s.Now.Add(15 * time.Minute))

	var rows []row
	measure := func(label string) {
		rows = append(rows, row{label, w.read(w.itemsIR, 100), w.read(w.itemsAb, 40)})
	}
	measure("before")
	cut := w.s.Now
	w.s.Border = true
	// Departures are spread over the first half hour as scheduled events, so
	// they happen at their times even while a measurement is running.
	leaving := w.s.Rand().Perm(len(w.routersIR))[:int(sz.churn*float64(len(w.routersIR)))]
	for i, idx := range leaving {
		n := w.routersIR[idx]
		w.s.At(cut.Add(time.Duration(i+1)*30*time.Minute/time.Duration(len(leaving)+1)), func() { n.Offline = true })
	}
	for _, after := range []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, 30 * time.Minute, time.Hour, 2 * time.Hour, 3 * time.Hour} {
		if at := cut.Add(after); at.After(w.s.Now) {
			w.s.RunUntil(at)
		}
		measure("+" + after.String())
	}
	w.s.Border = false
	w.s.RunUntil(w.s.Now.Add(30 * time.Minute))
	measure("reopen+30m")
	return rows
}

// TestShutdown cuts the border of a Farsi-style community and measures whether
// domestic nodes can still read domestically published records.
func TestShutdown(t *testing.T) {
	if testing.Short() {
		t.Skip("multi-hour virtual-time simulation")
	}
	all := []sizes{
		{name: "balanced", ir: 240, abroad: 80, readers: 60},
		{name: "router-scarce + churn", ir: 60, abroad: 180, readers: 200, churn: 0.2},
	}
	// Each (size, scenario) is its own deterministic simulation sharing no
	// state, so they run in parallel: one after another they took about ten
	// minutes under -race, at go test's default timeout.
	results := make([]map[string][]row, len(all))
	var mu sync.Mutex
	t.Run("sims", func(t *testing.T) {
		for i, sz := range all {
			results[i] = map[string][]row{}
			for _, sc := range scenarios {
				t.Run(sz.name+"/"+sc.name, func(t *testing.T) {
					t.Parallel()
					rows := runShutdown(42, sc, sz)
					mu.Lock()
					results[i][sc.name] = rows
					mu.Unlock()
				})
			}
		}
	})
	for i, sz := range all {
		results := results[i]
		// The isolation guarantee is checked whenever that scenario ran, even
		// when -run selected a single simulation.
		for _, r := range results["+isolation"] {
			if r.ir.rate() < 0.98 || r.ab.rate() < 0.98 {
				t.Errorf("%s %s: isolation mode read %.0f%% domestic, %.0f%% foreign; want ≥98%%",
					sz.name, r.label, 100*r.ir.rate(), 100*r.ab.rate())
			}
		}
		if len(results) < len(scenarios) {
			continue // the comparison table needs every scenario
		}
		var b strings.Builder
		fmt.Fprintf(&b, "\n%s: %d domestic routers, %d abroad, %d domestic read-only phones, %.0f%% domestic router churn after the cut\n",
			sz.name, sz.ir, sz.abroad, sz.readers, 100*sz.churn)
		fmt.Fprintf(&b, "%-10s", "")
		for _, sc := range scenarios {
			fmt.Fprintf(&b, "  %-23s", sc.name)
		}
		fmt.Fprintf(&b, "\n%-10s", "")
		for range scenarios {
			fmt.Fprintf(&b, "  %-24s", "domestic  foreign  p50")
		}
		b.WriteString("\n")
		for i := range results[scenarios[0].name] {
			fmt.Fprintf(&b, "%-10s", results[scenarios[0].name][i].label)
			for _, sc := range scenarios {
				r := results[sc.name][i]
				fmt.Fprintf(&b, "  %6.0f%%  %6.0f%%  %5.1fs  ", 100*r.ir.rate(), 100*r.ab.rate(), r.ir.p50().Seconds())
			}
			b.WriteString("\n")
		}
		t.Log(b.String())
	}
}
