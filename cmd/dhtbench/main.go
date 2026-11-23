// Command dhtbench measures warren's DHT on live Mainline next to
// libtorrent's, on the same host at the same time: how fast each fills its
// routing table, how long an immutable get takes to find an item a third
// node stored (a hit, what finding a provider's record costs), and how long
// one to a random target takes (a miss, a full walk to its closest nodes).
//
//	go run ./cmd/dhtbench -python /path/to/venv/bin/python -lookups 200
//
// Without -python only warren runs; -no-miss skips the miss phase, and
// -inflight, -alpha, -short and -timeout tune the measured warren node.
// Both nodes are full (not read-only) nodes, bootstrapped from the public
// routers.
package main

import (
	"bufio"
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/getlantern/warren/dht"
	"github.com/getlantern/warren/driver"
	"github.com/getlantern/warren/krpc"
	"github.com/getlantern/warren/natprobe"
)

type lookup struct {
	ms        float64 // total; -1 on error or timeout
	first     float64
	settled   float64
	queried   int
	failures  int
	responded bool
	found     bool
}

type tableSample struct {
	at    int
	nodes int
}

func main() {
	python := flag.String("python", "", "interpreter with libtorrent installed (empty: warren only)")
	script := flag.String("script", "tools/dhtbench/lt_bench.py", "libtorrent measurement script")
	lookups := flag.Int("lookups", 100, "gets per phase: hits (items warren stored) and misses (random targets)")
	concurrency := flag.Int("concurrency", 4, "gets in flight at once")
	warmup := flag.Duration("warmup", 60*time.Second, "routing-table warm-up before the gets")
	noMiss := flag.Bool("no-miss", false, "skip the miss phase")
	flag.IntVar(&tune.MaxInflight, "inflight", 0, "warren: most queries in flight per lookup (0: default)")
	flag.IntVar(&tune.Alpha, "alpha", 0, "warren: active queries per lookup (0: default)")
	flag.DurationVar(&tune.ShortTimeout, "short", 0, "warren: a query stops counting as active after this (0: default)")
	flag.DurationVar(&tune.QueryTimeout, "timeout", 0, "warren: a query fails after this (0: default)")
	flag.Parse()
	if *concurrency < 1 || *lookups < 1 {
		log.Fatal("-concurrency and -lookups must be at least 1")
	}

	seeds := resolve(natprobe.DefaultBootstrap)
	if len(seeds) == 0 {
		log.Fatal("no bootstrap router resolved")
	}
	// Learn our address before starting either measured node, so both warm
	// up for the same time.
	ip := externalIP(seeds)
	measured := tune
	measured.MaxLookups = max(measured.MaxLookups, *concurrency+16) // gets never hit ErrBusy
	w := startWarren(seeds, ip, measured)
	var lt *libtorrent
	if *python != "" {
		lt = startLibtorrent(*python, *script, *warmup, *concurrency)
	}
	defer func() { _ = w.n.Close() }()
	wTable := w.warm(*warmup)
	var ltTable []tableSample
	if lt != nil {
		ltTable = lt.ready()
	}

	// Items to find, stored by a separate node on the K nodes closest to
	// each, so neither measured node has walked toward them before.
	storer := startWarren(seeds, ip, dht.Config{})
	storer.warm(*warmup / 2)
	hits := storer.store(*lookups, *concurrency)
	_ = storer.n.Close()
	misses := make([]krpc.NodeID, *lookups)
	for i := range misses {
		_, _ = crand.Read(misses[i][:])
	}

	type phase struct {
		name    string
		targets []krpc.NodeID
		w, lt   []lookup
	}
	phases := []*phase{{name: "hit", targets: hits}, {name: "miss", targets: misses}}
	if *noMiss {
		phases = phases[:1]
	}
	for _, ph := range phases {
		var wg sync.WaitGroup
		if lt != nil {
			wg.Go(func() { ph.lt = lt.batch(ph.name, ph.targets) })
		}
		ph.w = w.gets(ph.targets, *concurrency)
		wg.Wait()
	}
	if lt != nil {
		lt.quit()
	}

	fmt.Printf("\nrouting table size during warm-up (nodes)\n%8s %10s %16s\n", "at", "warren", "libtorrent (at)")
	for i, s := range wTable {
		l := "-"
		if i < len(ltTable) {
			l = fmt.Sprintf("%d (%ds)", ltTable[i].nodes, ltTable[i].at)
		}
		fmt.Printf("%7ds %10d %16s\n", s.at, s.nodes, l)
	}
	total := func(l lookup) (float64, bool) { return l.ms, true }
	for _, ph := range phases {
		fmt.Printf("\nimmutable get, %s: %d targets, %d in flight\n", ph.name, len(ph.targets), *concurrency)
		tot := total
		if ph.name == "hit" {
			// Time to the value: a hit that came back empty is reported as
			// not found below, not as a latency.
			tot = func(l lookup) (float64, bool) { return l.ms, l.found }
		}
		report("warren total", ph.w, tot)
		// A lookup no node answered has no first reply or settling time.
		report("warren first reply", ph.w, func(l lookup) (float64, bool) { return l.first, l.responded })
		report("warren K settled", ph.w, func(l lookup) (float64, bool) { return l.settled, l.responded })
		if lt != nil {
			report("libtorrent total", ph.lt, tot)
		}
		var q, f, n, found int
		for _, l := range ph.w {
			if l.ms >= 0 {
				q, f, n = q+l.queried, f+l.failures, n+1
			}
			if l.found {
				found++
			}
		}
		if n > 0 {
			fmt.Printf("warren: found %d/%d, %.1f queries and %.1f failures per lookup\n", found, len(ph.w), float64(q)/float64(n), float64(f)/float64(n))
		}
		if lt != nil {
			found = 0
			for _, l := range ph.lt {
				if l.found {
					found++
				}
			}
			fmt.Printf("libtorrent: found %d/%d\n", found, len(ph.lt))
		}
	}
}

func resolve(hosts []string) []netip.AddrPort {
	var out []netip.AddrPort
	for _, h := range hosts {
		a, err := net.ResolveUDPAddr("udp4", h)
		if err != nil {
			log.Printf("resolve %s: %v", h, err)
			continue
		}
		out = append(out, a.AddrPort())
	}
	return out
}

func randomID() krpc.NodeID {
	var id krpc.NodeID
	_, _ = crand.Read(id[:])
	return id
}

// externalIP learns our public address from the routers' BEP 42 reflections,
// for a secure node ID that live nodes enforcing BEP 42 accept.
func externalIP(seeds []netip.AddrPort) netip.Addr {
	n, err := driver.Listen("0.0.0.0:0", dht.Config{ID: randomID()})
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = n.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, _ = n.Bootstrap(ctx, seeds)
	// The bootstrap may have used up ctx; read what it collected regardless.
	ictx, icancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer icancel()
	var ip netip.Addr
	_ = n.Inspect(ictx, func(d *dht.Node) {
		for _, r := range d.Reflections() {
			if a := r.Mapped.Addr().Unmap(); a.IsGlobalUnicast() && !a.IsPrivate() {
				ip = a
			}
		}
	})
	return ip
}

// tune holds the measured warren node's lookup settings from the flags
// (zero: default); the storer node always uses the defaults.
var tune dht.Config

type warren struct{ n *driver.Node }

func startWarren(seeds []netip.AddrPort, ip netip.Addr, cfg dht.Config) *warren {
	id := randomID()
	if ip.IsValid() {
		id = krpc.SecureID(ip, id)
	} else {
		log.Print("warren: no external address learned; using a random ID")
	}
	cfg.ID = id
	n, err := driver.Listen("0.0.0.0:0", cfg)
	if err != nil {
		log.Fatal(err)
	}
	go func() { _, _ = n.Bootstrap(context.Background(), seeds) }()
	return &warren{n}
}

func (w *warren) warm(warmup time.Duration) []tableSample {
	start := time.Now()
	size := func() int {
		var s int
		_ = w.n.Inspect(context.Background(), func(d *dht.Node) { s = len(d.Contacts(1 << 16)) })
		return s
	}
	var table []tableSample
	sample := func() {
		table = append(table, tableSample{int(time.Since(start).Round(time.Second).Seconds()), size()})
	}
	for next := time.Duration(0); next < warmup; next += 5 * time.Second {
		time.Sleep(time.Until(start.Add(next)))
		sample()
	}
	time.Sleep(time.Until(start.Add(warmup)))
	sample()
	return table
}

// store puts n random items and returns the targets of those stored on at
// least one node.
func (w *warren) store(n, concurrency int) []krpc.NodeID {
	var mu sync.Mutex
	var out []krpc.NodeID
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for range n {
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
			var b [20]byte
			_, _ = crand.Read(b[:])
			v := append([]byte("20:"), b[:]...)
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			t, done, err := w.n.Put(ctx, v)
			if err == nil && done.Stored > 0 {
				mu.Lock()
				out = append(out, t)
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	return out
}

func (w *warren) gets(targets []krpc.NodeID, concurrency int) []lookup {
	out := make([]lookup, len(targets))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, t := range targets {
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			g, err := w.n.GetItem(ctx, t)
			if err != nil {
				out[i] = lookup{ms: -1}
				return
			}
			ms := func(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
			out[i] = lookup{ms: ms(g.Timing.Total), first: ms(g.Timing.First), settled: ms(g.Timing.Settled),
				queried: g.Queried, failures: g.Failures, responded: g.Timing.First > 0, found: g.Value != nil}
		})
	}
	wg.Wait()
	return out
}

type ltMsg struct {
	T     string  `json:"t"`
	At    int     `json:"at"`
	Nodes int     `json:"nodes"`
	Ms    float64 `json:"ms"`
	Found bool    `json:"found"`
}

type libtorrent struct {
	cmd   *exec.Cmd
	in    io.WriteCloser
	lines chan ltMsg
}

func startLibtorrent(python, script string, warmup time.Duration, concurrency int) *libtorrent {
	cmd := exec.Command(python, "-I", script, strconv.Itoa(int(warmup.Seconds())), strconv.Itoa(concurrency))
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		log.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		log.Fatalf("libtorrent: %v", err)
	}
	l := &libtorrent{cmd: cmd, in: in, lines: make(chan ltMsg, 64)}
	go func() {
		defer close(l.lines)
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			var m ltMsg
			if json.Unmarshal(sc.Bytes(), &m) == nil {
				l.lines <- m
			}
		}
	}()
	return l
}

// next returns the helper's next message, giving up (and killing it) if it
// goes silent: libtorrent's own gets time out at 60 s.
func (l *libtorrent) next(phase string) (ltMsg, bool) {
	select {
	case m, ok := <-l.lines:
		return m, ok
	case <-time.After(5 * time.Minute):
		_ = l.cmd.Process.Kill()
		log.Fatalf("libtorrent stalled during %s", phase)
		return ltMsg{}, false
	}
}

// ready waits out libtorrent's warm-up and returns its table samples.
func (l *libtorrent) ready() []tableSample {
	var table []tableSample
	for {
		m, ok := l.next("warm-up")
		if !ok {
			break
		}
		switch m.T {
		case "table":
			table = append(table, tableSample{m.At, m.Nodes})
		case "ready":
			return table
		}
	}
	log.Fatal("libtorrent exited during warm-up")
	return nil
}

func (l *libtorrent) batch(label string, targets []krpc.NodeID) []lookup {
	hexes := make([]string, len(targets))
	for i, t := range targets {
		hexes[i] = hex.EncodeToString(t[:])
	}
	cmd, _ := json.Marshal(map[string]any{"label": label, "targets": hexes})
	if _, err := l.in.Write(append(cmd, '\n')); err != nil {
		log.Fatalf("libtorrent: %v", err)
	}
	var out []lookup
	for {
		m, ok := l.next(label)
		if !ok {
			break
		}
		switch m.T {
		case "lookup":
			out = append(out, lookup{ms: m.Ms, found: m.Found})
		case "batch":
			return out
		}
	}
	log.Fatal("libtorrent exited mid-batch")
	return nil
}

func (l *libtorrent) quit() {
	_, _ = l.in.Write([]byte(`{"quit": true}` + "\n"))
	_ = l.in.Close()
	_ = l.cmd.Wait()
}

func report(name string, ls []lookup, f func(lookup) (float64, bool)) {
	var v []float64
	failed := 0
	for _, l := range ls {
		if l.ms < 0 {
			failed++
			continue
		}
		if x, ok := f(l); ok {
			v = append(v, x)
		}
	}
	if len(v) == 0 {
		fmt.Printf("%-20s no results (%d failed)\n", name, failed)
		return
	}
	slices.Sort(v)
	p := func(q float64) float64 { return v[min(int(q*float64(len(v))), len(v)-1)] }
	fmt.Printf("%-20s p50 %7.0fms  p90 %7.0fms  p99 %7.0fms  max %7.0fms  (%d ok, %d failed)\n",
		name, p(0.5), p(0.9), p(0.99), v[len(v)-1], len(v), failed)
}
