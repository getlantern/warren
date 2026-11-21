// Command natprobe characterizes the local NAT using Mainline DHT nodes as
// reflectors.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"slices"
	"time"

	"github.com/getlantern/warren/natprobe"
)

func main() {
	reflectors := flag.Int("reflectors", 16, "fresh reflectors to ping serially")
	extra := flag.Int("extra-sockets", 4, "additional local sockets to extend the allocation sequence")
	listen := flag.Duration("listen", 0, "run as a full node this long afterwards to test unsolicited inbound")
	asJSON := flag.Bool("json", false, "print the full report as JSON")
	mappingTimeout := flag.Bool("mapping-timeout", false, "also estimate the NAT's idle UDP mapping timeout (takes ~3 minutes)")
	verbose := flag.Bool("v", false, "log progress")
	flag.Parse()

	cfg := natprobe.Config{Reflectors: *reflectors, ExtraSockets: *extra, Listen: *listen}
	if *verbose {
		cfg.Logf = log.Printf
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute+*listen)
	defer cancel()
	rep, err := natprobe.Run(ctx, cfg)
	if err != nil {
		log.Fatal(err)
	}
	if *mappingTimeout && len(rep.Reflectors) > 0 {
		tr, err := natprobe.MappingTimeout(ctx, rep.Reflectors[0], nil)
		if err != nil {
			log.Printf("mapping timeout: %v", err)
		}
		defer printTimeout(tr)
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			log.Fatal(err)
		}
		return
	}
	printReport(rep)
}

func printReport(r *natprobe.Report) {
	fmt.Printf("local           %s\n", r.Local)
	fmt.Printf("queries         %d sent, %d answered, %d without BEP 42 ip (%s)\n",
		r.Queries, r.Responders, r.NoIPField, r.Duration.Round(time.Millisecond))
	fmt.Printf("external IPs    %v\n", r.ExternalIPs)
	fmt.Printf("mapping         %s (samples %d, port preserving %v)\n", r.Mapping, r.Samples, r.PortPreserving)
	fmt.Printf("allocation      %s", r.Allocation)
	switch r.Allocation {
	case natprobe.AllocationSequential:
		fmt.Printf(" (step %.1f)", r.Step)
	case natprobe.AllocationBlock:
		fmt.Printf(" [%d–%d]", r.BlockLo, r.BlockHi)
	}
	fmt.Println()
	fmt.Printf("birthday odds   %.1f%% full range", 100*r.FullRangeOdds)
	if r.NarrowedOdds > 0 {
		fmt.Printf(", %.1f%% narrowed", 100*r.NarrowedOdds)
	}
	fmt.Printf("  (%d sockets × %d probes)\n", natprobe.DefaultBirthdaySockets, natprobe.DefaultBirthdayProbes)
	if r.Unsolicited > 0 {
		fmt.Printf("unsolicited     %d queries from never-contacted addresses: inbound filtering is endpoint-independent\n", r.Unsolicited)
	}
	fmt.Printf("strategy        %s\n", r.Strategy)

	fmt.Println("\nserial mappings (order: local → mapped via reflector)")
	obs := slices.Clone(r.Observations)
	slices.SortFunc(obs, func(a, b natprobe.Observation) int { return a.Order - b.Order })
	for _, o := range obs {
		if o.Order < 0 {
			continue
		}
		fmt.Printf("  %3d  :%-5d → %-21s via %-21s %4dms  %s\n",
			o.Order, o.Local.Port(), o.Mapped, o.Dest, o.RTT.Milliseconds(), o.Version)
	}
	fmt.Println("\nreflector versions")
	type kv struct {
		k string
		n int
	}
	var vs []kv
	for k, n := range r.Versions {
		vs = append(vs, kv{k, n})
	}
	slices.SortFunc(vs, func(a, b kv) int { return b.n - a.n })
	for _, v := range vs {
		fmt.Printf("  %4d  %s\n", v.n, v.k)
	}
}

func printTimeout(r natprobe.TimeoutResult) {
	fmt.Println("\nidle mapping timeout")
	for _, g := range r.Gaps {
		state := "no reply"
		if g.OK {
			state = "kept"
			if g.Changed {
				state = "expired (new port)"
			}
		}
		fmt.Printf("  %6s idle  %s\n", g.Gap, state)
	}
	switch {
	case r.Detectable:
		fmt.Printf("  mapping expires between %s and %s\n", r.AliveAt, r.Expired)
	default:
		fmt.Println("  undetectable here: the mapping outlived every gap, or the NAT reuses its port")
	}
	fmt.Printf("  suggested keepalive: %s\n", natprobe.KeepaliveFor(r, 25*time.Second))
}
