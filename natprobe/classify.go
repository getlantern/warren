// Package natprobe characterizes the local NAT using public Mainline DHT nodes
// as reflectors: BEP 42 responses carry an "ip" field with the address the
// responder saw, so every reply reveals one NAT mapping. On the wire the probe
// is ordinary DHT traffic.
package natprobe

import (
	"math"
	"net/netip"
	"slices"
	"time"
)

type Mapping string

const (
	MappingUnknown             Mapping = "unknown"
	MappingEndpointIndependent Mapping = "endpoint-independent"
	MappingEndpointDependent   Mapping = "endpoint-dependent"
)

const (
	DefaultBirthdaySockets = 64
	DefaultBirthdayProbes  = 256

	minMappingSamples    = 3
	minAllocationSamples = 6
	// Some reflectors misreport; tolerate a minority of outliers.
	modalShareForIndependent = 0.8
	maxSequentialStep        = 32
	sequentialShare          = 0.6
	minBlock, maxBlock       = 256, 8192
	portSpace                = 65536 - 1024
)

type Allocation string

const (
	AllocationNotApplicable Allocation = "n/a"
	AllocationUnknown       Allocation = "unknown"
	AllocationSequential    Allocation = "sequential"
	AllocationBlock         Allocation = "block"
	AllocationRandom        Allocation = "random"
)

type Observation struct {
	Socket int `json:"socket"`
	// Order is the position of this mapping's creation among the probe's
	// serial sends, counting sends that got no reply; -1 for concurrent
	// discovery queries whose creation order is unknown.
	Order   int            `json:"order"`
	Local   netip.AddrPort `json:"local"`
	Dest    netip.AddrPort `json:"dest"`
	Mapped  netip.AddrPort `json:"mapped"`
	RTT     time.Duration  `json:"rtt_ns"`
	Version string         `json:"version,omitempty"`
}

type Analysis struct {
	Mapping        Mapping      `json:"mapping"`
	PortPreserving bool         `json:"port_preserving"`
	ExternalIPs    []netip.Addr `json:"external_ips"`
	Allocation     Allocation   `json:"allocation"`
	// Step is the per-mapping port increment of a sequential allocator.
	Step float64 `json:"step,omitempty"`
	// BlockLo/BlockHi bound the smallest aligned power-of-two port block
	// containing every observed mapping.
	BlockLo uint16 `json:"block_lo,omitempty"`
	BlockHi uint16 `json:"block_hi,omitempty"`
	Samples int    `json:"samples"`
	// FullRangeOdds and NarrowedOdds give birthday-punch success for the
	// default budget, sprayed across all ports versus the inferred block.
	FullRangeOdds float64 `json:"full_range_odds"`
	NarrowedOdds  float64 `json:"narrowed_odds,omitempty"`
	Strategy      string  `json:"strategy"`
}

// BirthdayOdds is the chance that at least one of probes uniformly random
// guesses lands on one of sockets open ports in a space of size space.
func BirthdayOdds(sockets, probes, space int) float64 {
	if space <= 0 || sockets <= 0 || probes <= 0 {
		return 0
	}
	if sockets >= space {
		return 1
	}
	return 1 - math.Pow(1-float64(sockets)/float64(space), float64(probes))
}

// Analyze classifies the NAT from observations. local is the probe's main
// socket address, used to detect port preservation.
func Analyze(local netip.AddrPort, obs []Observation) Analysis {
	a := Analysis{
		Mapping:       MappingUnknown,
		Allocation:    AllocationUnknown,
		FullRangeOdds: BirthdayOdds(DefaultBirthdaySockets, DefaultBirthdayProbes, portSpace),
	}
	seenIP := map[netip.Addr]bool{}
	for _, o := range obs {
		if ip := o.Mapped.Addr(); !seenIP[ip] {
			seenIP[ip] = true
			a.ExternalIPs = append(a.ExternalIPs, ip)
		}
	}

	main := filter(obs, func(o Observation) bool { return o.Socket == 0 })
	a.Samples = len(main)
	if len(main) < minMappingSamples {
		a.Strategy = "insufficient reflector replies"
		return a
	}
	port, share := modalPort(main)
	if share >= modalShareForIndependent {
		a.Mapping = MappingEndpointIndependent
		a.Allocation = AllocationNotApplicable
		a.PortPreserving = port == local.Port()
		a.Strategy = "direct: advertise the reflexive address and simultaneous-open"
		return a
	}
	a.Mapping = MappingEndpointDependent

	// Every serial mapping from any socket shares the NAT's allocator, so the
	// sequence spans sockets.
	serial := filter(obs, func(o Observation) bool { return o.Order >= 0 })
	slices.SortFunc(serial, func(x, y Observation) int { return x.Order - y.Order })
	if len(serial) < minAllocationSamples {
		a.Strategy = "endpoint-dependent; too few serial samples to model allocation"
		return a
	}
	a.PortPreserving = serial[0].Mapped.Port() == serial[0].Local.Port()

	if step, ok := sequentialStep(serial); ok {
		a.Allocation = AllocationSequential
		a.Step = step
		a.NarrowedOdds = 1
		a.Strategy = "predict: next port ≈ last observed + step × mappings since; spray a small window around it"
		return a
	}
	if lo, hi, ok := alignedBlock(main); ok {
		a.Allocation = AllocationBlock
		a.BlockLo, a.BlockHi = lo, hi
		a.NarrowedOdds = BirthdayOdds(DefaultBirthdaySockets, DefaultBirthdayProbes, int(hi-lo)+1)
		a.Strategy = "birthday within the inferred port block"
		return a
	}
	a.Allocation = AllocationRandom
	a.Strategy = "birthday across the full port range; needs an endpoint-independent peer"
	return a
}

func filter(obs []Observation, keep func(Observation) bool) []Observation {
	var out []Observation
	for _, o := range obs {
		if keep(o) {
			out = append(out, o)
		}
	}
	return out
}

func modalPort(obs []Observation) (uint16, float64) {
	counts := map[uint16]int{}
	best, bestN := uint16(0), 0
	for _, o := range obs {
		p := o.Mapped.Port()
		counts[p]++
		if counts[p] > bestN {
			best, bestN = p, counts[p]
		}
	}
	return best, float64(bestN) / float64(len(obs))
}

// sequentialStep normalizes each port delta by the number of mappings created
// between the two samples, since sends that got no reply still consumed a
// port. Other subscribers sharing a CGNAT allocator add positive jitter, so
// small forward steps qualify, not just a constant one.
func sequentialStep(serial []Observation) (float64, bool) {
	var steps []float64
	for i := 1; i < len(serial); i++ {
		gap := serial[i].Order - serial[i-1].Order
		if gap <= 0 {
			continue
		}
		d := int(serial[i].Mapped.Port()) - int(serial[i-1].Mapped.Port())
		steps = append(steps, float64(d)/float64(gap))
	}
	if len(steps) == 0 {
		return 0, false
	}
	small := 0
	for _, s := range steps {
		if s > 0 && s <= maxSequentialStep {
			small++
		}
	}
	if float64(small)/float64(len(steps)) < sequentialShare {
		return 0, false
	}
	slices.Sort(steps)
	return steps[len(steps)/2], true
}

// alignedBlock finds the smallest aligned power-of-two block holding every
// mapped port. With six or more samples, uniformly random ports land in one
// 8192-port block with probability below (1/8)^5, so a hit is strong evidence
// of port-block allocation.
func alignedBlock(obs []Observation) (lo, hi uint16, ok bool) {
	if len(obs) < minAllocationSamples {
		return 0, 0, false
	}
	minP, maxP := obs[0].Mapped.Port(), obs[0].Mapped.Port()
	for _, o := range obs[1:] {
		minP = min(minP, o.Mapped.Port())
		maxP = max(maxP, o.Mapped.Port())
	}
	for size := minBlock; size <= maxBlock; size *= 2 {
		if int(minP)/size == int(maxP)/size {
			base := int(minP) / size * size
			return uint16(base), uint16(base + size - 1), true
		}
	}
	return 0, 0, false
}
