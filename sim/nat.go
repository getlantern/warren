package sim

import (
	"math/rand/v2"
	"net/netip"
	"time"
)

// NAT models a UDP NAT's three independent behaviors (RFC 4787): how it maps
// internal endpoints to public ports, how it allocates those ports, and how
// it filters inbound packets.
type NAT struct {
	cfg    NATConfig
	rng    *rand.Rand
	byKey  map[mapKey]*natMapping
	byPort map[uint16]*natMapping
	last   uint16
}

type MappingBehavior int

const (
	EndpointIndependentMapping MappingBehavior = iota
	EndpointDependentMapping
)

type FilteringBehavior int

const (
	EndpointIndependentFiltering FilteringBehavior = iota
	AddressDependentFiltering
	AddressPortDependentFiltering
)

type Allocation int

const (
	PortPreserving Allocation = iota
	SequentialPorts
	BlockRandomPorts
	RandomPorts
)

type NATConfig struct {
	Public    netip.Addr
	Mapping   MappingBehavior
	Filtering FilteringBehavior
	Alloc     Allocation
	// Step and Jitter shape sequential allocation: each new mapping advances
	// by Step plus up to Jitter×Step for other subscribers' mappings.
	Step, Jitter     int
	BlockLo, BlockHi uint16
	Timeout          time.Duration
}

type mapKey struct {
	local netip.AddrPort
	dst   netip.AddrPort // zero for endpoint-independent mapping
}

type natMapping struct {
	local  netip.AddrPort
	port   uint16
	used   time.Time
	sentIP map[netip.Addr]bool
	sentTo map[netip.AddrPort]bool
	key    mapKey
}

func NewNAT(cfg NATConfig, rng *rand.Rand) *NAT {
	if cfg.Timeout == 0 {
		cfg.Timeout = 2 * time.Minute
	}
	if cfg.Step == 0 {
		cfg.Step = 1
	}
	if cfg.BlockHi == 0 {
		cfg.BlockLo, cfg.BlockHi = 1024, 65535
	}
	return &NAT{cfg: cfg, rng: rng, byKey: map[mapKey]*natMapping{}, byPort: map[uint16]*natMapping{}, last: cfg.BlockLo + uint16(rng.IntN(64))}
}

func (n *NAT) Public() netip.Addr { return n.cfg.Public }

// Outbound translates a packet leaving local for dst, creating a mapping if
// needed, and returns the public source address. It reports false, and the
// packet is dropped, when the NAT has no free port left to allocate.
func (n *NAT) Outbound(local, dst netip.AddrPort, now time.Time) (netip.AddrPort, bool) {
	k := mapKey{local: local}
	if n.cfg.Mapping == EndpointDependentMapping {
		k.dst = dst
	}
	m := n.byKey[k]
	if m != nil && now.Sub(m.used) >= n.cfg.Timeout {
		n.drop(m)
		m = nil
	}
	if m == nil {
		port, ok := n.allocate(local.Port(), now)
		if !ok {
			return netip.AddrPort{}, false
		}
		m = &natMapping{local: local, port: port, key: k, sentIP: map[netip.Addr]bool{}, sentTo: map[netip.AddrPort]bool{}}
		n.byKey[k] = m
		n.byPort[m.port] = m
	}
	m.used = now
	m.sentIP[dst.Addr()] = true
	m.sentTo[dst] = true
	return netip.AddrPortFrom(n.cfg.Public, m.port), true
}

// Mappings is the number of live mappings, for checking port-quota use.
func (n *NAT) Mappings() int { return len(n.byPort) }

// Inbound filters a packet from 'from' arriving at public port, returning
// the internal destination if it is admitted.
func (n *NAT) Inbound(from netip.AddrPort, port uint16, now time.Time) (netip.AddrPort, bool) {
	m := n.byPort[port]
	if m == nil || now.Sub(m.used) >= n.cfg.Timeout {
		return netip.AddrPort{}, false
	}
	switch n.cfg.Filtering {
	case AddressDependentFiltering:
		if !m.sentIP[from.Addr()] {
			return netip.AddrPort{}, false
		}
	case AddressPortDependentFiltering:
		if !m.sentTo[from] {
			return netip.AddrPort{}, false
		}
	}
	return m.local, true
}

func (n *NAT) drop(m *natMapping) {
	delete(n.byKey, m.key)
	delete(n.byPort, m.port)
}

func (n *NAT) free(p uint16) bool { return p >= 1024 && n.byPort[p] == nil }

// allocate picks a public port, failing when the range is exhausted as a
// real NAT does when a subscriber hits its port quota.
func (n *NAT) allocate(localPort uint16, now time.Time) (uint16, bool) {
	lo, hi := int(n.cfg.BlockLo), int(n.cfg.BlockHi)
	size := hi - lo + 1
	if len(n.byPort) >= size {
		for _, m := range n.byPort {
			if now.Sub(m.used) >= n.cfg.Timeout {
				n.drop(m)
			}
		}
		if len(n.byPort) >= size {
			return 0, false
		}
	}
	random := func() (uint16, bool) {
		for {
			if p := uint16(lo + n.rng.IntN(size)); n.free(p) {
				return p, true
			}
		}
	}
	switch n.cfg.Alloc {
	case PortPreserving:
		if n.free(localPort) {
			return localPort, true
		}
		return random()
	case SequentialPorts:
		p := int(n.last)
		for {
			p += n.cfg.Step * (1 + n.rng.IntN(n.cfg.Jitter+1))
			if p > hi {
				p = lo + p%size
			}
			if n.free(uint16(p)) {
				n.last = uint16(p)
				return n.last, true
			}
		}
	default:
		return random()
	}
}
