package punch

import "net/netip"

type Strategy uint8

const (
	// Direct: both sides map independently; send to each other's
	// candidates (simultaneous open).
	Direct Strategy = iota
	// Spray: we map independently and the peer doesn't; spray its port
	// range from our one socket while the peer opens many sockets toward us.
	Spray
	// Open: the mirror of Spray; open many sockets toward the peer.
	Open
	// DoubleBirthday: both map dependently but their port ranges are
	// known; each side opens many sockets and sprays the other's range.
	// Works when both NATs filter by address rather than address and port.
	DoubleBirthday
	// Give up on a direct path; fall back to a relay.
	Relay
)

func (s Strategy) String() string {
	return [...]string{"direct", "spray", "open", "double-birthday", "relay"}[s]
}

// MaxExtraSockets is the most extra sockets a session opens (the open and
// birthday strategies), besides its own.
const MaxExtraSockets = openSockets

// Budgets.
const (
	openSockets        = 64
	openSocketsPredict = 8
	predictWindow      = 512
)

type portRange struct{ lo, hi uint16 }

func (r portRange) size() int { return int(r.hi) - int(r.lo) + 1 }

// Plan chooses our strategy. Unlike HyperDHT's table, which sprays the whole
// port space and refuses pairs where both sides map dependently, it narrows
// to predicted windows and inferred port blocks, which makes some of those
// pairs punchable.
func Plan(local, remote Profile, remoteCandidates []netip.AddrPort, doubleBirthday bool) (Strategy, portRange, int) {
	easy := func(p Profile) bool { return p.Mapping != MappingDependent }
	switch {
	case easy(local) && easy(remote):
		return Direct, portRange{}, 0
	case easy(local):
		return Spray, targetRange(remote, remoteCandidates), 0
	case easy(remote):
		return Open, portRange{}, socketsFor(local)
	case doubleBirthday && narrowed(remote) && narrowed(local):
		return DoubleBirthday, targetRange(remote, remoteCandidates), openSockets
	}
	return Relay, portRange{}, 0
}

func socketsFor(p Profile) int {
	if p.Allocation == AllocSequential {
		return openSocketsPredict
	}
	return openSockets
}

func narrowed(p Profile) bool {
	return p.Allocation == AllocSequential || (p.Allocation == AllocBlock && p.BlockHi > p.BlockLo)
}

// targetRange is where the peer's next mappings will land: just past its
// last observed port for a sequential allocator, inside its block for a
// block allocator, anywhere otherwise.
func targetRange(p Profile, cands []netip.AddrPort) portRange {
	switch p.Allocation {
	case AllocSequential:
		if last, ok := reflexivePort(cands); ok {
			step := max(int(p.Step), 1)
			// Where the allocator wraps to is unknown, so a window that
			// would run past the top of the port space narrows nothing.
			if hi := int(last) + step*predictWindow; hi <= 65535 {
				return portRange{last + 1, uint16(hi)}
			}
		}
	case AllocBlock:
		if p.BlockHi > p.BlockLo {
			return portRange{p.BlockLo, p.BlockHi}
		}
	}
	return portRange{1024, 65535}
}

// reflexivePort returns the first public candidate's port, which offers list
// first.
func reflexivePort(cands []netip.AddrPort) (uint16, bool) {
	for _, c := range cands {
		if a := c.Addr(); a.IsGlobalUnicast() && !a.IsPrivate() {
			return c.Port(), true
		}
	}
	return 0, false
}
