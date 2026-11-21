package dht

import (
	"net/netip"
	"time"

	"github.com/getlantern/warren/krpc"
)

// Relaying for peers that cannot punch a direct path. Two peers announce the
// same secret-derived info-hash to this node with ordinary announce_peer
// queries; once both have, it forwards non-KRPC datagrams between them
// blindly (the payload is end-to-end encrypted). To an observer this is two
// peers announcing a torrent to a DHT node and then talking uTP with it,
// which libtorrent does on the same socket.

type relayPair struct {
	peers   [2]netip.AddrPort
	n       int
	created time.Time
	active  time.Time
	tokens  float64 // byte budget, refilled at RelayRate
	used    bool    // has forwarded a datagram
}

type relay struct {
	pairs  map[krpc.NodeID]*relayPair
	byAddr map[netip.AddrPort]*relayPair
}

const (
	relayIdle = time.Minute
	// relayUnusedIdle expires pairs that never forwarded anything sooner:
	// every session binds a relay alongside punching, and most then
	// connect directly and never use it.
	relayUnusedIdle = 20 * time.Second
)

// Per-source limits. Announce tokens are per IP, so without them one host
// could fill the table from many ports, or pair with itself to hold every
// active slot. A source is an IPv4 address, or an IPv6 /64 and, more
// loosely, the /48 a single customer is often delegated. A source may hold
// a few half-formed pairs, a single self-pair (both members from it: only
// subscribers sharing one CGNAT IP need that), and complete pairs with
// other sources up to half of MaxRelayPairs, since a busy client binds a
// relay on every dial and should keep its fallback. Even a dual-stack host
// pairing its two families with each other holds at most half the slots.
type sourceLimit struct{ bits, pending int }

var (
	v4Limits = []sourceLimit{{32, 4}}
	v6Limits = []sourceLimit{{64, 4}, {48, 8}}
)

const maxSelfPairs = 1

// relayNorm drops the IPv4-mapped form and any zone: Prefix.Contains never
// matches a zoned address, so a link-local sender with a zone would
// otherwise escape the per-source count.
func relayNorm(ip netip.Addr) netip.Addr { return ip.Unmap().WithZone("") }

func (p *relayPair) members(src netip.Prefix) int {
	c := 0
	for i := range p.n {
		if src.Contains(relayNorm(p.peers[i].Addr())) {
			c++
		}
	}
	return c
}

// admits reports whether from's source may take on p: a new half-formed
// pair when p is nil, otherwise completing p with other as the second
// member. completeCap bounds its complete pairs.
func (r *relay) admits(from, other netip.AddrPort, p *relayPair, completeCap int) bool {
	ip := relayNorm(from.Addr())
	limits := v4Limits
	if !ip.Is4() {
		limits = v6Limits
	}
	for _, l := range limits {
		src, _ := ip.Prefix(l.bits)
		pending, complete, self := 0, 0, 0
		for _, q := range r.pairs {
			m := q.members(src)
			if q == p || m == 0 {
				continue
			}
			switch {
			case q.n < 2:
				pending++
			case m == 2:
				self++
				complete++
			default:
				complete++
			}
		}
		if p == nil {
			if pending >= l.pending {
				return false
			}
			continue
		}
		if complete >= completeCap {
			return false
		}
		if src.Contains(relayNorm(other.Addr())) && self >= maxSelfPairs {
			return false
		}
	}
	return true
}

func (n *Node) relaying() bool { return !n.cfg.ReadOnly && !n.cfg.DisableRelay }

// relayAnnounce records an announcer for infoHash, pairing the second
// distinct address with the first.
func (n *Node) relayAnnounce(now time.Time, from netip.AddrPort, infoHash krpc.NodeID) {
	if !n.relaying() {
		return
	}
	r := &n.rel
	if r.pairs == nil {
		r.pairs, r.byAddr = map[krpc.NodeID]*relayPair{}, map[netip.AddrPort]*relayPair{}
	}
	p := r.pairs[infoHash]
	if bound := r.byAddr[from]; bound != nil && bound != p {
		// An address relays one pair; refuse before allocating, or one
		// source could fill the table with empty pairs under fresh
		// info-hashes.
		return
	}
	if p == nil {
		if len(r.pairs) >= 4*n.cfg.MaxRelayPairs || !r.admits(from, netip.AddrPort{}, nil, 0) {
			return
		}
		p = &relayPair{created: now, active: now, tokens: float64(n.cfg.RelayRate)}
		r.pairs[infoHash] = p
	}
	for i := range p.n {
		if p.peers[i] == from {
			p.active = now
			return
		}
	}
	if p.n == 2 {
		return // pairs are fixed once formed
	}
	if p.n == 1 && n.activePairs() >= n.cfg.MaxRelayPairs {
		return
	}
	completeCap := max(n.cfg.MaxRelayPairs/2, 1)
	if p.n == 1 && (!r.admits(from, p.peers[0], p, completeCap) || !r.admits(p.peers[0], from, p, completeCap)) {
		return // a complete pair counts against both members' sources
	}
	p.peers[p.n] = from
	p.n++
	p.active = now
	r.byAddr[from] = p
}

func (n *Node) activePairs() int {
	c := 0
	for _, p := range n.rel.pairs {
		if p.n == 2 {
			c++
		}
	}
	return c
}

// relayForward passes a non-KRPC datagram from one member of a pair to the
// other, within the pair's byte budget.
func (n *Node) relayForward(now time.Time, from netip.AddrPort, b []byte) {
	p := n.rel.byAddr[from]
	if p == nil || p.n != 2 {
		return
	}
	rate := float64(n.cfg.RelayRate)
	p.tokens = min(rate, p.tokens+rate*now.Sub(p.active).Seconds())
	p.active = now
	if p.tokens < float64(len(b)) {
		return // over budget: drop, and the end-to-end congestion control backs off
	}
	p.tokens -= float64(len(b))
	p.used = true
	to := p.peers[0]
	if from == to {
		to = p.peers[1]
	}
	n.sends = append(n.sends, Send{To: to, Data: append([]byte(nil), b...)})
}

func (n *Node) expireRelays(now time.Time) {
	for k, p := range n.rel.pairs {
		if idle := now.Sub(p.active); idle >= relayIdle || !p.used && idle >= relayUnusedIdle {
			for i := range p.n {
				delete(n.rel.byAddr, p.peers[i])
			}
			delete(n.rel.pairs, k)
		}
	}
}

// RelayPairs reports how many pairs this node is relaying for.
func (n *Node) RelayPairs() int { return n.activePairs() }
