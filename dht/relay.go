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
}

type relay struct {
	pairs  map[krpc.NodeID]*relayPair
	byAddr map[netip.AddrPort]*relayPair
}

const relayIdle = time.Minute

// maxPairsPerSource bounds the pairs, half-formed or complete, that have a
// member from one source: an IPv4 address or an IPv6 /64, which one host
// controls. Announce tokens are per IP, so without it one host could fill
// the table from many ports, or pair with itself to hold every active slot.
// It isn't 1 because subscribers behind one CGNAT IP share it.
const maxPairsPerSource = 4

func relaySource(ip netip.Addr) netip.Prefix {
	ip = ip.Unmap()
	if ip.Is4() {
		return netip.PrefixFrom(ip, 32)
	}
	p, _ := ip.Prefix(64)
	return p
}

func (p *relayPair) from(src netip.Prefix) bool {
	for i := range p.n {
		if src.Contains(p.peers[i].Addr().Unmap()) {
			return true
		}
	}
	return false
}

func (r *relay) pairsFrom(src netip.Prefix) int {
	c := 0
	for _, p := range r.pairs {
		if p.from(src) {
			c++
		}
	}
	return c
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
		if len(r.pairs) >= 4*n.cfg.MaxRelayPairs || r.pairsFrom(relaySource(from.Addr())) >= maxPairsPerSource {
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
	if src := relaySource(from.Addr()); !p.from(src) && r.pairsFrom(src) >= maxPairsPerSource {
		return // joining would give this source another pair
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
	to := p.peers[0]
	if from == to {
		to = p.peers[1]
	}
	n.sends = append(n.sends, Send{To: to, Data: append([]byte(nil), b...)})
}

func (n *Node) expireRelays(now time.Time) {
	for k, p := range n.rel.pairs {
		if now.Sub(p.active) >= relayIdle {
			for i := range p.n {
				delete(n.rel.byAddr, p.peers[i])
			}
			delete(n.rel.pairs, k)
		}
	}
}

// RelayPairs reports how many pairs this node is relaying for.
func (n *Node) RelayPairs() int { return n.activePairs() }
