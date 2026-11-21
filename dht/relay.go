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

// Admission. A router can't tell one host from many subscribers behind a
// shared address, so per-source caps that bite an attacker bite CGNAT users,
// relay-only listeners and carrier IPv6 pools just as hard. The limits are
// therefore loose, and target what one address can do cheaply:
//
//   - An address relays one pair, checked before allocating.
//   - A source (an IPv4 address or IPv6 /64) holds at most
//     maxPendingPerSource half-formed pairs, and when the table is full the
//     oldest half-formed pair is evicted rather than new ones refused, so a
//     flood of announces churns the table instead of locking it.
//   - A source pairs with itself at most maxSelfPairs times; only
//     subscribers sharing one CGNAT IP need that at all.
//
// Holding active slots with pairs between two different sources is not
// limited per source: that is the open-relay problem every volunteer relay
// has, bounded by MaxRelayPairs, the per-pair byte budget, and idle expiry.
const (
	maxPendingPerSource = 8
	maxSelfPairs        = 1
)

// relayNorm drops the IPv4-mapped form and any zone: Prefix.Contains never
// matches a zoned address, so a link-local sender with a zone would
// otherwise escape the per-source count.
func relayNorm(ip netip.Addr) netip.Addr { return ip.Unmap().WithZone("") }

func relaySource(a netip.AddrPort) netip.Prefix {
	ip := relayNorm(a.Addr())
	bits := 64
	if ip.Is4() {
		bits = 32
	}
	p, _ := ip.Prefix(bits)
	return p
}

// count reports how many half-formed pairs have a member from src, and how
// many complete pairs have both members from it.
func (r *relay) count(src netip.Prefix) (pending, self int) {
	for _, q := range r.pairs {
		m := 0
		for i := range q.n {
			if src.Contains(relayNorm(q.peers[i].Addr())) {
				m++
			}
		}
		switch {
		case q.n == 1 && m == 1:
			pending++
		case q.n == 2 && m == 2:
			self++
		}
	}
	return pending, self
}

// evictPending drops the oldest half-formed pair, reporting whether there
// was one.
func (r *relay) evictPending() bool {
	var oldest krpc.NodeID
	var at time.Time
	for k, q := range r.pairs {
		if q.n < 2 && (at.IsZero() || q.created.Before(at)) {
			oldest, at = k, q.created
		}
	}
	if at.IsZero() {
		return false
	}
	q := r.pairs[oldest]
	for i := range q.n {
		delete(r.byAddr, q.peers[i])
	}
	delete(r.pairs, oldest)
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
		if pending, _ := r.count(relaySource(from)); pending >= maxPendingPerSource {
			return
		}
		if len(r.pairs) >= 4*n.cfg.MaxRelayPairs && !r.evictPending() {
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
	if src := relaySource(from); p.n == 1 && src == relaySource(p.peers[0]) {
		if _, self := r.count(src); self >= maxSelfPairs {
			return
		}
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
