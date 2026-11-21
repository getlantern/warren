// Package sim runs dht nodes over a deterministic virtual network with a
// cuttable border between a domestic region and the rest of the world. Hosts
// may sit behind a modeled NAT and run punch sessions on extra sockets, so
// the whole stack (DHT, signaling, hole punching) can run together.
package sim

import (
	"container/heap"
	"math/rand/v2"
	"net/netip"
	"time"

	"github.com/getlantern/warren/dht"
	"github.com/getlantern/warren/punch"
)

type Node struct {
	// Addr is the node's public address; for a NATed host, its public IP
	// and DHT socket's local port (the NAT decides the real public port).
	Addr     netip.AddrPort
	Domestic bool
	// Offline nodes neither send nor receive, as if powered off.
	Offline bool
	DHT     *dht.Node
	// NAT, when set, translates everything this host sends and receives.
	NAT *NAT
	// Local is the DHT socket's address on the host's own network.
	Local    netip.AddrPort
	sessions []*Session
	wake     time.Time
	wakeGen  uint64
}

// Session is a punch session attached to a host's data sockets: socket i is
// local port Base+i.
type Session struct {
	Node    *Node
	Punch   *punch.Session
	Base    uint16
	wake    time.Time
	wakeGen uint64
	// spins counts consecutive wakeups at the same instant: a session that
	// reports a timer it does not service would otherwise hang the run.
	spins  int
	lastAt time.Time
}

const sessionPorts = 128

func (s *Session) LocalAddr(socket int) netip.AddrPort {
	return netip.AddrPortFrom(s.Node.Local.Addr(), s.Base+uint16(socket))
}

type Sim struct {
	Now time.Time
	// Border, when set, drops every packet between domestic and foreign nodes.
	Border bool
	// Loss is the independent per-packet drop probability.
	Loss    float64
	OnEvent func(*Node, dht.Event)
	// OnSend observes every datagram a node emits, before loss or the border.
	OnSend func(from *Node, to netip.AddrPort, data []byte)
	// OnPunch receives punch session events.
	OnPunch func(*Session, punch.Event)

	Delivered, Dropped int

	rng    *rand.Rand
	q      queue
	seq    uint64
	nodes  []*Node
	byAddr map[netip.AddrPort]*Node
	byIP   map[netip.Addr]*Node // NATed hosts by public IP
}

func New(seed uint64, start time.Time) *Sim {
	return &Sim{Now: start, rng: rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)), byAddr: map[netip.AddrPort]*Node{}, byIP: map[netip.Addr]*Node{}}
}

func (s *Sim) Rand() *rand.Rand { return s.rng }
func (s *Sim) Nodes() []*Node   { return s.nodes }

// Add creates a node. cfg.Rand is replaced with one derived from the sim seed.
func (s *Sim) Add(addr netip.AddrPort, domestic bool, cfg dht.Config) *Node {
	cfg.Rand = rand.New(rand.NewPCG(s.rng.Uint64(), s.rng.Uint64()))
	n := &Node{Addr: addr, Domestic: domestic, DHT: dht.New(cfg), Local: addr}
	s.nodes = append(s.nodes, n)
	s.byAddr[addr] = n
	return n
}

// AddBehindNAT creates a host whose traffic passes through a NAT with public
// IP public. local is its DHT socket on the host's own network.
func (s *Sim) AddBehindNAT(public netip.Addr, local netip.AddrPort, nat NATConfig, domestic bool, cfg dht.Config) *Node {
	cfg.Rand = rand.New(rand.NewPCG(s.rng.Uint64(), s.rng.Uint64()))
	nat.Public = public
	n := &Node{
		Addr: netip.AddrPortFrom(public, local.Port()), Domestic: domestic, DHT: dht.New(cfg),
		NAT: NewNAT(nat, rand.New(rand.NewPCG(s.rng.Uint64(), s.rng.Uint64()))), Local: local,
	}
	s.nodes = append(s.nodes, n)
	s.byIP[public] = n
	return n
}

// Attach binds a punch session to fresh data sockets on n.
func (s *Sim) Attach(n *Node, p *punch.Session) *Session {
	ss := &Session{Node: n, Punch: p, Base: 40000 + uint16(len(n.sessions))*sessionPorts}
	n.sessions = append(n.sessions, ss)
	return ss
}

// DoSession runs f against a punch session, then delivers its output.
func (s *Sim) DoSession(ss *Session, f func(now time.Time)) {
	f(s.Now)
	s.flushSession(ss)
}

// Do runs f against a node at the current time, then delivers its output.
func (s *Sim) Do(n *Node, f func(now time.Time)) {
	f(s.Now)
	s.flush(n)
}

// At schedules f to run at t, in order with packet deliveries.
func (s *Sim) At(t time.Time, f func()) { s.push(&event{at: t, fn: f}) }

// RunUntil advances virtual time to t, processing every event before it.
// Time never moves backwards: an earlier t panics, since rewinding the clock
// without undoing state would silently corrupt measurements.
func (s *Sim) RunUntil(t time.Time) {
	if t.Before(s.Now) {
		panic("sim: RunUntil moves time backwards")
	}
	for s.q.Len() > 0 && !s.q[0].at.After(t) {
		ev := heap.Pop(&s.q).(*event)
		s.Now = ev.at
		switch {
		case ev.fn != nil:
			ev.fn()
		case ev.data != nil:
			s.deliver(ev)
		case ev.sess != nil:
			if ev.gen == ev.sess.wakeGen {
				if ss := ev.sess; s.Now.Equal(ss.lastAt) {
					if ss.spins++; ss.spins > 1000 {
						panic("sim: punch session keeps waking at the same instant; NextWakeup reports a timer Tick does not service")
					}
				} else {
					ss.spins, ss.lastAt = 0, s.Now
				}
				ev.sess.wake = time.Time{}
				ev.sess.Punch.Tick(s.Now)
				s.flushSession(ev.sess)
			}
		case ev.gen == ev.to.wakeGen:
			ev.to.wake = time.Time{}
			ev.to.DHT.Tick(s.Now)
			s.flush(ev.to)
		}
	}
	s.Now = t
}

// deliver passes a datagram through the destination's NAT, if any, to the
// DHT node or punch session bound to the local port it reaches.
func (s *Sim) deliver(ev *event) {
	n := ev.to
	if n.Offline {
		s.Dropped++
		return
	}
	local := netip.AddrPortFrom(n.Local.Addr(), ev.dst.Port())
	if n.NAT != nil {
		var ok bool
		if local, ok = n.NAT.Inbound(ev.from, ev.dst.Port(), s.Now); !ok {
			s.Dropped++
			return
		}
	}
	s.Delivered++
	if local.Port() == n.Local.Port() {
		n.DHT.HandlePacket(s.Now, ev.from, ev.data)
		s.flush(n)
		return
	}
	for _, ss := range n.sessions {
		if i := int(local.Port()) - int(ss.Base); i >= 0 && i < ss.Punch.Sockets() {
			ss.Punch.HandlePacket(s.Now, i, ev.from, ev.data)
			s.flushSession(ss)
			return
		}
	}
}

// send routes a datagram from local on n, through n's NAT, to dst.
func (s *Sim) send(n *Node, local, dst netip.AddrPort, data []byte) {
	to := s.byAddr[dst]
	if to == nil {
		to = s.byIP[dst.Addr()]
	}
	src := netip.AddrPortFrom(n.Addr.Addr(), local.Port())
	if n.NAT != nil {
		var ok bool
		if src, ok = n.NAT.Outbound(local, dst, s.Now); !ok {
			s.Dropped++
			return
		}
	}
	if to == nil || n.Offline || (s.Border && to.Domestic != n.Domestic) || s.rng.Float64() < s.Loss {
		s.Dropped++
		return
	}
	s.push(&event{at: s.Now.Add(s.latency(n, to)), to: to, from: src, dst: dst, data: data})
}

func (s *Sim) flushSession(ss *Session) {
	sends, events := ss.Punch.Drain()
	for _, snd := range sends {
		s.send(ss.Node, ss.LocalAddr(snd.Socket), snd.To, snd.Data)
	}
	if s.OnPunch != nil {
		for _, e := range events {
			s.OnPunch(ss, e)
		}
	}
	if w := ss.Punch.NextWakeup(); !w.IsZero() && (ss.wake.IsZero() || w.Before(ss.wake)) {
		if w.Before(s.Now) {
			w = s.Now
		}
		ss.wake = w
		ss.wakeGen++
		s.push(&event{at: w, sess: ss, gen: ss.wakeGen})
	}
}

func (s *Sim) flush(n *Node) {
	sends, events := n.DHT.Drain()
	for _, snd := range sends {
		if s.OnSend != nil {
			s.OnSend(n, snd.To, snd.Data)
		}
		s.send(n, n.Local, snd.To, snd.Data)
	}
	if s.OnEvent != nil {
		for _, e := range events {
			s.OnEvent(n, e)
		}
	}
	if w := n.DHT.NextWakeup(); !w.IsZero() && (n.wake.IsZero() || w.Before(n.wake)) {
		if w.Before(s.Now) {
			w = s.Now
		}
		n.wake = w
		n.wakeGen++
		s.push(&event{at: w, to: n, gen: n.wakeGen})
	}
}

// latency: 15–60 ms one way within a region, 120–220 ms across the border.
func (s *Sim) latency(a, b *Node) time.Duration {
	if a.Domestic == b.Domestic {
		return time.Duration(15+s.rng.IntN(45)) * time.Millisecond
	}
	return time.Duration(120+s.rng.IntN(100)) * time.Millisecond
}

func (s *Sim) push(e *event) {
	s.seq++
	e.seq = s.seq
	heap.Push(&s.q, e)
}

type event struct {
	at   time.Time
	seq  uint64
	to   *Node
	sess *Session
	fn   func()
	from netip.AddrPort
	dst  netip.AddrPort
	data []byte
	gen  uint64
}

type queue []*event

func (q queue) Len() int { return len(q) }
func (q queue) Less(i, j int) bool {
	if !q[i].at.Equal(q[j].at) {
		return q[i].at.Before(q[j].at)
	}
	return q[i].seq < q[j].seq
}
func (q queue) Swap(i, j int) { q[i], q[j] = q[j], q[i] }
func (q *queue) Push(x any)   { *q = append(*q, x.(*event)) }
func (q *queue) Pop() any {
	old := *q
	e := old[len(old)-1]
	*q = old[:len(old)-1]
	return e
}
