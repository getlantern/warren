package survey

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/getlantern/warren/dht"
	"github.com/getlantern/warren/krpc"
)

type Config struct {
	Bootstrap []string
	Label     Labeler
	// ProbesPerSecond bounds cold pings, keeping the vantage's traffic in
	// line with an ordinary busy node.
	ProbesPerSecond int
	// AltDelay is how long after an inbound query the other-port ping goes
	// out, comfortably inside typical 30-second NAT mapping lifetimes.
	AltDelay time.Duration
	Timeout  time.Duration
}

// Vantage is a Mainline node on socket A plus a probe socket B on another port.
type Vantage struct {
	cfg   Config
	a, b  *net.UDPConn
	id    krpc.NodeID
	tally *Tally

	mu        sync.Mutex
	nextT     uint16
	pending   map[uint16]*waiter  // by transaction id, across both sockets
	contacted map[netip.Addr]bool // anyone we exchanged packets with
	queue     []netip.AddrPort    // referred, never contacted
	alt       chan altProbe       // other-port probes owed to inbound queriers
}

type altProbe struct {
	to    netip.AddrPort
	label string
	at    time.Time
}

// Inbound queries come from anyone, with spoofable source addresses, so
// what they can make us remember or probe is bounded: past these limits new
// queriers are answered but neither tracked nor probed.
var (
	maxContacted = 1 << 20
	maxAltQueue  = 1024
)

func NewVantage(cfg Config) (*Vantage, error) {
	if cfg.ProbesPerSecond == 0 {
		cfg.ProbesPerSecond = 20
	}
	if cfg.AltDelay == 0 {
		cfg.AltDelay = 2 * time.Second
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 3 * time.Second
	}
	if cfg.Label == nil {
		cfg.Label = func(netip.Addr) string { return "all" }
	}
	a, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return nil, err
	}
	b, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		a.Close()
		return nil, err
	}
	v := &Vantage{cfg: cfg, a: a, b: b, tally: NewTally(), pending: map[uint16]*waiter{}, contacted: map[netip.Addr]bool{}, alt: make(chan altProbe, maxAltQueue)}
	rand.Read(v.id[:])
	return v, nil
}

func (v *Vantage) Tally() *Tally { return v.tally }

func (v *Vantage) Close() { v.a.Close(); v.b.Close() }

// Run surveys until ctx ends.
func (v *Vantage) Run(ctx context.Context) error {
	go v.read(v.a, true)
	go v.read(v.b, false)
	go v.walk(ctx)
	go v.altProbes(ctx)
	tick := time.NewTicker(time.Second / time.Duration(v.cfg.ProbesPerSecond))
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			if to, ok := v.nextCold(); ok {
				go v.cold(to)
			}
		}
	}
}

func (v *Vantage) nextCold() (netip.AddrPort, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	for len(v.queue) > 0 {
		to := v.queue[0]
		v.queue = v.queue[1:]
		if !v.contacted[to.Addr()] {
			v.contacted[to.Addr()] = true
			return to, true
		}
	}
	return netip.AddrPort{}, false
}

func (v *Vantage) cold(to netip.AddrPort) {
	label := v.cfg.Label(to.Addr())
	ok := v.ping(v.a, to)
	v.tally.update(label, func(c *Counts) {
		c.ColdProbed++
		if ok {
			c.ColdAnswered++
		}
	})
}

// walk discovers nodes with get_peers lookups toward random targets, as
// libtorrent's own refresh does, feeding referrals to the cold-probe queue.
func (v *Vantage) walk(ctx context.Context) {
	var frontier []netip.AddrPort
	for _, h := range v.cfg.Bootstrap {
		addrs, _ := net.DefaultResolver.LookupNetIP(ctx, "ip4", host(h))
		for _, a := range addrs {
			frontier = append(frontier, netip.AddrPortFrom(a, port(h)))
		}
	}
	for ctx.Err() == nil {
		if len(frontier) == 0 {
			v.mu.Lock()
			if n := len(v.queue); n > 0 {
				frontier = append(frontier, v.queue[n-1])
			}
			v.mu.Unlock()
			if len(frontier) == 0 {
				time.Sleep(time.Second)
				continue
			}
		}
		to := frontier[0]
		frontier = frontier[1:]
		var target krpc.NodeID
		rand.Read(target[:])
		r := v.query(v.a, to, "get_peers", krpc.Args{InfoHash: &target})
		if r == nil {
			continue
		}
		v.mu.Lock()
		for i, n := range r.R.Nodes {
			a := n.Addr.Addr()
			if !a.IsGlobalUnicast() || a.IsPrivate() || v.contacted[a] {
				continue
			}
			if i < 2 && len(frontier) < 64 {
				frontier = append(frontier, n.Addr) // keep walking
				v.contacted[a] = true
				continue
			}
			if len(v.queue) < 10000 {
				v.queue = append(v.queue, n.Addr)
			}
		}
		v.mu.Unlock()
		time.Sleep(50 * time.Millisecond)
	}
}

func (v *Vantage) ping(c *net.UDPConn, to netip.AddrPort) bool {
	return v.query(c, to, "ping", krpc.Args{}) != nil
}

type waiter struct {
	to netip.AddrPort
	ch chan *krpc.Msg
}

func (v *Vantage) query(c *net.UDPConn, to netip.AddrPort, q string, a krpc.Args) *krpc.Msg {
	w := &waiter{to: to, ch: make(chan *krpc.Msg, 1)}
	v.mu.Lock()
	v.nextT++
	t := v.nextT
	v.pending[t] = w
	v.contacted[to.Addr()] = true
	v.mu.Unlock()
	defer func() { v.mu.Lock(); delete(v.pending, t); v.mu.Unlock() }()

	var tid [2]byte
	binary.BigEndian.PutUint16(tid[:], t)
	a.ID = v.id
	m := krpc.Msg{T: tid[:], Y: krpc.Query, Q: q, A: a, V: dht.DefaultVersion}
	if _, err := c.WriteToUDPAddrPort(krpc.AppendMarshal(nil, &m), to); err != nil {
		return nil
	}
	select {
	case r := <-w.ch:
		return r
	case <-time.After(v.cfg.Timeout):
		return nil
	}
}

func (v *Vantage) read(c *net.UDPConn, primary bool) {
	buf := make([]byte, 2048)
	for {
		n, from, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		pkt := append([]byte(nil), buf[:n]...)
		var m krpc.Msg
		if krpc.Unmarshal(pkt, &m) != nil {
			continue
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		if m.Y == krpc.Query {
			if primary {
				v.serve(c, from, &m)
			}
			continue
		}
		if len(m.T) != 2 {
			continue
		}
		v.mu.Lock()
		w := v.pending[binary.BigEndian.Uint16(m.T)]
		v.mu.Unlock()
		if w != nil && w.to.Addr() == from.Addr() && m.Y == krpc.Response {
			select {
			case w.ch <- &m:
			default:
			}
		}
	}
}

// serve answers like a node with an empty table and schedules the
// other-port probe for queriers that are not read-only.
func (v *Vantage) serve(c *net.UDPConn, from netip.AddrPort, q *krpc.Msg) {
	r := krpc.Msg{T: q.T, Y: krpc.Response, IP: from, V: dht.DefaultVersion, R: krpc.Return{ID: v.id, P: int(from.Port())}}
	switch q.Q {
	case "ping":
	case "find_node", "get_peers":
		r.R.Nodes = []krpc.NodeInfo{}
		if q.Q == "get_peers" {
			r.R.Token = v.id[:4]
		}
	case "get":
		r.R.Nodes = []krpc.NodeInfo{}
		r.R.Token = v.id[:4]
	default:
		r = krpc.Msg{T: q.T, Y: krpc.Err, V: dht.DefaultVersion, E: &krpc.Error{Code: krpc.ErrMethodUnknown, Msg: "Method Unknown"}}
	}
	c.WriteToUDPAddrPort(krpc.AppendMarshal(nil, &r), from)
	if q.RO {
		return
	}
	v.mu.Lock()
	first := !v.contacted[from.Addr()] && len(v.contacted) < maxContacted
	if first {
		v.contacted[from.Addr()] = true
	}
	v.mu.Unlock()
	if !first {
		return
	}
	label := v.cfg.Label(from.Addr())
	v.tally.update(label, func(c *Counts) { c.InboundSeen++ })
	select {
	case v.alt <- altProbe{to: from, label: label, at: time.Now().Add(v.cfg.AltDelay)}:
	default: // queue full: skip the probe rather than grow
	}
}

// altProbes sends the owed other-port probes, each no earlier than its due
// time and all paced at ProbesPerSecond, so concurrent pings stay bounded
// by that rate times the ping timeout.
func (v *Vantage) altProbes(ctx context.Context) {
	tick := time.NewTicker(time.Second / time.Duration(v.cfg.ProbesPerSecond))
	defer tick.Stop()
	for {
		var p altProbe
		select {
		case <-ctx.Done():
			return
		case p = <-v.alt:
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Until(p.at)):
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		go func() {
			ok := v.ping(v.b, p.to)
			v.tally.update(p.label, func(c *Counts) {
				c.AltProbed++
				if ok {
					c.AltAns++
				}
			})
		}()
	}
}

func host(hp string) string {
	h, _, err := net.SplitHostPort(hp)
	if err != nil {
		return hp
	}
	return h
}

func port(hp string) uint16 {
	_, p, err := net.SplitHostPort(hp)
	if err != nil {
		return 6881
	}
	n, _ := net.LookupPort("udp", p)
	return uint16(n)
}
