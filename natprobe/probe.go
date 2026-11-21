package natprobe

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/getlantern/warren/krpc"
)

var DefaultBootstrap = []string{
	"router.bittorrent.com:6881",
	"dht.transmissionbt.com:6881",
	"router.utorrent.com:6881",
	"dht.libtorrent.org:25401",
}

type Config struct {
	Bootstrap []string
	// Reflectors is how many fresh nodes the main socket pings serially to
	// model port allocation.
	Reflectors int
	// ExtraSockets each ping one reflector serially after the main sequence,
	// extending the allocation sequence across local ports.
	ExtraSockets int
	QueryTimeout time.Duration
	// Listen, if positive, runs the main socket as a full (non read-only)
	// node for this long after probing and counts queries arriving from
	// addresses never contacted. Any such query proves the NAT forwards
	// unsolicited traffic to the mapping.
	Listen time.Duration
	// Version is sent as the KRPC "v" field; empty omits it.
	Version []byte
	Logf    func(format string, args ...any)
}

func (c *Config) defaults() {
	if len(c.Bootstrap) == 0 {
		c.Bootstrap = DefaultBootstrap
	}
	if c.Reflectors == 0 {
		c.Reflectors = 16
	}
	if c.QueryTimeout == 0 {
		c.QueryTimeout = 1500 * time.Millisecond
	}
	if c.Logf == nil {
		c.Logf = func(string, ...any) {}
	}
}

type Report struct {
	Local        netip.AddrPort `json:"local"`
	Started      time.Time      `json:"started"`
	Duration     time.Duration  `json:"duration_ns"`
	Queries      int            `json:"queries"`
	Responders   int            `json:"responders"`
	NoIPField    int            `json:"responders_without_ip"`
	Versions     map[string]int `json:"versions"`
	Unsolicited  int            `json:"unsolicited_queries"`
	Observations []Observation  `json:"observations"`
	// Reflectors are serial reflectors that reported our address, usable
	// for follow-up tests such as MappingTimeout.
	Reflectors []netip.AddrPort `json:"-"`
	Analysis
}

func Run(ctx context.Context, cfg Config) (*Report, error) {
	cfg.defaults()
	p := &prober{cfg: cfg, rep: &Report{Started: time.Now(), Versions: map[string]int{}}}
	main, err := p.open(0, cfg.Listen <= 0)
	if err != nil {
		return nil, err
	}
	defer main.close()
	p.rep.Local = main.local

	if err := p.discover(ctx, main); err != nil {
		return nil, err
	}
	order := p.serial(ctx, main)
	p.extraSockets(ctx, order)
	if cfg.Listen > 0 {
		p.listen(ctx, main)
	}

	p.rep.Reflectors = p.serialDest
	p.rep.Duration = time.Since(p.rep.Started)
	p.rep.Analysis = Analyze(main.local, p.rep.Observations)
	return p.rep, nil
}

type prober struct {
	cfg Config
	mu  sync.Mutex
	rep *Report
	// candidates are nodes learned but not yet contacted by any socket.
	candidates []krpc.NodeInfo
	known      map[netip.AddrPort]bool
	// serialDest are serial reflectors that reported our address.
	serialDest []netip.AddrPort
}

func (p *prober) record(o Observation, m *krpc.Msg) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rep.Responders++
	p.rep.Versions[versionString(m.V)]++
	if !m.IP.IsValid() {
		p.rep.NoIPField++
		return
	}
	o.Mapped = netip.AddrPortFrom(m.IP.Addr().Unmap(), m.IP.Port())
	o.Version = versionString(m.V)
	p.rep.Observations = append(p.rep.Observations, o)
}

func (p *prober) learn(nodes []krpc.NodeInfo) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.known == nil {
		p.known = map[netip.AddrPort]bool{}
	}
	for _, n := range nodes {
		a := n.Addr.Addr()
		if p.known[n.Addr] || !a.Is4() || !a.IsGlobalUnicast() || a.IsPrivate() || n.Addr.Port() == 0 {
			continue
		}
		p.known[n.Addr] = true
		p.candidates = append(p.candidates, n)
	}
}

// take removes and returns up to n candidates, at most one per /16 so the
// sample spans unrelated networks.
func (p *prober) take(n int, seen16 map[[2]byte]bool) []krpc.NodeInfo {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out, rest []krpc.NodeInfo
	for _, c := range p.candidates {
		a := c.Addr.Addr().As4()
		key := [2]byte{a[0], a[1]}
		if len(out) < n && (seen16 == nil || !seen16[key]) {
			if seen16 != nil {
				seen16[key] = true
			}
			out = append(out, c)
			continue
		}
		rest = append(rest, c)
	}
	p.candidates = rest
	return out
}

func (p *prober) query(ctx context.Context, s *sock, order int, to netip.AddrPort, q string, a krpc.Args) (*krpc.Msg, bool) {
	p.mu.Lock()
	p.rep.Queries++
	p.mu.Unlock()
	start := time.Now()
	m, err := s.query(ctx, to, q, a, p.cfg.QueryTimeout)
	if err != nil || m.Y != krpc.Response {
		return nil, false
	}
	p.record(Observation{Socket: s.idx, Order: order, Local: s.local, Dest: to, RTT: time.Since(start)}, m)
	return m, true
}

// discover walks outward from the bootstrap routers with concurrent
// find_node queries until enough fresh reflectors are known.
func (p *prober) discover(ctx context.Context, s *sock) error {
	need := p.cfg.Reflectors + p.cfg.ExtraSockets + 8
	var boots []krpc.NodeInfo
	for _, h := range p.cfg.Bootstrap {
		addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", hostOnly(h))
		if err != nil {
			p.cfg.Logf("resolve %s: %v", h, err)
			continue
		}
		port := portOnly(h)
		for _, a := range addrs {
			boots = append(boots, krpc.NodeInfo{Addr: netip.AddrPortFrom(a, port)})
		}
	}
	if len(boots) == 0 {
		return errors.New("natprobe: no bootstrap address resolved")
	}
	p.walk(ctx, s, boots)
	for round := 0; round < 4 && p.fresh() < need; round++ {
		p.walk(ctx, s, p.take(16, nil))
	}
	if p.fresh() < p.cfg.Reflectors/2 {
		return fmt.Errorf("natprobe: only %d reflectors discovered", p.fresh())
	}
	return nil
}

func (p *prober) walk(ctx context.Context, s *sock, nodes []krpc.NodeInfo) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for _, n := range nodes {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			target := randomID()
			if m, ok := p.query(ctx, s, -1, n.Addr, "find_node", krpc.Args{Target: &target}); ok {
				p.learn(m.R.Nodes)
			}
		}()
	}
	wg.Wait()
}

func (p *prober) fresh() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.candidates)
}

// serial pings fresh reflectors one at a time so the NAT creates mappings in
// a known order. Returns the next order number.
func (p *prober) serial(ctx context.Context, s *sock) int {
	order := 0
	seen16 := map[[2]byte]bool{}
	for replies := 0; replies < p.cfg.Reflectors; {
		batch := p.take(1, seen16)
		if len(batch) == 0 {
			break
		}
		if m, ok := p.query(ctx, s, order, batch[0].Addr, "ping", krpc.Args{}); ok {
			replies++
			if m.IP.IsValid() {
				p.serialDest = append(p.serialDest, batch[0].Addr)
			}
		}
		order++
	}
	return order
}

func (p *prober) extraSockets(ctx context.Context, order int) {
	if len(p.serialDest) == 0 {
		return
	}
	for i := 1; i <= p.cfg.ExtraSockets; i++ {
		dest := p.serialDest[(i-1)%len(p.serialDest)]
		s, err := p.open(i, true)
		if err != nil {
			p.cfg.Logf("extra socket: %v", err)
			return
		}
		p.query(ctx, s, order, dest, "ping", krpc.Args{})
		order++
		s.close()
	}
}

func (p *prober) listen(ctx context.Context, s *sock) {
	if len(p.rep.Observations) > 0 {
		s.setID(krpc.SecureID(p.rep.Observations[0].Mapped.Addr(), s.getID()))
	}
	// Re-announce ourselves to a few nodes as a full node so others add us.
	p.walk(ctx, s, p.take(16, nil))
	t := time.NewTimer(p.cfg.Listen)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
	p.mu.Lock()
	p.rep.Unsolicited = s.unsolicitedCount()
	p.mu.Unlock()
}

// listenUDP opens probe sockets; tests replace it to simulate exhaustion.
var listenUDP = net.ListenUDP

func (p *prober) open(idx int, readOnly bool) (*sock, error) {
	conn, err := listenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return nil, err
	}
	s := &sock{
		idx:       idx,
		conn:      conn,
		local:     conn.LocalAddr().(*net.UDPAddr).AddrPort(),
		id:        randomID(),
		readOnly:  readOnly,
		version:   p.cfg.Version,
		pending:   map[uint16]chan reply{},
		contacted: map[netip.Addr]bool{},
	}
	if b := s.local.Addr(); b.IsUnspecified() {
		s.local = netip.AddrPortFrom(outboundIP(), s.local.Port())
	}
	go s.readLoop()
	return s, nil
}

type reply struct {
	from netip.AddrPort
	msg  *krpc.Msg
}

type sock struct {
	idx      int
	conn     *net.UDPConn
	local    netip.AddrPort
	readOnly bool
	version  []byte

	mu          sync.Mutex
	id          krpc.NodeID
	nextT       uint16
	pending     map[uint16]chan reply
	contacted   map[netip.Addr]bool
	unsolicited int
}

func (s *sock) getID() krpc.NodeID   { s.mu.Lock(); defer s.mu.Unlock(); return s.id }
func (s *sock) setID(id krpc.NodeID) { s.mu.Lock(); s.id = id; s.mu.Unlock() }
func (s *sock) unsolicitedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unsolicited
}
func (s *sock) close() { s.conn.Close() }

func (s *sock) query(ctx context.Context, to netip.AddrPort, q string, a krpc.Args, timeout time.Duration) (*krpc.Msg, error) {
	ch := make(chan reply, 1)
	s.mu.Lock()
	s.nextT++
	t := s.nextT
	s.pending[t] = ch
	s.contacted[to.Addr()] = true
	a.ID = s.id
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.pending, t); s.mu.Unlock() }()

	var tid [2]byte
	binary.BigEndian.PutUint16(tid[:], t)
	m := krpc.Msg{T: tid[:], Y: krpc.Query, Q: q, A: a, RO: s.readOnly, V: s.version}
	if _, err := s.conn.WriteToUDPAddrPort(krpc.AppendMarshal(nil, &m), to); err != nil {
		return nil, err
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case r := <-ch:
			if r.from.Addr().Unmap() != to.Addr().Unmap() {
				continue
			}
			return r.msg, nil
		case <-timer.C:
			return nil, context.DeadlineExceeded
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (s *sock) readLoop() {
	buf := make([]byte, 2048)
	for {
		n, from, err := s.conn.ReadFromUDPAddrPort(buf)
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
			s.serve(from, &m)
			continue
		}
		if len(m.T) != 2 {
			continue
		}
		s.mu.Lock()
		ch := s.pending[binary.BigEndian.Uint16(m.T)]
		s.mu.Unlock()
		if ch != nil {
			select {
			case ch <- reply{from: from, msg: &m}:
			default:
			}
		}
	}
}

// serve answers inbound queries minimally, like a node with an empty table,
// and counts those from never-contacted addresses.
func (s *sock) serve(from netip.AddrPort, q *krpc.Msg) {
	s.mu.Lock()
	if !s.contacted[from.Addr()] {
		s.unsolicited++
	}
	id, ro := s.id, s.readOnly
	s.mu.Unlock()
	if ro {
		return
	}
	resp := krpc.Msg{T: q.T, Y: krpc.Response, IP: from, V: s.version, R: krpc.Return{ID: id}}
	switch q.Q {
	case "ping":
	case "find_node":
		resp.R.Nodes = []krpc.NodeInfo{}
	case "get_peers":
		resp.R.Nodes = []krpc.NodeInfo{}
		resp.R.Token = id[:4]
	default:
		resp = krpc.Msg{T: q.T, Y: krpc.Err, V: s.version, E: &krpc.Error{Code: krpc.ErrMethodUnknown, Msg: "Method Unknown"}}
	}
	s.conn.WriteToUDPAddrPort(krpc.AppendMarshal(nil, &resp), from)
}

func randomID() krpc.NodeID {
	var id krpc.NodeID
	rand.Read(id[:])
	return id
}

func versionString(v []byte) string {
	if len(v) == 0 {
		return "(none)"
	}
	if len(v) >= 2 && isAlpha(v[0]) && isAlpha(v[1]) {
		return fmt.Sprintf("%s %x", v[:2], v[2:])
	}
	return fmt.Sprintf("%x", v)
}

func isAlpha(c byte) bool { return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' }

func hostOnly(hp string) string {
	h, _, err := net.SplitHostPort(hp)
	if err != nil {
		return hp
	}
	return h
}

func portOnly(hp string) uint16 {
	_, p, err := net.SplitHostPort(hp)
	if err != nil {
		return 6881
	}
	n, err := net.LookupPort("udp", p)
	if err != nil {
		return 6881
	}
	return uint16(n)
}

// outboundIP finds the source address the kernel would use for a public
// destination, without sending anything.
func outboundIP() netip.Addr {
	c, err := net.Dial("udp4", "192.0.2.1:9")
	if err != nil {
		return netip.Addr{}
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).AddrPort().Addr()
}
