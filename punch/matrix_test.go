package punch_test

import (
	"container/heap"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/getlantern/warren/krpc"
	"github.com/getlantern/warren/punch"
	"github.com/getlantern/warren/sim"
)

// natKind is a NAT behavior plus what an accurate natprobe run would report.
type natKind struct {
	name string
	cfg  *sim.NATConfig // nil: a public host with no NAT
}

func kinds() []natKind {
	block := func(f sim.FilteringBehavior) *sim.NATConfig {
		return &sim.NATConfig{Mapping: sim.EndpointDependentMapping, Filtering: f, Alloc: sim.BlockRandomPorts, BlockLo: 34816, BlockHi: 34816 + 2047}
	}
	return []natKind{
		{"public", nil},
		{"cone", &sim.NATConfig{Mapping: sim.EndpointIndependentMapping, Filtering: sim.AddressPortDependentFiltering, Alloc: sim.PortPreserving}},
		{"sequential", &sim.NATConfig{Mapping: sim.EndpointDependentMapping, Filtering: sim.AddressPortDependentFiltering, Alloc: sim.SequentialPorts, Step: 1, Jitter: 2}},
		{"cgnat-block", block(sim.AddressDependentFiltering)},
		{"block-strict", block(sim.AddressPortDependentFiltering)},
		{"random", &sim.NATConfig{Mapping: sim.EndpointDependentMapping, Filtering: sim.AddressPortDependentFiltering, Alloc: sim.RandomPorts}},
	}
}

func profileOf(k natKind, baseline bool) punch.Profile {
	if k.cfg == nil || k.cfg.Mapping == sim.EndpointIndependentMapping {
		return punch.Profile{Mapping: punch.MappingIndependent}
	}
	p := punch.Profile{Mapping: punch.MappingDependent, Allocation: punch.AllocRandom}
	if baseline {
		return p // HyperDHT classifies only consistent vs random
	}
	switch k.cfg.Alloc {
	case sim.SequentialPorts:
		p.Allocation, p.Step = punch.AllocSequential, uint16(k.cfg.Step)
	case sim.BlockRandomPorts:
		p.Allocation, p.BlockLo, p.BlockHi = punch.AllocBlock, k.cfg.BlockLo, k.cfg.BlockHi
	}
	return p
}

type host struct {
	public  netip.Addr
	local   netip.Addr
	nat     *sim.NAT
	sess    *punch.Session
	result  punch.Event
	at      time.Time
	wakeGen int
}

const basePort = 40000

func (h *host) localAddr(socket int) netip.AddrPort {
	return netip.AddrPortFrom(h.local, basePort+uint16(socket))
}

type delivery struct {
	at   time.Time
	seq  int
	to   *host // nil: the reflector
	from netip.AddrPort
	dst  netip.AddrPort
	data []byte
	wake int
}

type queue []*delivery

func (q queue) Len() int { return len(q) }
func (q queue) Less(i, j int) bool {
	if !q[i].at.Equal(q[j].at) {
		return q[i].at.Before(q[j].at)
	}
	return q[i].seq < q[j].seq
}
func (q queue) Swap(i, j int) { q[i], q[j] = q[j], q[i] }
func (q *queue) Push(x any)   { *q = append(*q, x.(*delivery)) }
func (q *queue) Pop() any {
	o := *q
	d := o[len(o)-1]
	*q = o[:len(o)-1]
	return d
}

type world struct {
	now       time.Time
	q         queue
	seq       int
	rng       *rand.Rand
	reflector netip.AddrPort
	hosts     []*host
}

func (w *world) push(d *delivery) { w.seq++; d.seq = w.seq; heap.Push(&w.q, d) }

func (w *world) flush(h *host) {
	sends, events := h.sess.Drain()
	for _, s := range sends {
		src := h.localAddr(s.Socket)
		if h.nat != nil {
			var ok bool
			if src, ok = h.nat.Outbound(src, s.To, w.now); !ok {
				continue
			}
		}
		var to *host
		for _, x := range w.hosts {
			if x.public == s.To.Addr() {
				to = x
			}
		}
		if to == nil && s.To != w.reflector {
			continue
		}
		w.push(&delivery{at: w.now.Add(time.Duration(30+w.rng.IntN(50)) * time.Millisecond), to: to, from: src, dst: s.To, data: s.Data})
	}
	for _, e := range events {
		switch e.(type) {
		case punch.Connected, punch.Failed:
			h.result, h.at = e, w.now
		}
	}
	if t := h.sess.NextWakeup(); !t.IsZero() {
		h.wakeGen++
		w.push(&delivery{at: t, to: h, wake: h.wakeGen})
	}
}

func (w *world) run(until time.Time) {
	for w.q.Len() > 0 && !w.q[0].at.After(until) {
		d := heap.Pop(&w.q).(*delivery)
		w.now = d.at
		switch {
		case d.wake != 0:
			if d.wake == d.to.wakeGen {
				d.to.sess.Tick(w.now)
				w.flush(d.to)
			}
		case d.to == nil:
			w.reflect(d)
		default:
			h := d.to
			local := d.dst
			if h.nat != nil {
				var ok bool
				if local, ok = h.nat.Inbound(d.from, d.dst.Port(), w.now); !ok {
					continue
				}
			}
			socket := int(local.Port()) - basePort
			if socket < 0 || socket >= h.sess.Sockets() {
				continue
			}
			h.sess.HandlePacket(w.now, socket, d.from, d.data)
			w.flush(h)
		}
	}
	w.now = until
}

// reflect answers a ping the way a Mainline node does: with the sender's
// observed address in the ip field.
func (w *world) reflect(d *delivery) {
	var q krpc.Msg
	if krpc.Unmarshal(d.data, &q) != nil || q.Y != krpc.Query {
		return
	}
	r := krpc.Msg{T: q.T, Y: krpc.Response, IP: d.from, R: krpc.Return{ID: krpc.NodeID{9}}}
	for _, h := range w.hosts {
		if h.public == d.from.Addr() {
			w.push(&delivery{at: w.now.Add(20 * time.Millisecond), to: h, from: w.reflector, dst: d.from, data: krpc.AppendMarshal(nil, &r)})
		}
	}
}

func newHost(w *world, i int, k natKind, cfg punch.Config) *host {
	pub := netip.AddrFrom4([4]byte{byte(2 + 43*i), 10, 0, 1})
	h := &host{public: pub, local: pub}
	if k.cfg != nil {
		c := *k.cfg
		c.Public = pub
		h.nat = sim.NewNAT(c, rand.New(rand.NewPCG(w.rng.Uint64(), 1)))
		h.local = netip.AddrFrom4([4]byte{192, 168, byte(i), 10})
	}
	cfg.Rand = rand.New(rand.NewPCG(w.rng.Uint64(), 2))
	h.sess = punch.New(cfg)
	return h
}

type outcome struct {
	ok       bool
	took     time.Duration
	strategy punch.Strategy
	mappings int // NAT ports consumed on the busier side
}

func punchOnce(seed uint64, a, b natKind, baseline bool) outcome {
	w := &world{now: time.Unix(1_800_000_000, 0), rng: rand.New(rand.NewPCG(seed, 99)), reflector: netip.MustParseAddrPort("198.51.100.1:6881")}
	secret := []byte("0123456789abcdef0123456789abcdef")
	ha := newHost(w, 0, a, punch.Config{Initiator: true, Secret: secret, Local: profileOf(a, baseline), NoDoubleBirthday: baseline})
	hb := newHost(w, 1, b, punch.Config{Local: profileOf(b, baseline), NoDoubleBirthday: baseline})
	w.hosts = []*host{ha, hb}

	for _, h := range w.hosts {
		h.sess.Reflect([]netip.AddrPort{w.reflector})
		w.flush(h)
	}
	w.run(w.now.Add(time.Second))
	oa, ob := ha.sess.Offer([]netip.AddrPort{ha.localAddr(0)}), hb.sess.Offer([]netip.AddrPort{hb.localAddr(0)})

	// The responder starts when the offer arrives; the initiator one signaling
	// hop later, when the answer arrives.
	start := w.now
	hb.sess.Start(w.now, roundTrip(oa))
	w.flush(hb)
	w.run(w.now.Add(150 * time.Millisecond))
	ha.sess.Start(w.now, roundTrip(ob))
	w.flush(ha)
	w.run(start.Add(10 * time.Second))

	ca, okA := ha.result.(punch.Connected)
	_, okB := hb.result.(punch.Connected)
	o := outcome{ok: okA && okB}
	if okA {
		o.strategy = ca.Strategy
	} else if f, ok := ha.result.(punch.Failed); ok {
		o.strategy = f.Strategy
	}
	last := ha.at
	if hb.at.After(last) {
		last = hb.at
	}
	o.took = last.Sub(start)
	for _, h := range w.hosts {
		if h.nat != nil {
			o.mappings = max(o.mappings, h.nat.Mappings())
		}
	}
	return o
}

func roundTrip(o punch.Offer) punch.Offer {
	back, err := punch.UnmarshalOffer(o.Marshal())
	if err != nil {
		panic(err)
	}
	return back
}

// TestPunchMatrix measures direct-connection success for every NAT pairing,
// against a HyperDHT-style planner that knows only consistent vs random
// mapping and refuses pairs where both sides map dependently.
func TestPunchMatrix(t *testing.T) {
	const seeds = 40
	ks := kinds()
	var b strings.Builder
	fmt.Fprintf(&b, "\nsuccess over %d seeds, ours (baseline)\n%-13s", seeds, "")
	for _, k := range ks {
		fmt.Fprintf(&b, "%-17s", k.name)
	}
	b.WriteString("\n")
	rate := map[[2]string][2]float64{}
	for i, a := range ks {
		fmt.Fprintf(&b, "%-13s", a.name)
		for j, bk := range ks {
			if j < i {
				fmt.Fprintf(&b, "%-17s", "")
				continue
			}
			var ours, base int
			for s := range seeds {
				if punchOnce(uint64(s), a, bk, false).ok {
					ours++
				}
				if punchOnce(uint64(s), a, bk, true).ok {
					base++
				}
			}
			r := [2]float64{float64(ours) / seeds, float64(base) / seeds}
			rate[[2]string{a.name, bk.name}] = r
			fmt.Fprintf(&b, "%3.0f%% (%3.0f%%)      ", 100*r[0], 100*r[1])
		}
		b.WriteString("\n")
	}
	t.Log(b.String())

	for pair, r := range rate {
		if r[0] < r[1] {
			t.Errorf("%v: ours %.0f%% below baseline %.0f%%", pair, 100*r[0], 100*r[1])
		}
	}
	for _, want := range []struct {
		a, b string
		min  float64
	}{
		{"public", "random", 1}, {"cone", "cone", 1}, {"cone", "sequential", 0.95},
		{"cone", "cgnat-block", 0.95}, {"cgnat-block", "cgnat-block", 0.9},
	} {
		if r := rate[[2]string{want.a, want.b}]; r[0] < want.min {
			t.Errorf("%s↔%s: %.0f%%, want ≥%.0f%%", want.a, want.b, 100*r[0], 100*want.min)
		}
	}
}

func TestOfferRoundTrip(t *testing.T) {
	o := punch.Offer{
		Secret:     []byte("secret-secret-secret"),
		Candidates: []netip.AddrPort{netip.MustParseAddrPort("2.10.0.1:40000"), netip.MustParseAddrPort("[2001:db8::1]:5")},
		Profile:    punch.Profile{Mapping: punch.MappingDependent, Allocation: punch.AllocBlock, BlockLo: 2048, BlockHi: 4095},
	}
	back := roundTrip(o)
	if string(back.Secret) != string(o.Secret) || len(back.Candidates) != 2 || back.Candidates[1] != o.Candidates[1] || back.Profile != o.Profile {
		t.Fatalf("round trip: %+v", back)
	}
	if len(o.Marshal()) > 200 {
		t.Errorf("offer is %d bytes; it must fit easily in a signaling payload", len(o.Marshal()))
	}
}

// A dual-stack offer carries an IPv6 profile, and each family's session
// sees only its own candidates and profile; relays stay with IPv4.
func TestOfferFamilies(t *testing.T) {
	p6 := punch.Profile{Mapping: punch.MappingIndependent}
	o := punch.Offer{
		Secret:     []byte("secret-secret-secret"),
		Candidates: []netip.AddrPort{netip.MustParseAddrPort("2.10.0.1:40000"), netip.MustParseAddrPort("[2001:db8::1]:5")},
		Profile:    punch.Profile{Mapping: punch.MappingDependent, Allocation: punch.AllocRandom},
		Profile6:   &p6,
		Relays:     []netip.AddrPort{netip.MustParseAddrPort("2.176.0.9:6881")},
	}
	back := roundTrip(o)
	if back.Profile6 == nil || *back.Profile6 != p6 {
		t.Fatalf("IPv6 profile lost in transit: %+v", back.Profile6)
	}
	v4, v6 := back.Family(false), back.Family(true)
	if len(v4.Candidates) != 1 || !v4.Candidates[0].Addr().Is4() || v4.Profile != o.Profile || len(v4.Relays) != 1 {
		t.Fatalf("IPv4 family: %+v", v4)
	}
	if len(v6.Candidates) != 1 || v6.Candidates[0].Addr().Is4() || v6.Profile != p6 || len(v6.Relays) != 0 {
		t.Fatalf("IPv6 family: %+v", v6)
	}
	if string(v6.Secret) != string(o.Secret) {
		t.Fatal("IPv6 family lost the secret")
	}
	if back := roundTrip(punch.Offer{Profile: o.Profile}); back.Profile6 != nil {
		t.Fatal("an IPv4-only offer grew an IPv6 profile")
	}
}
