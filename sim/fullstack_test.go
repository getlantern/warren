package sim

import (
	"crypto/ed25519"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/getlantern/warren/dht"
	"github.com/getlantern/warren/endpoint"
	"github.com/getlantern/warren/krpc"
	"github.com/getlantern/warren/natprobe"
	"github.com/getlantern/warren/punch"
)

type natType struct {
	name string
	cfg  NATConfig
	// want is what passive inference should conclude.
	want punch.Mapping
}

var phoneNATs = []natType{
	{"cone", NATConfig{Mapping: EndpointIndependentMapping, Filtering: AddressPortDependentFiltering, Alloc: PortPreserving}, punch.MappingIndependent},
	{"cgnat-block", NATConfig{Mapping: EndpointDependentMapping, Filtering: AddressDependentFiltering, Alloc: BlockRandomPorts, BlockLo: 34816, BlockHi: 34816 + 2047}, punch.MappingDependent},
	{"sequential", NATConfig{Mapping: EndpointDependentMapping, Filtering: AddressPortDependentFiltering, Alloc: SequentialPorts, Step: 1, Jitter: 2}, punch.MappingDependent},
	{"random", NATConfig{Mapping: EndpointDependentMapping, Filtering: AddressPortDependentFiltering, Alloc: RandomPorts}, punch.MappingDependent},
}

type fullWorld struct {
	s       *Sim
	routers []*Node
	phones  int
}

func newFullWorld(seed uint64, routers int) *fullWorld {
	w := &fullWorld{s: New(seed, start)}
	for i := range routers {
		a := netip.AddrPortFrom(netip.AddrFrom4([4]byte{2, byte(176 + i/200), byte(i), 7}), 6881)
		w.routers = append(w.routers, w.s.Add(a, true, member(w.s, a.Addr(), false)))
	}
	seeds := []netip.AddrPort{w.routers[0].Addr, w.routers[1].Addr}
	for i, n := range w.routers {
		w.s.RunUntil(start.Add(time.Duration(i) * 50 * time.Millisecond))
		w.s.Do(n, func(now time.Time) { n.DHT.Bootstrap(now, seeds) })
	}
	w.s.RunUntil(w.s.Now.Add(5 * time.Minute))
	return w
}

func member(s *Sim, ip netip.Addr, ro bool) dht.Config {
	var id krpc.NodeID
	for i := range id {
		id[i] = byte(s.Rand().Uint32())
	}
	return dht.Config{ID: farsi.Tag(krpc.SecureID(ip, id)), Community: &farsi, ReadOnly: ro}
}

// phone adds a read-only DHT node behind a NAT and bootstraps it.
func (w *fullWorld) phone(nt natType) *Node {
	w.phones++
	public := netip.AddrFrom4([4]byte{5, 120, byte(w.phones), 1})
	local := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 168, byte(w.phones), 10}), 6881)
	n := w.s.AddBehindNAT(public, local, nt.cfg, true, member(w.s, public, true))
	w.s.Do(n, func(now time.Time) { n.DHT.Bootstrap(now, []netip.AddrPort{w.routers[2].Addr, w.routers[3].Addr}) })
	w.s.RunUntil(w.s.Now.Add(30 * time.Second))
	return n
}

// inferred derives a NAT profile from the DHT socket's BEP 42 reflections,
// as endpoint does on a real phone.
func inferred(n *Node) punch.Profile {
	var obs []natprobe.Observation
	for _, r := range n.DHT.Reflections() {
		obs = append(obs, natprobe.Observation{Order: r.Order, Local: n.Local, Dest: r.From, Mapped: r.Mapped})
	}
	return endpoint.ProfileOf(natprobe.Analyze(n.Local, obs))
}

type connectResult struct {
	ok               bool
	relayed          bool
	took             time.Duration
	strategy         punch.Strategy
	callerProf, prov punch.Profile
	stage            string
}

// connect runs endpoint's flow: gather on a fresh data socket via DHT
// contacts, signal the offer, the provider gathers and answers, both punch.
func (w *fullWorld) connect(caller, provider *Node, providerKey [32]byte) connectResult {
	s := w.s
	res := connectResult{callerProf: inferred(caller), prov: inferred(provider), stage: "gather"}
	rng := rand.New(rand.NewPCG(s.Rand().Uint64(), 3))
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(rng.Uint32())
	}
	contacts := func(n *Node) []netip.AddrPort {
		var out []netip.AddrPort
		for _, c := range n.DHT.Contacts(3) {
			out = append(out, c.Addr)
		}
		return out
	}

	cs := s.Attach(caller, punch.New(punch.Config{Initiator: true, Secret: secret, Local: res.callerProf, Rand: rng, Relay: contacts(caller)[0]}))
	var ps *Session
	var incoming dht.Incoming
	var callerOffer punch.Offer
	var op dht.OpID
	started := s.Now
	var doneC, doneP bool

	s.OnEvent = func(n *Node, e dht.Event) {
		switch e := e.(type) {
		case dht.Incoming:
			if n != provider || ps != nil {
				return
			}
			res.stage = "provider gather"
			incoming = e
			callerOffer, _ = punch.UnmarshalOffer(e.Payload)
			ps = s.Attach(provider, punch.New(punch.Config{Local: res.prov, Rand: rand.New(rand.NewPCG(rng.Uint64(), 4))}))
			s.DoSession(ps, func(time.Time) { ps.Punch.Reflect(contacts(provider)) })
		case dht.Answered:
			if n == caller && e.Op == op {
				res.stage = "punch"
				answer, _ := punch.UnmarshalOffer(e.Payload)
				s.DoSession(cs, func(now time.Time) { cs.Punch.Start(now, answer) })
			}
		case dht.SignalFailed:
			if n == caller && e.Op == op {
				res.stage = "signal: " + e.Err.Error()
			}
		}
	}
	answered := false
	s.OnPunch = func(ss *Session, e punch.Event) {
		switch e := e.(type) {
		case punch.Reflected:
			if ss == ps && !answered {
				answered = true
				ans := ps.Punch.Offer([]netip.AddrPort{ps.LocalAddr(0)})
				s.Do(provider, func(now time.Time) { provider.DHT.Answer(now, incoming.Session, ans.Marshal()) })
				s.DoSession(ps, func(now time.Time) { ps.Punch.Start(now, callerOffer) })
			}
		case punch.Connected:
			if ss == cs {
				doneC, res.strategy, res.relayed = true, e.Strategy, e.Relayed
				res.took = s.Now.Sub(started)
			}
			if ss == ps {
				doneP = true
			}
		case punch.Failed:
			if ss == cs {
				res.strategy = e.Strategy
				res.stage = "punch: " + e.Err.Error()
			}
		}
	}

	s.DoSession(cs, func(time.Time) { cs.Punch.Reflect(contacts(caller)) })
	s.RunUntil(s.Now.Add(time.Second))
	offer := cs.Punch.Offer([]netip.AddrPort{cs.LocalAddr(0)})
	if len(offer.Candidates) < 2 {
		return res // no reflexive candidate gathered
	}
	res.stage = "signal"
	ck := key("caller")
	s.Do(caller, func(now time.Time) {
		op, _ = caller.DHT.Signal(now, ck, providerKey, offer.Marshal())
	})
	s.RunUntil(s.Now.Add(15 * time.Second))
	res.ok = doneC && doneP
	s.OnEvent, s.OnPunch = nil, nil
	return res
}

// TestFullStackThroughNATs runs DHT signaling and hole punching together
// between phones behind modeled NATs: record binding and keepalives through
// the provider's NAT, offers forwarded to it, passive NAT inference, and the
// punch itself.
func TestFullStackThroughNATs(t *testing.T) {
	pairs := [][2]int{{0, 0}, {0, 1}, {1, 1}, {0, 2}, {0, 3}, {2, 2}, {1, 3}}
	const seeds = 4
	var b strings.Builder
	fmt.Fprintf(&b, "\n%-24s %-8s %-8s %-16s %s\n", "provider ↔ caller", "success", "p50", "strategy", "failure stages")
	inferenceErrors := 0
	results := map[[2]int]int{}
	for _, p := range pairs {
		prov, call := phoneNATs[p[0]], phoneNATs[p[1]]
		ok := 0
		var took []time.Duration
		var strat punch.Strategy
		stages := map[string]int{}
		for seed := range seeds {
			w := newFullWorld(uint64(100*p[0]+10*p[1]+seed), 40)
			provider, caller := w.phone(prov), w.phone(call)
			pk := key(fmt.Sprint("provider ", seed))
			w.s.Do(provider, func(now time.Time) { provider.DHT.Listen(now, pk) })
			w.s.RunUntil(w.s.Now.Add(time.Minute))
			r := w.connect(caller, provider, pub(pk))
			if r.callerProf.Mapping != call.want || r.prov.Mapping != prov.want {
				inferenceErrors++
				t.Logf("inference: caller %s → %+v, provider %s → %+v", call.name, r.callerProf, prov.name, r.prov)
			}
			strat = r.strategy
			if r.ok {
				ok++
				took = append(took, r.took)
			} else {
				stages[r.stage]++
			}
		}
		results[p] = ok
		p50 := "-"
		if len(took) > 0 {
			p50 = took[len(took)/2].Round(10 * time.Millisecond).String()
		}
		fmt.Fprintf(&b, "%-24s %d/%d      %-8s %-16v %v\n", prov.name+" ↔ "+call.name, ok, seeds, p50, strat, stages)
	}
	t.Log(b.String())
	if inferenceErrors > 0 {
		t.Errorf("%d passive NAT inferences were wrong", inferenceErrors)
	}
	// With router relays, every pair connects: directly where it can, through
	// a relay otherwise.
	for _, p := range pairs {
		if results[p] < seeds-1 {
			t.Errorf("%s ↔ %s: %d/%d connected", phoneNATs[p[0]].name, phoneNATs[p[1]].name, results[p], seeds)
		}
	}
}

func pub(k ed25519.PrivateKey) [32]byte { return [32]byte(k.Public().(ed25519.PublicKey)) }
