package dht

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/getlantern/warren/krpc"
)

// The short timeout follows measured round trips between its floor and the
// configured ceiling, and is the ceiling until enough replies are timed.
func TestAdaptiveShortTimeout(t *testing.T) {
	var r rttEstimator
	if got := r.shortTimeout(time.Second); got != time.Second {
		t.Fatalf("with no samples: %v, want the ceiling", got)
	}
	for range 20 {
		r.sample(100 * time.Millisecond)
	}
	if got := r.shortTimeout(time.Second); got < minShortTimeout || got > 400*time.Millisecond {
		t.Fatalf("steady 100 ms round trips give %v, want near the 250 ms floor", got)
	}
	for range 20 {
		r.sample(3 * time.Second)
	}
	if got := r.shortTimeout(time.Second); got != time.Second {
		t.Fatalf("slow round trips give %v, want the 1 s ceiling", got)
	}
}

// A caller offers to two holders at once, replaces one that doesn't ack
// in time with the next, and fails only when every holder is spent.
func TestParallelOffers(t *testing.T) {
	n := New(Config{ID: outsiderID(rng(90)), Rand: rng(91)})
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	m, err := NewMutable(priv, make([]byte, 32), 1, ImmutableValue([]byte("offer")))
	if err != nil {
		t.Fatal(err)
	}
	s := &signalOp{op: 1, offer: &m}
	for i := 1; i <= 3; i++ {
		s.holders = append(s.holders, &cand{addr: addr(i), token: []byte("tok")})
	}
	n.signals = append(n.signals, s)
	offersTo := func() []string {
		sends, _ := n.Drain()
		var to []string
		for _, snd := range sends {
			var q krpc.Msg
			if krpc.Unmarshal(snd.Data, &q) == nil && q.Q == "put" {
				to = append(to, snd.To.String())
			}
		}
		return to
	}
	n.fillOffers(t0, s)
	if got := offersTo(); len(got) != 2 || got[0] != addr(1).String() || got[1] != addr(2).String() {
		t.Fatalf("first offers went to %v, want the first two holders", got)
	}
	n.offerAcked(s, 0, true) // the first holder acks, the second stays silent
	n.signalTimeouts(t0.Add(time.Second + time.Millisecond))
	if got := offersTo(); len(got) != 1 || got[0] != addr(3).String() {
		t.Fatalf("after the second holder missed its ack, offers went to %v, want the third", got)
	}
	n.signalTimeouts(t0.Add(signalAttemptTimeout + 2*time.Second))
	_, events := n.Drain()
	failed := false
	for _, e := range events {
		if f, ok := e.(SignalFailed); ok && f.Op == 1 && f.Err == ErrNoAnswer {
			failed = true
		}
	}
	if !failed {
		t.Fatal("the signal didn't fail once every holder was spent")
	}
}

// Near an epoch's start a caller looks up the previous epoch's record at
// once; later in the epoch only the current one.
func TestPreviousEpochLookedUpNearBoundary(t *testing.T) {
	start := time.Unix(epochOf(t0)*int64(RecordEpoch/time.Second), 0)
	for _, tc := range []struct {
		at      time.Time
		lookups int
	}{
		{start.Add(5 * time.Minute), 2},
		{start.Add(30 * time.Minute), 1},
	} {
		r := rng(92)
		n := New(Config{ID: outsiderID(r), Rand: rng(93)})
		for i := 1; i <= 4; i++ {
			n.primary.heard(outsiderID(r), addr(i), tc.at)
		}
		priv := ed25519.NewKeyFromSeed(make([]byte, 32))
		if _, err := n.Signal(tc.at, priv, [32]byte{1}, []byte("hi")); err != nil {
			t.Fatal(err)
		}
		if got := len(n.lookups); got != tc.lookups {
			t.Fatalf("%v into the epoch: %d record lookups, want %d", tc.at.Sub(start), got, tc.lookups)
		}
	}
}

// A query past the adaptive short timeout stops counting toward alpha, so
// the lookup widens, but holds the lookup open until Config.ShortTimeout;
// past that it leaves the frontier, so a closer-looking dead node can't stop
// the lookup reaching the next candidate.
func TestSlowAndLapsedQueries(t *testing.T) {
	r := rng(94)
	n := New(Config{ID: outsiderID(r), Rand: rng(95), K: 2, Alpha: 1, MaxInflight: 4})
	for range 8 {
		n.rtt.sample(100 * time.Millisecond) // adaptive short timeout: the 250 ms floor
	}
	target := outsiderID(r)
	near := func(byteIdx int) krpc.NodeID {
		id := target
		id[byteIdx] ^= 0x80
		return id
	}
	ids := []krpc.NodeID{near(19), near(15), near(10)} // nearest to farthest
	for i, id := range ids[:2] {                       // the farthest arrives as a referral
		n.primary.heard(id, addr(i+1), t0)
	}
	op, err := n.FindNode(t0, target)
	if err != nil {
		t.Fatal(err)
	}
	queried := func() map[netip.AddrPort][]byte {
		sends, _ := n.Drain()
		out := map[netip.AddrPort][]byte{}
		for _, s := range sends {
			var m krpc.Msg
			if krpc.Unmarshal(s.Data, &m) == nil && m.Y == krpc.Query {
				out[s.To] = m.T
			}
		}
		return out
	}
	first := queried()
	if len(first) != 1 || first[addr(1)] == nil {
		t.Fatalf("alpha 1: first queries %v, want only the nearest", first)
	}
	// Past the adaptive timeout the nearest is slow: the lookup widens.
	n.Tick(t0.Add(300 * time.Millisecond))
	if got := queried(); got[addr(2)] == nil {
		t.Fatalf("after the nearest went slow, queries %v, want the next", got)
	}
	// The second answers at 400 ms, referring the farthest, which is outside
	// the K=2 frontier. The nearest is slow but not lapsed, so it still
	// holds the lookup open.
	resp := krpc.AppendMarshal(nil, &krpc.Msg{T: n.lastTID(addr(2)), Y: krpc.Response,
		R: krpc.Return{ID: ids[1], Nodes: []krpc.NodeInfo{{ID: ids[2], Addr: addr(3)}}}})
	n.HandlePacket(t0.Add(400*time.Millisecond), addr(2), resp)
	if done := lookupDone(n, op); done != nil {
		t.Fatalf("finished at 400 ms with a slow query still open: %+v", done)
	}
	// At 1 s the nearest lapses: it leaves the frontier, so the farthest
	// enters it and is queried rather than the lookup ending short.
	n.Tick(t0.Add(time.Second + time.Millisecond))
	if got := queried(); got[addr(3)] == nil {
		t.Fatalf("after the nearest lapsed, queries %v, want the next candidate", got)
	}
}

func lookupDone(n *Node, op OpID) *LookupDone {
	_, events := n.Drain()
	for _, e := range events {
		if d, ok := e.(LookupDone); ok && d.Op == op {
			return &d
		}
	}
	return nil
}

// lastTID returns the transaction ID of the query in flight to addr.
func (n *Node) lastTID(to netip.AddrPort) []byte {
	for tid, tx := range n.txns {
		if tx.to == to {
			return []byte{byte(tid >> 8), byte(tid)}
		}
	}
	return nil
}

// A holder that acks late, after the adaptive short timeout but before
// Config.ShortTimeout, brings in the next holder without being dropped.
func TestLateHolderStillRelays(t *testing.T) {
	n := New(Config{ID: outsiderID(rng(96)), Rand: rng(97)})
	for range 8 {
		n.rtt.sample(50 * time.Millisecond) // adaptive short timeout: 250 ms
	}
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	m, _ := NewMutable(priv, make([]byte, 32), 1, ImmutableValue([]byte("offer")))
	s := &signalOp{op: 2, offer: &m}
	for i := 1; i <= 4; i++ {
		s.holders = append(s.holders, &cand{addr: addr(i), token: []byte("tok")})
	}
	n.signals = append(n.signals, s)
	n.fillOffers(t0, s)
	n.Drain()
	n.signalTimeouts(t0.Add(300 * time.Millisecond)) // both late: two more holders
	if len(s.tries) != 4 {
		t.Fatalf("%d offers out after the first two went late, want 4", len(s.tries))
	}
	n.offerAcked(s, 0, true) // the first holder acks at 400 ms, late but alive
	n.signalTimeouts(t0.Add(time.Second + time.Millisecond))
	kept := false
	for _, tr := range s.tries {
		kept = kept || (tr.attempt == 0 && tr.acked)
	}
	if !kept {
		t.Fatal("a holder that acked late was dropped")
	}
	if !slices.Contains(n.signals, s) {
		t.Fatal("the signal failed with a holder still relaying")
	}
}

// A rebind forgets the old network's round trips.
func TestRebindResetsShortTimeout(t *testing.T) {
	n := New(Config{ID: outsiderID(rng(98)), Rand: rng(99)})
	for range 8 {
		n.rtt.sample(40 * time.Millisecond)
	}
	if n.shortTimeout() == n.cfg.ShortTimeout {
		t.Fatal("setup: the short timeout didn't adapt")
	}
	n.Rebound(t0)
	if got := n.shortTimeout(); got != n.cfg.ShortTimeout {
		t.Fatalf("after a rebind the short timeout is %v, want the %v ceiling until new round trips are timed", got, n.cfg.ShortTimeout)
	}
}

// With both epochs' lookups running, a record that can't be used (no holder
// gave a token) waits for the other lookup; a usable one cancels it.
func TestEpochLookupsCooperate(t *testing.T) {
	n := New(Config{ID: outsiderID(rng(100)), Rand: rng(101)})
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	x, _ := ecdh.X25519().NewPrivateKey(make([]byte, 32))
	rec := func(holders ...*cand) *lookup {
		return &lookup{best: &MutableItem{V: encodeRecord([32]byte(x.PublicKey().Bytes()))}, holders: holders}
	}
	unusable, usable := rec(&cand{addr: addr(1)}), rec(&cand{addr: addr(2), token: []byte("tok")})
	s := &signalOp{op: 3, priv: priv, payload: []byte("hi"), searching: 2, lookups: []*lookup{unusable, usable}}
	n.signals = append(n.signals, s)
	n.lookups = append(n.lookups, unusable, usable)
	n.recordFound(t0, s, unusable)
	if !slices.Contains(n.signals, s) || s.offer != nil {
		t.Fatal("an unusable record ended the signal while the other epoch's lookup ran")
	}
	other := &lookup{}
	s.searching++
	s.lookups = append(s.lookups, other)
	n.lookups = append(n.lookups, other)
	n.recordFound(t0, s, usable)
	if s.offer == nil {
		t.Fatal("a usable record didn't start the offer")
	}
	if !other.finished || slices.Contains(n.lookups, other) {
		t.Fatal("the other epoch's lookup kept running after the offer started")
	}
}
