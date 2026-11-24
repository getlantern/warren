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
	n.offerAcked(t0, s, 0, true) // the first holder acks, the second stays silent
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
	n.offerAcked(t0.Add(400*time.Millisecond), s, 0, true) // the first holder acks at 400 ms, late but alive
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

// With both epochs' lookups running, the current epoch's record is
// preferred (a previous epoch's can be a restarted provider's old one, with
// a key it no longer holds): a previous record waits for the current lookup,
// is used if the current one finds nothing usable, and is cancelled by a
// usable current one.
func TestEpochLookupsPreferCurrent(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	x, _ := ecdh.X25519().NewPrivateKey(make([]byte, 32))
	rec := func(at int, token bool) *lookup {
		h := &cand{addr: addr(at)}
		if token {
			h.token = []byte("tok")
		}
		return &lookup{best: &MutableItem{V: encodeRecord([32]byte(x.PublicKey().Bytes()))}, holders: []*cand{h}}
	}
	setup := func(cur, prev *lookup) (*Node, *signalOp) {
		n := New(Config{ID: outsiderID(rng(100)), Rand: rng(101)})
		s := &signalOp{op: 3, priv: priv, payload: []byte("hi"), searching: 2, lookups: []*lookup{cur, prev}, cur: cur, triedPrev: true}
		n.signals = append(n.signals, s)
		n.lookups = append(n.lookups, cur, prev)
		return n, s
	}
	offeredTo := func(s *signalOp) netip.AddrPort {
		if s.offer == nil || len(s.holders) == 0 {
			return netip.AddrPort{}
		}
		return s.holders[0].addr
	}

	// A usable previous record arrives first: it waits, and the current wins.
	cur, prev := rec(1, true), rec(2, true)
	n, s := setup(cur, prev)
	n.recordFound(t0, s, prev)
	if s.offer != nil {
		t.Fatal("the previous epoch's record was used before the current lookup finished")
	}
	n.recordFound(t0, s, cur)
	if offeredTo(s) != addr(1) {
		t.Fatalf("offered via %v, want the current epoch's holder", offeredTo(s))
	}

	// The current record is unusable (no token): the previous one is used.
	cur, prev = rec(1, false), rec(2, true)
	n, s = setup(cur, prev)
	n.recordFound(t0, s, cur)
	if s.offer != nil || !slices.Contains(n.signals, s) {
		t.Fatal("an unusable current record ended or misdirected the signal while the previous lookup ran")
	}
	n.recordFound(t0, s, prev)
	if offeredTo(s) != addr(2) {
		t.Fatalf("offered via %v, want the previous epoch's holder", offeredTo(s))
	}

	// A usable current record cancels the previous lookup still running.
	cur, prev = rec(1, true), rec(2, true)
	n, s = setup(cur, prev)
	n.recordFound(t0, s, cur)
	if offeredTo(s) != addr(1) || !prev.finished || slices.Contains(n.lookups, prev) {
		t.Fatal("a usable current record didn't take the offer and cancel the previous lookup")
	}
}

// An offer that can't be sent (the transaction table is full) keeps its
// holder: with an offer already out, the rest wait for that offer's timers
// to try again; with none out, the signal fails with ErrBusy, not
// ErrNoAnswer.
func TestUnsentOfferKeepsHolders(t *testing.T) {
	n := New(Config{ID: outsiderID(rng(102)), Rand: rng(103)})
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	m, _ := NewMutable(priv, make([]byte, 32), 1, ImmutableValue([]byte("offer")))
	holders := []*cand{{addr: addr(1), token: []byte("tok")}, {addr: addr(2), token: []byte("tok")}, {addr: addr(3), token: []byte("tok")}}
	s := &signalOp{op: 4, offer: &m, holders: holders}
	n.signals = append(n.signals, s)
	n.cfg.MaxTransactions = len(n.txns) + 1 // room for one offer only
	n.fillOffers(t0, s)
	if len(s.tries) != 1 || s.tries[0].attempt != 0 || s.next != 1 {
		t.Fatalf("tries %d next %d: want the first holder's offer out and the rest kept", len(s.tries), s.next)
	}
	n.cfg.MaxTransactions = 512 // room again: the first offer's timer brings in the next
	n.signalTimeouts(t0.Add(2 * time.Second))
	if s.next < 2 {
		t.Fatalf("once there was room, next is %d: the kept holders weren't tried", s.next)
	}

	n2 := New(Config{ID: outsiderID(rng(104)), Rand: rng(105)})
	s2 := &signalOp{op: 5, offer: &m, holders: holders}
	n2.signals = append(n2.signals, s2)
	n2.cfg.MaxTransactions = 0 // nothing can be sent
	n2.fillOffers(t0, s2)
	_, events := n2.Drain()
	busy := false
	for _, e := range events {
		if f, ok := e.(SignalFailed); ok && f.Op == 5 && f.Err == ErrBusy {
			busy = true
		}
	}
	if !busy || slices.Contains(n2.signals, s2) {
		t.Fatal("a signal none of whose offers could be sent didn't fail with ErrBusy")
	}
}

// After the last holder is given up on, the signal stays open through that
// holder's answer window: its ack may have been lost while it relayed.
func TestSignalWaitsOutLastAnswerWindow(t *testing.T) {
	n := New(Config{ID: outsiderID(rng(104)), Rand: rng(105)})
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	m, _ := NewMutable(priv, make([]byte, 32), 1, ImmutableValue([]byte("offer")))
	s := &signalOp{op: 5, offer: &m, holders: []*cand{{addr: addr(1), token: []byte("tok")}}}
	n.signals = append(n.signals, s)
	n.fillOffers(t0, s)
	n.signalTimeouts(t0.Add(2 * time.Second)) // unacked past ShortTimeout: given up on
	if !slices.Contains(n.signals, s) {
		t.Fatal("the signal failed with the holder's answer window still open")
	}
	n.signalTimeouts(t0.Add(signalAttemptTimeout + time.Millisecond))
	if slices.Contains(n.signals, s) {
		t.Fatal("the signal outlived every answer window")
	}
}

// A record lookup that finishes while expire walks the transactions, and
// cancels the other epoch's lookup (deleting transactions expire has yet to
// visit), doesn't crash it.
func TestExpireSurvivesCancelledLookup(t *testing.T) {
	r := rng(106)
	n := New(Config{ID: outsiderID(r), Rand: rng(107)})
	start := time.Unix(epochOf(t0)*int64(RecordEpoch/time.Second), 0).Add(time.Minute)
	for i := 1; i <= 4; i++ {
		n.primary.heard(outsiderID(r), addr(i), start)
	}
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	if _, err := n.Signal(start, priv, [32]byte{1}, []byte("hi")); err != nil {
		t.Fatal(err)
	}
	s := n.signals[0]
	if len(s.lookups) != 2 {
		t.Fatalf("setup: %d record lookups, want both epochs'", len(s.lookups))
	}
	x, _ := ecdh.X25519().NewPrivateKey(make([]byte, 32))
	cur := s.lookups[0]
	cur.best = &MutableItem{V: encodeRecord([32]byte(x.PublicKey().Bytes()))}
	cur.holders = []*cand{{addr: addr(1), token: []byte("tok")}}
	for _, c := range cur.cands {
		if c.state != inflight {
			c.state = failed // its in-flight queries are all that keep it open
		}
	}
	n.Tick(start.Add(2 * time.Second)) // they lapse: cur finishes, cancelling the other
	if s.offer == nil {
		t.Fatal("setup: the current record didn't start the offer")
	}
}

// Across a signal's whole life, with holders that never answer, NextWakeup
// is never a time already past (the driver would spin).
func TestSignalWakeupNeverInPast(t *testing.T) {
	n := New(Config{ID: outsiderID(rng(108)), Rand: rng(109)})
	for range 8 {
		n.rtt.sample(50 * time.Millisecond) // offers go late at 250 ms
	}
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	m, _ := NewMutable(priv, make([]byte, 32), 1, ImmutableValue([]byte("offer")))
	s := &signalOp{op: 6, offer: &m}
	for i := 1; i <= 5; i++ {
		s.holders = append(s.holders, &cand{addr: addr(i), token: []byte("tok")})
	}
	n.signals = append(n.signals, s)
	n.nextMaint = t0.Add(time.Hour)
	n.fillOffers(t0, s)
	for now := t0; slices.Contains(n.signals, s); now = now.Add(50 * time.Millisecond) {
		if now.After(t0.Add(time.Minute)) {
			t.Fatal("the signal never ended")
		}
		n.Tick(now)
		n.Drain()
		if w := n.NextWakeup(); !w.After(now) {
			t.Fatalf("at %v NextWakeup is %v, not ahead", now.Sub(t0), w.Sub(t0))
		}
	}
}

// A holder that rejects the offer is dropped at once, not waited on.
func TestRejectedOfferDropsHolder(t *testing.T) {
	n := New(Config{ID: outsiderID(rng(110)), Rand: rng(111)})
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	m, _ := NewMutable(priv, make([]byte, 32), 1, ImmutableValue([]byte("offer")))
	s := &signalOp{op: 7, offer: &m, holders: []*cand{{addr: addr(1), token: []byte("tok")}}}
	n.signals = append(n.signals, s)
	n.fillOffers(t0, s)
	n.offerAcked(t0.Add(50*time.Millisecond), s, 0, false)
	if slices.Contains(n.signals, s) {
		t.Fatal("a signal whose only holder rejected the offer kept waiting")
	}
}
