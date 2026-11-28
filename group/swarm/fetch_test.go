package swarm

import (
	"errors"
	"math/rand/v2"
	"slices"
	"testing"
	"time"
)

const pieceSize = 1000

// clock is a fake clock.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func full(n uint32) *Bitfield {
	f := NewBitfield(n)
	for i := range n {
		f.Set(i)
	}
	return f
}

func set(n uint32, pieces ...uint32) *Bitfield {
	f := NewBitfield(n)
	for _, i := range pieces {
		f.Set(i)
	}
	return f
}

func newFetch(t testing.TB, n uint32, c *clock, cfg Config) *Fetch[string] {
	t.Helper()
	cfg.PieceSize = pieceSize
	cfg.Now = c.now
	cfg.Rand = rand.New(rand.NewPCG(1, 2))
	f, err := NewFetch[string](n, nil, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func setPeer(t testing.TB, f *Fetch[string], p string, has *Bitfield) {
	t.Helper()
	if err := f.SetPeer(p, has); err != nil {
		t.Fatal(err)
	}
}

// sim runs f against peers serving at rate bytes a second (0: never
// answers), one piece at a time each, until done or stuck. It returns the
// simulated time taken and whether it finished.
type simPeer struct {
	rate  float64
	queue []uint32
	busy  time.Time // when the piece being served completes
}

func sim(t testing.TB, f *Fetch[string], c *clock, peers map[string]*simPeer) (time.Duration, bool) {
	t.Helper()
	start := c.t
	names := slices.Sorted(func(yield func(string) bool) {
		for p := range peers {
			if !yield(p) {
				return
			}
		}
	})
	for steps := 0; !f.Done(); steps++ {
		if steps > 100000 {
			t.Fatal("simulation runaway")
		}
		for _, p := range names {
			sp := peers[p]
			for _, i := range f.Next(p) {
				if len(sp.queue) == 0 && sp.rate > 0 {
					sp.busy = c.t.Add(time.Duration(pieceSize / sp.rate * float64(time.Second)))
				}
				sp.queue = append(sp.queue, i)
			}
		}
		// The next piece to land.
		var next string
		for _, p := range names {
			sp := peers[p]
			if sp.rate > 0 && len(sp.queue) > 0 && (next == "" || sp.busy.Before(peers[next].busy)) {
				next = p
			}
		}
		if next == "" {
			return c.t.Sub(start), false
		}
		sp := peers[next]
		c.t = sp.busy
		i := sp.queue[0]
		sp.queue = sp.queue[1:]
		if len(sp.queue) > 0 {
			sp.busy = c.t.Add(time.Duration(pieceSize / sp.rate * float64(time.Second)))
		}
		for _, q := range f.Received(next, i, pieceSize, true) {
			qp := peers[q]
			if k := slices.Index(qp.queue, i); k >= 0 {
				qp.queue = slices.Delete(qp.queue, k, k+1)
			}
		}
	}
	return c.t.Sub(start), true
}

// TestFetchCompletes: peers with uneven holdings and speeds, whose union
// is the blob, fetch all of it.
func TestFetchCompletes(t *testing.T) {
	c := &clock{t: time.Unix(0, 0)}
	const n = 60
	f := newFetch(t, n, c, Config{})
	a, b := NewBitfield(n), NewBitfield(n)
	for i := range uint32(n) {
		if i%3 != 0 {
			a.Set(i)
		}
		if i%2 == 0 {
			b.Set(i)
		}
	}
	setPeer(t, f, "a", a)
	setPeer(t, f, "b", b)
	setPeer(t, f, "c", set(n, 3, 9, 15, 21, 27, 33, 39, 45, 51, 57))
	if _, ok := sim(t, f, c, map[string]*simPeer{"a": {rate: 20000}, "b": {rate: 5000}, "c": {rate: 1000}}); !ok {
		t.Fatalf("stuck with %d of %d pieces", f.Have().Count(), n)
	}
}

// TestRarestFirst: a peer holding everything is asked first for the
// pieces only it holds.
func TestRarestFirst(t *testing.T) {
	c := &clock{t: time.Unix(0, 0)}
	const n = 20
	f := newFetch(t, n, c, Config{MinDepth: 4})
	setPeer(t, f, "all", full(n))
	setPeer(t, f, "half", set(n, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9))
	for _, i := range f.Next("all") {
		if i < 10 {
			t.Fatalf("asked the full peer for piece %d, which two peers hold, before the rare ones", i)
		}
	}
}

// TestRarestTiesRandom: among equally rare pieces, two fetchers seeded
// differently start on different pieces.
func TestRarestTiesRandom(t *testing.T) {
	c := &clock{t: time.Unix(0, 0)}
	first := map[uint32]bool{}
	for seed := range uint64(8) {
		f, err := NewFetch[string](64, nil, Config{PieceSize: pieceSize, Now: c.now, Rand: rand.New(rand.NewPCG(seed, seed))})
		if err != nil {
			t.Fatal(err)
		}
		setPeer(t, f, "p", full(64))
		first[f.Next("p")[0]] = true
	}
	if len(first) < 3 {
		t.Fatalf("ties fell on only %d distinct first pieces over 8 fetchers", len(first))
	}
}

// TestPlayhead: streaming asks for the window from the playhead in order,
// before rarer pieces elsewhere.
func TestPlayhead(t *testing.T) {
	c := &clock{t: time.Unix(0, 0)}
	const n = 40
	f := newFetch(t, n, c, Config{MinDepth: 5, Window: 4})
	setPeer(t, f, "all", full(n))
	setPeer(t, f, "some", set(n, 10, 11, 12, 13)) // the playhead's pieces aren't rare
	f.SetPlayhead(10)
	got := f.Next("all")
	if len(got) != 5 || !slices.Equal(got[:4], []uint32{10, 11, 12, 13}) {
		t.Fatalf("streaming from 10 asked for %v", got)
	}
	if got[4] >= 10 && got[4] <= 13 {
		t.Fatalf("past the window, asked for %d", got[4])
	}
	f.StopStreaming()
	f2 := newFetch(t, n, c, Config{MinDepth: 4, Window: 4})
	setPeer(t, f2, "all", full(n))
	setPeer(t, f2, "some", set(n, 10, 11, 12, 13))
	f2.SetPlayhead(10)
	f2.StopStreaming()
	for _, i := range f2.Next("all") {
		if i >= 10 && i <= 13 {
			t.Fatalf("not streaming, asked for %d, which two peers hold", i)
		}
	}
}

// TestWorkStealing: a peer that never answers holds requests for the last
// pieces; once everything is asked of someone, the others steal them, and
// the fetch completes.
func TestWorkStealing(t *testing.T) {
	c := &clock{t: time.Unix(0, 0)}
	const n = 30
	f := newFetch(t, n, c, Config{})
	setPeer(t, f, "fast", full(n))
	setPeer(t, f, "stuck", full(n))
	if _, ok := sim(t, f, c, map[string]*simPeer{"fast": {rate: 10000}, "stuck": {rate: 0}}); !ok {
		t.Fatalf("stuck with %d of %d pieces: nothing stolen from the stalled peer", f.Have().Count(), n)
	}
}

// TestNoStealingBeforeEndgame: while unrequested pieces remain anywhere,
// a peer holding only pieces already asked of others gets no duplicates.
func TestNoStealingBeforeEndgame(t *testing.T) {
	c := &clock{t: time.Unix(0, 0)}
	const n = 10
	f := newFetch(t, n, c, Config{MinDepth: 2})
	setPeer(t, f, "a", full(n))
	a := f.Next("a")
	setPeer(t, f, "b", set(n, a...)) // b holds just what a was asked for
	if got := f.Next("b"); got != nil {
		t.Fatalf("before the endgame, b was given duplicates %v (a has %v)", got, a)
	}
}

// TestStealsOldestFirst: in the endgame, the longest outstanding request
// is stolen first.
func TestStealsOldestFirst(t *testing.T) {
	c := &clock{t: time.Unix(0, 0)}
	const n = 2
	f := newFetch(t, n, c, Config{MinDepth: 1, MaxDepth: 1})
	setPeer(t, f, "x", set(n, 1))
	setPeer(t, f, "y", set(n, 0))
	if got := f.Next("x"); !slices.Equal(got, []uint32{1}) {
		t.Fatalf("x asked for %v", got)
	}
	c.t = c.t.Add(time.Second)
	if got := f.Next("y"); !slices.Equal(got, []uint32{0}) {
		t.Fatalf("y asked for %v", got)
	}
	setPeer(t, f, "z", full(n))
	if got := f.Next("z"); !slices.Equal(got, []uint32{1}) {
		t.Fatalf("z stole %v, want the older request, piece 1", got)
	}
}

// TestCancelDuplicates: a piece that lands from one peer is cancelled at
// the others it was stolen to.
func TestCancelDuplicates(t *testing.T) {
	c := &clock{t: time.Unix(0, 0)}
	f := newFetch(t, 1, c, Config{})
	setPeer(t, f, "a", full(1))
	setPeer(t, f, "b", full(1))
	if got := f.Next("a"); !slices.Equal(got, []uint32{0}) {
		t.Fatalf("a asked for %v", got)
	}
	c.t = c.t.Add(time.Second)
	if got := f.Next("b"); !slices.Equal(got, []uint32{0}) {
		t.Fatalf("in the endgame, b asked for %v", got)
	}
	if cancel := f.Received("a", 0, pieceSize, true); !slices.Equal(cancel, []string{"b"}) {
		t.Fatalf("cancel %v", cancel)
	}
	if !f.Done() || f.Outstanding("b") != 0 {
		t.Fatal("not done, or b still has the piece outstanding")
	}
}

// TestPipelineDepth: a peer's pipeline follows its measured throughput,
// within bounds.
func TestPipelineDepth(t *testing.T) {
	c := &clock{t: time.Unix(0, 0)}
	const n = 200
	f := newFetch(t, n, c, Config{MinDepth: 2, MaxDepth: 16})
	setPeer(t, f, "p", full(n))
	first := f.Next("p")
	if len(first) != 2 {
		t.Fatalf("an unmeasured peer got %d requests", len(first))
	}
	c.t = c.t.Add(100 * time.Millisecond) // 10 pieces a second
	f.Received("p", first[0], pieceSize, true)
	if got := f.Outstanding("p") + len(f.Next("p")); got != 10 {
		t.Fatalf("at 10 pieces a second, a 1s pipeline of %d", got)
	}
	for range 10 { // everything outstanding lands a millisecond on: capped
		f.Next("p")
		c.t = c.t.Add(time.Millisecond)
		for i := range f.peers["p"].out {
			f.Received("p", i, pieceSize, true)
		}
	}
	if got := f.Outstanding("p") + len(f.Next("p")); got != 16 {
		t.Fatalf("a fast peer's pipeline of %d, want MaxDepth 16", got)
	}
}

// TestFailedPiece: a piece that fails verification goes back to the
// others, strikes its sender, and enough strikes stop requests to it.
func TestFailedPiece(t *testing.T) {
	c := &clock{t: time.Unix(0, 0)}
	const n = 10
	f := newFetch(t, n, c, Config{MaxStrikes: 2, MinDepth: 1})
	setPeer(t, f, "bad", full(n))
	setPeer(t, f, "good", full(n))
	i := f.Next("bad")[0]
	if cancel := f.Received("bad", i, pieceSize, false); cancel != nil || f.Have().Has(i) {
		t.Fatal("a failed piece was kept")
	}
	if f.Strikes("bad") != 1 {
		t.Fatal("no strike")
	}
	if got := f.Next("good"); !slices.Contains(got, i) {
		// i is unrequested again, and as rare as the rest: it must be
		// askable; drain good until it is asked.
		found := slices.Contains(got, i)
		for !found && len(got) > 0 {
			for _, j := range got {
				f.Received("good", j, pieceSize, true)
			}
			got = f.Next("good")
			found = slices.Contains(got, i)
		}
		if !found {
			t.Fatalf("piece %d never asked again", i)
		}
	}
	j := f.Next("bad")
	if len(j) == 0 {
		t.Fatal("one strike stopped requests")
	}
	f.Received("bad", j[0], pieceSize, false)
	if got := f.Next("bad"); got != nil {
		t.Fatalf("after MaxStrikes, asked for %v", got)
	}
}

// TestRemovePeer: a removed peer's outstanding pieces are asked of others,
// and it holds nothing toward rarity.
func TestRemovePeer(t *testing.T) {
	c := &clock{t: time.Unix(0, 0)}
	const n = 4
	f := newFetch(t, n, c, Config{MinDepth: 4})
	setPeer(t, f, "a", full(n))
	setPeer(t, f, "b", full(n))
	if got := f.Next("a"); len(got) != 4 {
		t.Fatalf("a asked for %v", got)
	}
	f.RemovePeer("a")
	got := f.Next("b")
	if len(got) != 4 {
		t.Fatalf("after a left, b asked for %v", got)
	}
	if f.avail[0] != 1 {
		t.Fatalf("availability %d after a left", f.avail[0])
	}
}

// TestResume: a fetch started from pieces on disk asks only for the rest.
func TestResume(t *testing.T) {
	c := &clock{t: time.Unix(0, 0)}
	const n = 8
	have := set(n, 0, 1, 2, 3, 4, 5)
	f, err := NewFetch[string](n, have, Config{PieceSize: pieceSize, Now: c.now, MinDepth: 8})
	if err != nil {
		t.Fatal(err)
	}
	setPeer(t, f, "p", full(n))
	got := f.Next("p")
	slices.Sort(got)
	if !slices.Equal(got, []uint32{6, 7}) {
		t.Fatalf("resuming asked for %v", got)
	}
	have.Set(6) // the caller's bitfield isn't shared
	if f.Have().Has(6) {
		t.Fatal("the fetch shares the caller's bitfield")
	}
}

// TestPeerHas: an update adds a piece to a peer's holdings and rarity.
func TestPeerHas(t *testing.T) {
	c := &clock{t: time.Unix(0, 0)}
	f := newFetch(t, 4, c, Config{MinDepth: 4})
	setPeer(t, f, "p", NewBitfield(4))
	if got := f.Next("p"); got != nil {
		t.Fatalf("asked a peer holding nothing for %v", got)
	}
	f.PeerHas("p", 2)
	f.PeerHas("p", 2)
	f.PeerHas("p", 9)
	if got := f.Next("p"); !slices.Equal(got, []uint32{2}) || f.avail[2] != 1 {
		t.Fatalf("after an update, asked for %v, availability %d", got, f.avail[2])
	}
	setPeer(t, f, "p", set(4, 3)) // a new bitfield replaces the old
	if f.avail[2] != 0 || f.avail[3] != 1 {
		t.Fatalf("after replacing p's bitfield, availability %v", f.avail)
	}
	if err := f.SetPeer("q", NewBitfield(5)); !errors.Is(err, ErrBitfield) {
		t.Fatalf("a bitfield for another piece count: %v", err)
	}
}

// TestResumeMismatch: a resume bitfield for another piece count is refused.
func TestResumeMismatch(t *testing.T) {
	for _, m := range []uint32{3, 5} {
		if _, err := NewFetch[string](4, NewBitfield(m), Config{}); !errors.Is(err, ErrBitfield) {
			t.Fatalf("a %d-piece resume for a 4-piece blob: %v", m, err)
		}
	}
}

// TestThroughputThroughLatency: a peer serving 100 pieces a second behind
// a 500ms round trip gets a pipeline deep enough to use it: back-to-back
// arrivals measure its rate, not each piece's round trip.
func TestThroughputThroughLatency(t *testing.T) {
	c := &clock{t: time.Unix(0, 0)}
	const n = 300
	f := newFetch(t, n, c, Config{})
	setPeer(t, f, "p", full(n))
	const service, rtt = 10 * time.Millisecond, 500 * time.Millisecond
	type arrival struct {
		at time.Time
		i  uint32
	}
	var arrivals []arrival
	var free time.Time // when the peer finishes what it's serving
	for steps := 0; !f.Done(); steps++ {
		if steps > 10*n {
			t.Fatal("runaway")
		}
		for _, i := range f.Next("p") {
			start := c.t.Add(rtt / 2)
			if free.After(start) {
				start = free
			}
			free = start.Add(service)
			arrivals = append(arrivals, arrival{free.Add(rtt / 2), i})
		}
		if len(arrivals) == 0 {
			t.Fatal("stuck")
		}
		a := arrivals[0]
		arrivals = arrivals[1:]
		c.t = a.at
		f.Received("p", a.i, pieceSize, true)
	}
	// 300 pieces at 100 a second is 3s plus the round trip; measuring each
	// piece's round trip kept the pipeline at 2, about 4 pieces a second.
	if took := c.t.Sub(time.Unix(0, 0)); took > 10*time.Second {
		t.Fatalf("300 pieces took %v", took)
	}
}

// TestEndgameIgnoresUnavailable: a piece nobody holds doesn't keep a
// stalled peer's piece from being stolen.
func TestEndgameIgnoresUnavailable(t *testing.T) {
	c := &clock{t: time.Unix(0, 0)}
	const n = 3
	f := newFetch(t, n, c, Config{MinDepth: 1, MaxDepth: 1})
	setPeer(t, f, "stuck", set(n, 0))
	if got := f.Next("stuck"); !slices.Equal(got, []uint32{0}) {
		t.Fatalf("stuck asked for %v", got)
	}
	setPeer(t, f, "good", set(n, 0, 1))
	got := f.Next("good")
	if !slices.Equal(got, []uint32{1}) {
		t.Fatalf("good asked for %v", got)
	}
	f.Received("good", 1, pieceSize, true)
	if got := f.Next("good"); !slices.Equal(got, []uint32{0}) {
		t.Fatalf("with piece 2 held by no one, good stole %v, want 0", got)
	}
}

// TestStrikesSurviveRemoval: a peer that leaves and comes back keeps its
// strikes.
func TestStrikesSurviveRemoval(t *testing.T) {
	c := &clock{t: time.Unix(0, 0)}
	f := newFetch(t, 4, c, Config{MaxStrikes: 1, MinDepth: 1})
	setPeer(t, f, "bad", full(4))
	f.Received("bad", f.Next("bad")[0], pieceSize, false)
	f.RemovePeer("bad")
	setPeer(t, f, "bad", full(4))
	if got := f.Next("bad"); got != nil || f.Strikes("bad") != 1 {
		t.Fatalf("back after its strike, asked for %v with %d strikes", got, f.Strikes("bad"))
	}
}
