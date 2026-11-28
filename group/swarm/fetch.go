package swarm

import (
	"math/rand/v2"
	"slices"
	"time"
)

// Config tunes a Fetch; zero fields take the defaults below.
type Config struct {
	// PieceSize is the blob's piece size, for sizing pipelines.
	PieceSize uint32
	// TargetRTT is how much of a peer's measured throughput to keep in
	// flight: its pipeline holds TargetRTT's worth of pieces (1s).
	TargetRTT time.Duration
	// MinDepth and MaxDepth bound a peer's pipeline (2 and 32 pieces). A
	// peer not yet measured gets MinDepth.
	MinDepth, MaxDepth int
	// Window is how many pieces from the playhead are fetched in order
	// when streaming (8).
	Window uint32
	// MaxStrikes is how many pieces failing verification a peer may send
	// before it gets no more requests (3).
	MaxStrikes int
	// Now is the clock (time.Now); Rand breaks ties (seeded randomly).
	Now  func() time.Time
	Rand *rand.Rand
}

func (c Config) withDefaults() Config {
	if c.TargetRTT == 0 {
		c.TargetRTT = time.Second
	}
	if c.MinDepth == 0 {
		c.MinDepth = 2
	}
	if c.MaxDepth == 0 {
		c.MaxDepth = 32
	}
	if c.MaxDepth < c.MinDepth {
		c.MaxDepth = c.MinDepth
	}
	if c.Window == 0 {
		c.Window = 8
	}
	if c.MaxStrikes == 0 {
		c.MaxStrikes = 3
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Rand == nil {
		c.Rand = rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64()))
	}
	return c
}

// rateWeight is the weight of a new throughput sample in a peer's moving
// average.
const rateWeight = 0.3

// Fetch is one blob's fetch from a set of peers, identified by P.
type Fetch[P comparable] struct {
	cfg   Config
	have  *Bitfield
	peers map[P]*peer
	// avail counts, per piece, the peers holding it; asked how many peers
	// have a piece outstanding.
	avail, asked []int
	// streaming, with the playhead's piece.
	streaming bool
	playhead  uint32
}

type peer struct {
	has     *Bitfield
	out     map[uint32]time.Time // pieces requested, and when
	rate    float64              // bytes per second, a moving average; 0 unmeasured
	strikes int
}

// NewFetch starts fetching a blob of n pieces, holding have already (nil
// for none; a partial download resumes from it).
func NewFetch[P comparable](n uint32, have *Bitfield, cfg Config) *Fetch[P] {
	if have == nil {
		have = NewBitfield(n)
	}
	return &Fetch[P]{cfg: cfg.withDefaults(), have: have.Clone(), peers: map[P]*peer{},
		avail: make([]int, n), asked: make([]int, n)}
}

// Have is a copy of the pieces held.
func (f *Fetch[P]) Have() *Bitfield { return f.have.Clone() }

// Done reports whether every piece is held.
func (f *Fetch[P]) Done() bool { return f.have.Full() }

// SetPeer sets what peer p holds (a bitfield it sent), adding it if new;
// its outstanding requests stay. A bitfield for another piece count is
// refused (ErrBitfield).
func (f *Fetch[P]) SetPeer(p P, has *Bitfield) error {
	if has.Len() != f.have.Len() {
		return ErrBitfield
	}
	pr := f.peers[p]
	if pr == nil {
		pr = &peer{out: map[uint32]time.Time{}}
		f.peers[p] = pr
	} else {
		f.count(pr.has, -1)
	}
	pr.has = has.Clone()
	f.count(pr.has, +1)
	return nil
}

func (f *Fetch[P]) count(has *Bitfield, d int) {
	for i := range has.Len() {
		if has.Has(i) {
			f.avail[i] += d
		}
	}
}

// PeerHas records that peer p now holds piece i (an update after its
// bitfield).
func (f *Fetch[P]) PeerHas(p P, i uint32) {
	pr := f.peers[p]
	if pr == nil || i >= f.have.Len() || pr.has.Has(i) {
		return
	}
	pr.has.Set(i)
	f.avail[i]++
}

// RemovePeer drops peer p; its outstanding requests go back to the rest.
func (f *Fetch[P]) RemovePeer(p P) {
	pr := f.peers[p]
	if pr == nil {
		return
	}
	f.count(pr.has, -1)
	for i := range pr.out {
		f.asked[i]--
	}
	delete(f.peers, p)
}

// SetPlayhead streams from piece i: pieces within Window of it are fetched
// first, in order.
func (f *Fetch[P]) SetPlayhead(i uint32) { f.streaming, f.playhead = true, i }

// StopStreaming goes back to rarest first throughout.
func (f *Fetch[P]) StopStreaming() { f.streaming = false }

// depth is peer pr's pipeline: TargetRTT of its measured throughput.
func (f *Fetch[P]) depth(pr *peer) int {
	d := f.cfg.MinDepth
	if pr.rate > 0 && f.cfg.PieceSize > 0 {
		d = int(pr.rate * f.cfg.TargetRTT.Seconds() / float64(f.cfg.PieceSize))
	}
	return min(max(d, f.cfg.MinDepth), f.cfg.MaxDepth)
}

// wanted reports whether p could be asked for piece i: missing here, held
// by p, and not already asked of it.
func (f *Fetch[P]) wanted(pr *peer, i uint32) bool {
	_, out := pr.out[i]
	return !f.have.Has(i) && pr.has.Has(i) && !out
}

// Next returns the pieces to request from peer p now, filling its
// pipeline, and records them outstanding. Unrequested pieces come first:
// those within Window of the playhead in order when streaming, then the
// rarest. Once every missing piece is asked of someone (the endgame), it
// steals: duplicates of the longest outstanding requests to others.
func (f *Fetch[P]) Next(p P) []uint32 {
	pr := f.peers[p]
	if pr == nil || pr.strikes >= f.cfg.MaxStrikes {
		return nil
	}
	slots := f.depth(pr) - len(pr.out)
	if slots <= 0 {
		return nil
	}
	var picks []uint32
	ask := func(i uint32) {
		pr.out[i] = f.cfg.Now()
		f.asked[i]++
		picks = append(picks, i)
		slots--
	}
	n := f.have.Len()
	if f.streaming {
		for i := f.playhead; i < n && i-f.playhead < f.cfg.Window && slots > 0; i++ {
			if f.asked[i] == 0 && f.wanted(pr, i) {
				ask(i)
			}
		}
	}
	var fresh []uint32
	endgame := true
	for i := range n {
		if f.have.Has(i) {
			continue
		}
		if f.asked[i] == 0 {
			endgame = false
			if f.wanted(pr, i) {
				fresh = append(fresh, i)
			}
		}
	}
	// Rarest first; shuffled first so ties fall randomly.
	f.cfg.Rand.Shuffle(len(fresh), func(a, b int) { fresh[a], fresh[b] = fresh[b], fresh[a] })
	slices.SortStableFunc(fresh, func(a, b uint32) int { return f.avail[a] - f.avail[b] })
	for _, i := range fresh {
		if slots == 0 {
			break
		}
		ask(i)
	}
	if slots > 0 && endgame {
		f.steal(p, pr, ask, slots)
	}
	return picks
}

// steal asks p for pieces outstanding at other peers, longest outstanding
// first.
func (f *Fetch[P]) steal(p P, pr *peer, ask func(uint32), slots int) {
	type req struct {
		i  uint32
		at time.Time
	}
	oldest := map[uint32]time.Time{}
	for q, qr := range f.peers {
		if q == p {
			continue
		}
		for i, at := range qr.out {
			if t, ok := oldest[i]; (!ok || at.Before(t)) && f.wanted(pr, i) {
				oldest[i] = at
			}
		}
	}
	var reqs []req
	for i, at := range oldest {
		reqs = append(reqs, req{i, at})
	}
	slices.SortFunc(reqs, func(a, b req) int {
		if c := a.at.Compare(b.at); c != 0 {
			return c
		}
		return int(a.i) - int(b.i)
	})
	for _, r := range reqs[:min(slots, len(reqs))] {
		ask(r.i)
	}
}

// Received records piece i arriving from peer p, size bytes, and whether
// it verified against the blob's tree (the caller checks; only a verified
// piece is kept). A verified piece is held from now on, and the other
// peers it was asked of are returned, for the caller to cancel. A piece
// that failed is a strike against p and goes back to the rest.
func (f *Fetch[P]) Received(p P, i uint32, size int, verified bool) (cancel []P) {
	if i >= f.have.Len() {
		return nil
	}
	if pr := f.peers[p]; pr != nil {
		if at, ok := pr.out[i]; ok {
			delete(pr.out, i)
			f.asked[i]--
			if el := f.cfg.Now().Sub(at).Seconds(); verified && el > 0 {
				sample := float64(size) / el
				if pr.rate == 0 {
					pr.rate = sample
				} else {
					pr.rate += rateWeight * (sample - pr.rate)
				}
			}
		}
		if !verified {
			pr.strikes++
		}
	}
	if !verified || f.have.Has(i) {
		return nil
	}
	f.have.Set(i)
	for q, qr := range f.peers {
		if _, ok := qr.out[i]; ok {
			delete(qr.out, i)
			f.asked[i]--
			cancel = append(cancel, q)
		}
	}
	return cancel
}

// Outstanding is how many requests peer p has in flight.
func (f *Fetch[P]) Outstanding(p P) int {
	if pr := f.peers[p]; pr != nil {
		return len(pr.out)
	}
	return 0
}

// Strikes is how many pieces from peer p failed verification.
func (f *Fetch[P]) Strikes(p P) int {
	if pr := f.peers[p]; pr != nil {
		return pr.strikes
	}
	return 0
}
