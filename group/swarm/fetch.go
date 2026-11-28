package swarm

import (
	"container/heap"
	"errors"
	"math"
	"math/rand/v2"
	"slices"
	"time"
)

// Config tunes a Fetch; zero fields take the defaults below.
type Config struct {
	// PieceSize is the blob's piece size, for sizing pipelines.
	PieceSize uint32
	// QueueTime is how much of a peer's measured throughput to keep
	// requested: its pipeline holds QueueTime's worth of pieces (3s, as
	// libtorrent's request queue time). Any round trip shorter than it
	// is covered.
	QueueTime time.Duration
	// RequestTimeout is how long a request may stay outstanding before
	// it goes back to the other peers (15s); a peer found with any past
	// it earns a strike (one, however many): a peer holding pieces back
	// keeps them no longer, and is out after MaxStrikes. It may still
	// deliver one late.
	RequestTimeout time.Duration
	// MinDepth and MaxDepth bound a peer's pipeline (2 and 32 pieces; zero
	// or less takes the default). A
	// peer not yet measured gets MinDepth; a pipeline-limited one measures
	// its depth over its round trip, so QueueTime of that grows its
	// pipeline until its throughput, not the pipeline, is the limit.
	MinDepth, MaxDepth int
	// Window is how many pieces from the playhead are fetched in order
	// when streaming (8).
	Window uint32
	// MaxStrikes is how many strikes a peer may earn, by sending a piece
	// that fails verification or letting requests time out, before it's
	// out of the fetch (3): its requests and holdings go to the rest, and
	// SetPeer refuses it.
	MaxStrikes int
	// Now is the clock (time.Now); Rand breaks ties (seeded randomly).
	Now  func() time.Time
	Rand *rand.Rand
}

func (c Config) withDefaults() Config {
	if c.QueueTime == 0 {
		c.QueueTime = 3 * time.Second
	}
	if c.RequestTimeout == 0 {
		c.RequestTimeout = 15 * time.Second
	}
	if c.MinDepth <= 0 {
		c.MinDepth = 2
	}
	if c.MaxDepth <= 0 {
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

// A peer's throughput is the bytes it delivered over the time it was busy
// (had requests outstanding): measured once that spans minBusy, and both
// halved past maxBusy (twice QueueTime, longer than a distant peer's burst
// cycle, so a burst doesn't read as its rate), so it follows the peer's
// recent rate.
const (
	minBusy = 250 * time.Millisecond
	maxBusy = 6 * time.Second
)

// MaxPieces bounds a fetch's blob: a fetch keeps about 8 bytes a piece of
// accounting (content.MaxPieces is the same bound).
const MaxPieces = 1 << 24

var (
	// ErrTooLarge means a blob has more than MaxPieces pieces.
	ErrTooLarge = errors.New("swarm: blob too large")
	// ErrStruckOut means a peer earned MaxStrikes (failed pieces and
	// stalls), and is out of this fetch.
	ErrStruckOut = errors.New("swarm: peer struck out")
)

// Fetch is one blob's fetch from a set of peers, identified by P: an
// authenticated identity from a bounded set (a group's members), since a
// fetch remembers every peer that struck out. It isn't safe for concurrent
// use: one owner drives it, or callers serialize every call, reads
// included.
type Fetch[P comparable] struct {
	cfg   Config
	have  *Bitfield
	peers map[P]*peer
	// strikes outlive a peer's removal, so leaving and coming back doesn't
	// clear them.
	strikes map[P]int
	// avail counts, per piece, the peers holding it; asked how many peers
	// have a piece outstanding.
	avail, asked []int32
	// streaming, with the playhead's piece.
	streaming bool
	playhead  uint32
}

type peer struct {
	has *Bitfield
	out map[uint32]time.Time // pieces requested, and when
	// Throughput: bytes delivered over busy time, plus the busy spell
	// running since busySince while out isn't empty.
	bytes     float64
	busy      time.Duration
	busySince time.Time
	lastAt    time.Time // its last delivery
}

// ask records piece i outstanding at pr; drop removes it. Every request
// goes through both, so busy time counts exactly the spells pr had
// requests out, whatever ended them.
func (f *Fetch[P]) ask(pr *peer, i uint32) {
	now := f.cfg.Now()
	if len(pr.out) == 0 {
		pr.busySince = now
	}
	pr.out[i] = now
	f.asked[i]++
}

func (f *Fetch[P]) drop(pr *peer, i uint32) {
	if _, ok := pr.out[i]; !ok {
		return
	}
	delete(pr.out, i)
	f.asked[i]--
	if len(pr.out) == 0 {
		pr.busy += f.cfg.Now().Sub(pr.busySince)
	}
}

// rate is pr's throughput in bytes a second; 0 until it has been busy
// minBusy.
func (f *Fetch[P]) rate(pr *peer) float64 {
	busy := pr.busy
	if len(pr.out) > 0 {
		busy += f.cfg.Now().Sub(pr.busySince)
	}
	if busy < minBusy {
		return 0
	}
	return pr.bytes / busy.Seconds()
}

// NewFetch starts fetching a blob of n pieces, holding have already (nil
// for none; a partial download resumes from it). A have for another piece
// count is refused (ErrBitfield).
func NewFetch[P comparable](n uint32, have *Bitfield, cfg Config) (*Fetch[P], error) {
	if n > MaxPieces {
		return nil, ErrTooLarge
	}
	if have == nil {
		have = NewBitfield(n)
	}
	if have.Len() != n {
		return nil, ErrBitfield
	}
	return &Fetch[P]{cfg: cfg.withDefaults(), have: have.Clone(), peers: map[P]*peer{}, strikes: map[P]int{},
		avail: make([]int32, n), asked: make([]int32, n)}, nil
}

// Have is a copy of the pieces held.
func (f *Fetch[P]) Have() *Bitfield { return f.have.Clone() }

// Done reports whether every piece is held.
func (f *Fetch[P]) Done() bool { return f.have.Full() }

// SetPeer sets what peer p holds (a bitfield it sent), adding it if new;
// its outstanding requests stay. A bitfield for another piece count is
// refused (ErrBitfield), as is a peer that struck out (ErrStruckOut).
func (f *Fetch[P]) SetPeer(p P, has *Bitfield) error {
	if has.Len() != f.have.Len() {
		return ErrBitfield
	}
	if f.strikes[p] >= f.cfg.MaxStrikes {
		return ErrStruckOut
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

func (f *Fetch[P]) count(has *Bitfield, d int32) {
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

// RemovePeer drops peer p; its outstanding requests go back to the rest,
// those already past RequestTimeout as strikes, so leaving doesn't escape
// them.
func (f *Fetch[P]) RemovePeer(p P) {
	pr := f.peers[p]
	if pr == nil {
		return
	}
	f.overdue(p, pr)
	f.count(pr.has, -1)
	for i := range pr.out {
		f.drop(pr, i)
	}
	delete(f.peers, p)
}

// SetPlayhead streams from piece i: pieces within Window of it are fetched
// first, in order.
func (f *Fetch[P]) SetPlayhead(i uint32) { f.streaming, f.playhead = true, i }

// StopStreaming goes back to rarest first throughout.
func (f *Fetch[P]) StopStreaming() { f.streaming = false }

// depth is peer pr's pipeline: QueueTime of its measured throughput.
func (f *Fetch[P]) depth(pr *peer) int {
	d := f.cfg.MinDepth
	if r := f.rate(pr); r > 0 && f.cfg.PieceSize > 0 {
		// Rounded up, so a pipeline-limited peer at MinDepth 1 can grow.
		d = int(math.Ceil(r * f.cfg.QueueTime.Seconds() / float64(f.cfg.PieceSize)))
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
// rarest. Once every missing piece some peer holds is asked of someone
// (the endgame; pieces nobody holds don't hold it off), it steals:
// duplicates of the longest outstanding requests to others. First, every
// peer's requests past RequestTimeout go back to the rest.
func (f *Fetch[P]) Next(p P) []uint32 {
	f.expire() // first: it may strike p out
	pr := f.peers[p]
	if pr == nil {
		return nil
	}
	slots := f.depth(pr) - len(pr.out)
	if slots <= 0 {
		return nil
	}
	var picks []uint32
	ask := func(i uint32) {
		f.ask(pr, i)
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
	if slots == 0 {
		return picks
	}
	// One pass: unasked counts the missing pieces some peer holds that no
	// one is asked for (the endgame is when none are left), and rarest
	// keeps the slots rarest p can be asked for, ties falling randomly,
	// in a bounded heap rather than a list the size of the blob.
	rarest := &candidates{}
	unasked := 0
	for i := range n {
		if f.have.Has(i) || f.asked[i] != 0 || f.avail[i] == 0 {
			continue
		}
		unasked++
		if !f.wanted(pr, i) {
			continue
		}
		c := candidate{i: i, avail: f.avail[i], tie: f.cfg.Rand.Uint64()}
		if rarest.Len() < slots {
			heap.Push(rarest, c)
		} else if c.less((*rarest)[0]) {
			(*rarest)[0] = c
			heap.Fix(rarest, 0)
		}
	}
	picked := make([]candidate, rarest.Len())
	for k := len(picked) - 1; k >= 0; k-- {
		picked[k] = heap.Pop(rarest).(candidate)
	}
	for _, c := range picked {
		ask(c.i)
		unasked--
	}
	if slots > 0 && unasked == 0 {
		f.steal(p, pr, ask, slots)
	}
	return picks
}

// candidate is a piece to ask for, ordered rarest first, then by a random
// tie-breaker.
type candidate struct {
	i     uint32
	avail int32
	tie   uint64
}

func (c candidate) less(d candidate) bool {
	return c.avail < d.avail || c.avail == d.avail && c.tie < d.tie
}

// candidates is a max-heap of candidates: its top is the least rare kept,
// the one to drop for a rarer.
type candidates []candidate

func (h candidates) Len() int           { return len(h) }
func (h candidates) Less(a, b int) bool { return h[b].less(h[a]) }
func (h candidates) Swap(a, b int)      { h[a], h[b] = h[b], h[a] }
func (h *candidates) Push(x any)        { *h = append(*h, x.(candidate)) }
func (h *candidates) Pop() any {
	old := *h
	c := old[len(old)-1]
	*h = old[:len(old)-1]
	return c
}

// expire gives requests outstanding past RequestTimeout back to the rest,
// a strike for each peer that had any, and removes those that struck out.
func (f *Fetch[P]) expire() {
	var out []P
	for p, pr := range f.peers {
		if f.overdue(p, pr) {
			out = append(out, p)
		}
	}
	for _, p := range out {
		f.RemovePeer(p) // struck out
	}
}

// overdue drops pr's requests past RequestTimeout, and strikes p once if
// any were (one stall is one strike, however deep its pipeline), wherever
// that's noticed: Next, a delivery, a cancellation or removal. It reports
// whether p has struck out, for the caller to remove it.
func (f *Fetch[P]) overdue(p P, pr *peer) bool {
	cutoff := f.cfg.Now().Add(-f.cfg.RequestTimeout)
	late := false
	for i, at := range pr.out {
		if at.Before(cutoff) {
			f.drop(pr, i)
			late = true
		}
	}
	if late {
		f.strikes[p]++
	}
	return f.strikes[p] >= f.cfg.MaxStrikes
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
	// A failure is a strike against p whatever the index, and whether or
	// not p is still in the fetch.
	if !verified {
		f.strike(p)
	}
	pr := f.peers[p]
	if pr != nil && f.overdue(p, pr) {
		f.RemovePeer(p)
		pr = nil
	}
	if i >= f.have.Len() {
		return nil
	}
	if pr != nil {
		if _, ok := pr.out[i]; ok {
			now := f.cfg.Now()
			// Halve the history once time has moved past the last
			// delivery, with bytes and busy time both as of then, so the
			// pieces of one burst are weighed alike.
			if now.After(pr.lastAt) && pr.busy > maxBusy {
				pr.bytes, pr.busy = pr.bytes/2, pr.busy/2
			}
			if verified {
				pr.bytes += float64(size)
			}
			f.drop(pr, i)
			// The running spell too, or a pipeline kept full would never
			// decay.
			if len(pr.out) > 0 {
				pr.busy += now.Sub(pr.busySince)
				pr.busySince = now
			}
			pr.lastAt = now
		}
	}
	if !verified || f.have.Has(i) {
		return nil
	}
	f.have.Set(i)
	var out []P
	for q, qr := range f.peers {
		if f.overdue(q, qr) { // before the cancellation clears its request
			out = append(out, q)
		}
		if _, ok := qr.out[i]; ok {
			f.drop(qr, i)
			cancel = append(cancel, q)
		}
	}
	for _, q := range out {
		f.RemovePeer(q)
	}
	return cancel
}

// strike counts a strike against p, and removes it from the fetch once it
// has MaxStrikes.
func (f *Fetch[P]) strike(p P) {
	if f.strikes[p]++; f.strikes[p] >= f.cfg.MaxStrikes {
		f.RemovePeer(p) // its pieces and requests go to the rest
	}
}

// Outstanding is how many requests peer p has in flight.
func (f *Fetch[P]) Outstanding(p P) int {
	if pr := f.peers[p]; pr != nil {
		return len(pr.out)
	}
	return 0
}

// Strikes is how many strikes peer p has in this fetch (failed pieces and
// timed-out stalls), kept across its removal.
func (f *Fetch[P]) Strikes(p P) int { return f.strikes[p] }
