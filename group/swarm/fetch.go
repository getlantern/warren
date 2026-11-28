package swarm

import (
	"errors"
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
	// peer starts at MinDepth, doubling as it shows it can fill more (slow
	// start).
	MinDepth, MaxDepth int
	// Window is how many pieces from the playhead are fetched in order
	// when streaming (8).
	Window uint32
	// MaxStrikes is how many pieces failing verification a peer may send
	// before it's out of the fetch (3): its requests and holdings go to
	// the rest, and SetPeer refuses it.
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

// A peer's throughput is the bytes it delivered over the time it was busy
// (had requests outstanding): measured once that spans minBusy, and both
// halved past maxBusy, so it follows the peer's recent rate.
const (
	minBusy = 250 * time.Millisecond
	maxBusy = 2 * time.Second
)

// MaxPieces bounds a fetch's blob: a fetch keeps about 8 bytes a piece of
// accounting (content.MaxPieces is the same bound).
const MaxPieces = 1 << 24

var (
	// ErrTooLarge means a blob has more than MaxPieces pieces.
	ErrTooLarge = errors.New("swarm: blob too large")
	// ErrStruckOut means a peer sent MaxStrikes pieces that failed
	// verification, and is out of this fetch.
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
	// allBytes and allBusy are the same, never halved, for measuring
	// slow start's phases.
	allBytes float64
	allBusy  time.Duration
	// Slow start: a measured rate only shows what the pipeline allowed,
	// so while doubling it keeps raising the rate (slowStart), the
	// pipeline doubles (ssDepth) each time it delivers a full pipeline's
	// worth (ssCount). Each phase's rate is measured from where it began
	// (ssBytes, ssBusy) against the last phase's (ssRate).
	slowStart bool
	ssDepth   int
	ssCount   int
	ssRate    float64
	ssBytes   float64
	ssBusy    time.Duration
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
		d := f.cfg.Now().Sub(pr.busySince)
		pr.busy += d
		pr.allBusy += d
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
		pr = &peer{out: map[uint32]time.Time{}, slowStart: true, ssDepth: f.cfg.MinDepth}
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

// RemovePeer drops peer p; its outstanding requests go back to the rest.
func (f *Fetch[P]) RemovePeer(p P) {
	pr := f.peers[p]
	if pr == nil {
		return
	}
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

// depth is peer pr's pipeline: TargetRTT of its measured throughput.
func (f *Fetch[P]) depth(pr *peer) int {
	d := f.cfg.MinDepth
	if r := f.rate(pr); r > 0 && f.cfg.PieceSize > 0 {
		d = int(r * f.cfg.TargetRTT.Seconds() / float64(f.cfg.PieceSize))
	}
	if pr.slowStart {
		d = max(d, pr.ssDepth)
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
// duplicates of the longest outstanding requests to others.
func (f *Fetch[P]) Next(p P) []uint32 {
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
	// unasked counts the missing pieces some peer holds that no one is
	// asked for: the endgame is when none are left.
	var fresh []uint32
	unasked := 0
	for i := range n {
		if f.have.Has(i) {
			continue
		}
		if f.asked[i] == 0 && f.avail[i] > 0 {
			unasked++
			if f.wanted(pr, i) {
				fresh = append(fresh, i)
			}
		}
	}
	// Rarest first; shuffled first so ties fall randomly.
	f.cfg.Rand.Shuffle(len(fresh), func(a, b int) { fresh[a], fresh[b] = fresh[b], fresh[a] })
	slices.SortStableFunc(fresh, func(a, b uint32) int { return int(f.avail[a]) - int(f.avail[b]) })
	for _, i := range fresh {
		if slots == 0 {
			break
		}
		ask(i)
		unasked--
	}
	if slots > 0 && unasked == 0 {
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
		if _, ok := pr.out[i]; ok {
			if verified {
				pr.bytes += float64(size)
				pr.allBytes += float64(size)
			}
			f.drop(pr, i)
			// The running spell too, or a pipeline kept full would never
			// decay.
			if len(pr.out) > 0 {
				now := f.cfg.Now()
				d := now.Sub(pr.busySince)
				pr.busy += d
				pr.allBusy += d
				pr.busySince = now
			}
			if pr.busy > maxBusy {
				pr.bytes, pr.busy = pr.bytes/2, pr.busy/2
			}
			if verified && pr.slowStart {
				f.slowStart(pr)
			}
		}
		if !verified {
			if f.strikes[p]++; f.strikes[p] >= f.cfg.MaxStrikes {
				f.RemovePeer(p) // its pieces and requests go to the rest
			}
		}
	}
	if !verified || f.have.Has(i) {
		return nil
	}
	f.have.Set(i)
	for q, qr := range f.peers {
		if _, ok := qr.out[i]; ok {
			f.drop(qr, i)
			cancel = append(cancel, q)
		}
	}
	return cancel
}

// slowStart doubles pr's pipeline each time it delivers a full one, while
// each doubling raises its rate by slowStartGain: each phase's rate is
// measured from where the phase began, so a slow start to a peer's
// deliveries doesn't make later ones look like gains. A pipeline-limited
// peer gains with each doubling, whatever its round trip; a slow one
// stops gaining, and then the pipeline follows its measured rate alone.
func (f *Fetch[P]) slowStart(pr *peer) {
	if pr.ssCount++; pr.ssCount < pr.ssDepth {
		return
	}
	pr.ssCount = 0
	busy := pr.allBusy - pr.ssBusy
	if busy <= 0 {
		return
	}
	r := (pr.allBytes - pr.ssBytes) / busy.Seconds()
	if pr.ssRate > 0 && r < pr.ssRate*slowStartGain || pr.ssDepth >= f.cfg.MaxDepth {
		pr.slowStart = false
		return
	}
	pr.ssDepth, pr.ssRate = min(2*pr.ssDepth, f.cfg.MaxDepth), r
	pr.ssBytes, pr.ssBusy = pr.allBytes, pr.allBusy
}

// slowStartGain is the rise in rate a doubling must bring to keep doubling.
const slowStartGain = 1.1

// Outstanding is how many requests peer p has in flight.
func (f *Fetch[P]) Outstanding(p P) int {
	if pr := f.peers[p]; pr != nil {
		return len(pr.out)
	}
	return 0
}

// Strikes is how many pieces from peer p failed verification in this
// fetch, kept across its removal.
func (f *Fetch[P]) Strikes(p P) int { return f.strikes[p] }
