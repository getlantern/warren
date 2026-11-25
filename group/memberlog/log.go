package memberlog

import (
	"errors"

	"github.com/getlantern/warren/group/keys"
	"github.com/getlantern/warren/group/roster"
)

var (
	// ErrForked means the author's log is forked: members keep the proof
	// and accept nothing more from it.
	ErrForked = errors.New("memberlog: log forked")
	// ErrPastCutoff means the author was removed and the entry is past the
	// head its remover recorded.
	ErrPastCutoff = errors.New("memberlog: entry past the removal cutoff")
	// ErrOffChain means the author was removed and the entry isn't (yet)
	// anchored to the chain from the recorded head: the head itself, or
	// the entry the lowest anchored one names as its previous. Sync sends a
	// removed author's log from the head down, so an entry refused this way
	// can be sent again once its successor has arrived.
	ErrOffChain = errors.New("memberlog: entry not anchored to the removal's head")
	// ErrTooFar means the entry is more than Window past the author's
	// contiguous chain: sync fills logs from the bottom, so it is sent
	// again once the gap closes.
	ErrTooFar = errors.New("memberlog: entry too far past the held chain")
	// ErrNotWriter means the roster doesn't let the author write a log: it
	// was never admitted, or it is (or was) a mirror.
	ErrNotWriter = errors.New("memberlog: author may not write a log")
	// ErrUnknownEpoch means the entry names no counting key-making roster
	// operation.
	ErrUnknownEpoch = errors.New("memberlog: unknown epoch")
	// ErrNoRoster means Add came before any Update gave the Set a fold.
	ErrNoRoster = errors.New("memberlog: no roster fold yet")
	// ErrWrongGroup means the entry belongs to another group.
	ErrWrongGroup = errors.New("memberlog: entry of another group")
)

// Window and MaxAhead bound what a member holds past an author's
// contiguous chain, in entries and in bytes, so nobody can make others
// store entries that are never shown. Sync fills logs from the bottom, so
// a refused entry (ErrTooFar) is sent again once the gap closes.
const (
	Window   = 1024
	MaxAhead = 4 << 20
)

// ForkProof is two entries the author signed that can't both be on one
// chain: two at one sequence number, or one whose Prev isn't the other.
type ForkProof struct{ A, B *Entry }

// Log is one author's log as a member holds it: at most one entry per
// sequence number.
type Log struct {
	author keys.PublicKey
	bySeq  map[uint64]*Entry
	top    uint64 // the visible chain is 1..top
	fork   *ForkProof
	// held and shown are the box bytes of every held entry and of the
	// visible ones, so what is held ahead of the chain costs nothing to
	// read however far past the window it lies.
	held, shown int
	// ok reports whether an entry may show under the roster now.
	ok func(*Entry) bool

	removed bool
	cutSeq  uint64
	cutHead ID
	// low is the lowest sequence number anchored to the recorded head
	// (cutSeq+1 while the head itself is missing).
	low uint64
}

func newLog(author keys.PublicKey, ok func(*Entry) bool) *Log {
	return &Log{author: author, bySeq: map[uint64]*Entry{}, ok: ok}
}

// Fork returns a copy of the proof the log forked, or nil.
func (l *Log) Fork() *ForkProof {
	if l.fork == nil {
		return nil
	}
	return &ForkProof{A: l.fork.A.clone(), B: l.fork.B.clone()}
}

// Entries returns the entries the app may see, in order: the unbroken,
// linked chain from entry 1, stopping before the fork point of a forked
// log (nobody can tell which branch is the author's) and, for a removed
// author, at the cutoff.
//
// They are copies, as are all entries a Log or Set hands out, so changing
// them can't reach the log.
func (l *Log) Entries() []*Entry {
	out := make([]*Entry, 0, l.top)
	for seq := uint64(1); seq <= l.top; seq++ {
		out = append(out, l.bySeq[seq].clone())
	}
	return out
}

// Head returns a copy of the last entry the app may see, or nil.
func (l *Log) Head() *Entry {
	if l.top == 0 {
		return nil
	}
	return l.bySeq[l.top].clone()
}

// limit is the highest sequence number the app may see: below a fork
// point, except where a removal's head has anchored the chain past it, and
// never past a removal's cutoff.
func (l *Log) limit() uint64 {
	lim := ^uint64(0)
	if l.fork != nil {
		point := min(l.fork.A.Seq, l.fork.B.Seq)
		if !l.removed || l.low > point {
			lim = point - 1
		}
	}
	if l.removed {
		lim = min(lim, l.cutSeq)
	}
	return lim
}

// retop recomputes the visible chain's end after a change at or below seq,
// appending to gone every still-held entry that leaves the app's view.
func (l *Log) retop(seq uint64, gone *[]*Entry) {
	old := l.top
	defer func() {
		for s := l.top + 1; s <= old; s++ {
			if e := l.bySeq[s]; e != nil {
				*gone = append(*gone, e)
				l.shown -= len(e.Box)
			}
		}
		for s := old + 1; s <= l.top; s++ {
			l.shown += len(l.bySeq[s].Box)
		}
	}()
	if seq <= l.top {
		l.top = seq - 1
	}
	l.top = min(l.top, l.limit())
	for l.top < l.limit() {
		next := l.bySeq[l.top+1]
		if next == nil || !l.ok(next) || (l.top > 0 && next.Prev != l.bySeq[l.top].id) {
			break
		}
		l.top++
	}
}

// ahead is the bytes of entries held past the visible chain.
func (l *Log) ahead() int { return l.held - l.shown }

// put stores e.
func (l *Log) put(e *Entry) {
	l.bySeq[e.Seq] = e
	l.held += len(e.Box)
}

// drop removes the entry at seq, reporting it in gone if it was visible.
func (l *Log) drop(seq uint64, gone *[]*Entry) {
	if e := l.bySeq[seq]; e != nil {
		if seq <= l.top {
			*gone = append(*gone, e)
			l.shown -= len(e.Box)
		}
		l.held -= len(e.Box)
		delete(l.bySeq, seq)
	}
}

// add stores e, checked against the log. It reports whether e was new, and
// appends to gone any visible entries that leave the app's view.
func (l *Log) add(e *Entry, gone *[]*Entry) (bool, error) {
	if old := l.bySeq[e.Seq]; old != nil && old.id == e.id {
		return false, nil
	}
	if l.removed {
		return l.addRemoved(e, gone)
	}
	if l.fork != nil {
		return false, ErrForked
	}
	// Conflicts first: fork evidence needs no new slot, so the budget
	// mustn't hide it.
	if old := l.bySeq[e.Seq]; old != nil {
		l.fork = &ForkProof{A: old, B: e}
	} else if prev := l.bySeq[e.Seq-1]; prev != nil && e.Prev != prev.id {
		l.fork = &ForkProof{A: prev, B: e}
	} else if next := l.bySeq[e.Seq+1]; next != nil && next.Prev != e.id {
		l.fork = &ForkProof{A: e, B: next}
	}
	if l.fork != nil {
		l.retop(l.top+1, gone)
		return false, ErrForked
	}
	// The entry that closes the gap is always taken: it only ever shrinks
	// what is held ahead.
	if e.Seq > l.top+1 && (e.Seq > l.top+Window || l.ahead()+len(e.Box) > MaxAhead) {
		return false, ErrTooFar
	}
	l.put(e)
	l.retop(e.Seq, gone)
	return true, nil
}

// trim drops what a live log holds past its bounds, highest first: after a
// lifted removal, a head's chain may have filled more than a live log
// holds ahead. Sync fetches what it drops again as the gap closes.
func (l *Log) trim() {
	var none []*Entry // nothing dropped here is visible
	for s := range l.bySeq {
		if s > l.top+Window {
			l.drop(s, &none)
		}
	}
	for s := l.top + Window; l.ahead() > MaxAhead && s > l.top; s-- {
		l.drop(s, &none)
	}
}

// addRemoved accepts a removed author's entry only when anchored to the
// recorded head, which keeps one entry per sequence number however many
// histories the author signs, and confirms or evicts the held entry below.
func (l *Log) addRemoved(e *Entry, gone *[]*Entry) (bool, error) {
	if e.Seq > l.cutSeq || (e.Seq == l.cutSeq && e.id != l.cutHead) {
		return false, ErrPastCutoff
	}
	anchored := e.Seq+1 == l.low && (e.Seq == l.cutSeq || l.bySeq[l.low].Prev == e.id)
	if !anchored {
		return false, ErrOffChain
	}
	if old := l.bySeq[e.Seq]; old != nil {
		l.drop(e.Seq, gone) // held from before the removal, off the head's chain
		l.retop(e.Seq, gone)
	}
	l.put(e)
	l.low = e.Seq
	l.anchorDown(gone)
	l.retop(e.Seq, gone)
	return true, nil
}

// anchorDown extends the anchored chain over held entries the lowest
// anchored one links to, and evicts the first one it contradicts.
func (l *Log) anchorDown(gone *[]*Entry) {
	for l.low > 1 {
		below := l.bySeq[l.low-1]
		if below == nil {
			return
		}
		if below.id != l.bySeq[l.low].Prev {
			l.drop(l.low-1, gone)
			l.retop(l.low-1, gone)
			return
		}
		l.low--
	}
}

// cut applies a removal's cutoff, or with removed false lifts one: the
// removal stopped counting.
func (l *Log) cut(removed bool, seq uint64, head ID, gone *[]*Entry) {
	if l.removed == removed && (!removed || (l.cutSeq == seq && l.cutHead == head)) {
		return
	}
	if !removed {
		// The author is a member again; what past the cutoff was dropped,
		// sync fills in again, unless the log is forked: a fork proof is
		// evidence the author signed two histories, whoever removed it.
		l.removed, l.cutSeq, l.cutHead, l.low = false, 0, ID{}, 0
		l.retop(l.top+1, gone)
		l.trim()
		return
	}
	// The fork proof stays: entries past the fork point show only once the
	// head's anchored chain covers them (see limit).
	l.removed, l.cutSeq, l.cutHead = true, seq, head
	for s, e := range l.bySeq {
		if s > seq || (s == seq && e.id != head) {
			l.drop(s, gone)
		}
	}
	l.low = seq + 1
	if seq > 0 && l.bySeq[seq] != nil {
		l.low = seq
		l.anchorDown(gone)
	}
	l.retop(1, gone) // after low: what shows past a fork point depends on it
}

// Set is every author's log in one group, checked against the roster.
type Set struct {
	group roster.ID
	logs  map[keys.PublicKey]*Log
	gone  []*Entry

	// Facts from the last fold seen, which every Add asks.
	fold     *roster.Result
	epochs   map[roster.ID]bool             // counting key-making ops
	lastRole map[keys.PublicKey]roster.Role // each key's last counting role
	cutoffs  map[keys.PublicKey]cutoff      // each removed key's cutoff
}

type cutoff struct {
	seq  uint64
	head ID
}

// NewSet makes the logs of group.
func NewSet(group roster.ID) *Set {
	return &Set{group: group, logs: map[keys.PublicKey]*Log{}}
}

// Log returns author's log, or nil.
func (s *Set) Log(author keys.PublicKey) *Log { return s.logs[author] }

// Withdrawn returns, and forgets, the entries the app had been shown and
// should withdraw: past a removal's cutoff, off its head's chain, or at or
// past a fork point.
func (s *Set) Withdrawn() []*Entry {
	g := make([]*Entry, len(s.gone))
	for i, e := range s.gone {
		g[i] = e.clone()
	}
	s.gone = nil
	return g
}

// writer reports whether the roster lets author write a log: admitted and
// not a mirror, or removed (under its cutoff) and not a mirror before.
func (s *Set) writer(author keys.PublicKey) bool {
	switch role := s.fold.Roles[author]; role {
	case roster.Member, roster.Admin, roster.Owner:
		return true
	}
	_, removed := s.cutoffs[author]
	return removed && s.lastRole[author] != roster.Mirror
}

// eligible reports whether e may show under the current fold: its author
// may write, and its epoch counts. A fold that changes either hides e and
// what follows it, and a later one can show them again.
func (s *Set) eligible(e *Entry) bool {
	return s.writer(e.Author) && s.epochs[e.Epoch]
}

// learn caches what Add needs from fold f.
func (s *Set) learn(f *roster.Result) {
	if s.fold == f {
		return
	}
	s.fold = f
	s.epochs = map[roster.ID]bool{}
	s.lastRole = map[keys.PublicKey]roster.Role{}
	s.cutoffs = map[keys.PublicKey]cutoff{}
	removing := map[roster.ID]bool{}
	for _, rid := range f.Removed {
		removing[rid] = true
	}
	for _, o := range f.Order {
		if !f.Counts[o.ID()] {
			continue
		}
		switch o.Kind {
		case roster.Genesis:
			s.epochs[o.ID()] = true
			s.lastRole[o.Author] = roster.Owner
		case roster.Rekey:
			s.epochs[o.ID()] = true
		case roster.Remove:
			s.epochs[o.ID()] = true
			if removing[o.ID()] {
				s.cutoffs[o.Target] = cutoff{seq: o.LogSeq, head: ID(o.LogHead)}
			}
		case roster.Add, roster.SetRole:
			s.lastRole[o.Target] = o.Role
		}
	}
}

// apply brings author's log in line with the roster: cut by its counting
// removal, or uncut if that removal no longer counts.
func (s *Set) apply(author keys.PublicKey, l *Log) {
	c, removed := s.cutoffs[author]
	l.cut(removed, c.seq, c.head, &s.gone)
}

// Update applies a new fold of the roster to every log, and Add checks
// against it from then on; entries leaving the app's view collect for
// Withdrawn. Pass the newest fold: the Set follows the one given last. A
// fold of another group is refused, leaving the Set as it was.
func (s *Set) Update(f *roster.Result) error {
	if !s.ours(f) {
		return ErrWrongGroup
	}
	s.learn(f)
	for author, l := range s.logs {
		s.apply(author, l)
		l.retop(1, &s.gone) // eligibility may have changed either way
		if !l.removed {
			l.trim() // what just left view is held ahead, within bounds
		}
	}
	return nil
}

// ours reports whether f folds this Set's group: its genesis is the op
// whose ID names the group.
func (s *Set) ours(f *roster.Result) bool {
	for _, o := range f.Order {
		if o.Kind == roster.Genesis {
			return o.ID() == s.group
		}
	}
	return false
}

// Add checks e against the last fold given to Update and its author's log,
// and stores it. It reports whether e was new; entries leaving the app's
// view collect for Withdrawn.
func (s *Set) Add(e *Entry) (bool, error) {
	// Entry's fields are exported, so verify and own what is stored, as
	// roster.Add does: a mutated or unsigned entry fails here.
	e, err := Decode(e.Encode())
	if err != nil {
		return false, err
	}
	if e.Group != s.group {
		return false, ErrWrongGroup
	}
	if s.fold == nil {
		return false, ErrNoRoster
	}
	if !s.writer(e.Author) {
		return false, ErrNotWriter // never admitted, or a mirror
	}
	// A removed author's log is filled top-down from the recorded head, so
	// an entry whose epoch stopped counting must still be taken to anchor
	// the eligible ones below it; it stays hidden (eligible), and anchoring
	// bounds what is held.
	if _, removed := s.cutoffs[e.Author]; !removed && !s.epochs[e.Epoch] {
		return false, ErrUnknownEpoch
	}
	l := s.logs[e.Author]
	if l == nil {
		l = newLog(e.Author, s.eligible)
		s.logs[e.Author] = l
	}
	s.apply(e.Author, l)
	return l.add(e, &s.gone)
}
