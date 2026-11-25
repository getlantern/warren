package memberlog

import (
	"errors"
	"slices"

	"github.com/getlantern/warren/group/keys"
	"github.com/getlantern/warren/group/roster"
)

var (
	// ErrForked means the author's log is forked: members keep the proof
	// and accept nothing more from it.
	ErrForked = errors.New("memberlog: log forked")
	// ErrPastCutoff means the author was removed and the entry isn't on the
	// chain ending at the head its remover recorded.
	ErrPastCutoff = errors.New("memberlog: entry past the removal cutoff")
	// ErrNotWriter means the roster doesn't let the author write a log: it
	// was never admitted, or it is a mirror.
	ErrNotWriter = errors.New("memberlog: author may not write a log")
	// ErrUnknownEpoch means the entry names no key-making roster operation.
	ErrUnknownEpoch = errors.New("memberlog: unknown epoch")
	// ErrWrongGroup means the entry belongs to another group.
	ErrWrongGroup = errors.New("memberlog: entry of another group")
)

// ForkProof is two entries the author signed that can't both be on one
// chain: two at one sequence number, or one whose Prev isn't the other.
type ForkProof struct{ A, B *Entry }

// Log is one author's log as a member holds it.
type Log struct {
	author  keys.PublicKey
	entries map[ID]*Entry
	bySeq   map[uint64][]ID
	fork    *ForkProof
	removed bool
	cutSeq  uint64
	cutHead ID
}

func newLog(author keys.PublicKey) *Log {
	return &Log{author: author, entries: map[ID]*Entry{}, bySeq: map[uint64][]ID{}}
}

// Fork returns the proof the log forked, or nil.
func (l *Log) Fork() *ForkProof { return l.fork }

// add stores e, checked against the log's chain. It reports whether e was
// new.
func (l *Log) add(e *Entry) (bool, error) {
	if l.entries[e.id] != nil {
		return false, nil
	}
	if l.removed {
		// Only the chain ending at the recorded head will be shown; other
		// entries at or below the cutoff are kept but never shown, and a
		// removed author's conflicting history isn't a fork that would
		// hide the entries it wrote before removal.
		if e.Seq > l.cutSeq || (e.Seq == l.cutSeq && e.id != l.cutHead) {
			return false, ErrPastCutoff
		}
		l.store(e)
		return true, nil
	}
	if l.fork != nil {
		return false, ErrForked
	}
	if others := l.bySeq[e.Seq]; len(others) > 0 {
		l.fork = &ForkProof{A: l.entries[others[0]], B: e}
		return false, ErrForked
	}
	if prev := l.one(e.Seq - 1); prev != nil && e.Prev != prev.id {
		l.fork = &ForkProof{A: prev, B: e}
		return false, ErrForked
	}
	if next := l.one(e.Seq + 1); next != nil && next.Prev != e.id {
		l.fork = &ForkProof{A: e, B: next}
		return false, ErrForked
	}
	l.store(e)
	return true, nil
}

func (l *Log) store(e *Entry) {
	l.entries[e.id] = e
	l.bySeq[e.Seq] = append(l.bySeq[e.Seq], e.id)
}

// one returns the entry at seq if there is exactly one.
func (l *Log) one(seq uint64) *Entry {
	if ids := l.bySeq[seq]; len(ids) == 1 {
		return l.entries[ids[0]]
	}
	return nil
}

// Entries returns the entries the app may see, in order: for a member, the
// unbroken chain from entry 1, stopping at a gap, or before the fork point
// of a forked log (which branch is the author's nobody can tell); for a
// removed author, the chain ending at the recorded head, once it is
// complete back to entry 1.
func (l *Log) Entries() []*Entry {
	if l.removed {
		if l.cutSeq == 0 {
			return nil
		}
		var chain []*Entry
		e := l.entries[l.cutHead]
		for e != nil {
			chain = append(chain, e)
			if e.Seq == 1 {
				slices.Reverse(chain)
				return chain
			}
			e = l.entries[e.Prev]
		}
		return nil // incomplete until sync fills the gap
	}
	var out []*Entry
	var prev ID
	for seq := uint64(1); ; seq++ {
		if l.fork != nil && seq >= min(l.fork.A.Seq, l.fork.B.Seq) {
			return out
		}
		e := l.one(seq)
		if e == nil || (seq > 1 && e.Prev != prev) {
			return out
		}
		out = append(out, e)
		prev = e.id
	}
}

// Head returns the last entry the app may see, or nil.
func (l *Log) Head() *Entry {
	es := l.Entries()
	if len(es) == 0 {
		return nil
	}
	return es[len(es)-1]
}

// cut applies a removal's cutoff and returns the entries that were visible
// and no longer are, for the app to withdraw.
func (l *Log) cut(seq uint64, head ID) []*Entry {
	if l.removed && l.cutSeq == seq && l.cutHead == head {
		return nil
	}
	before := l.Entries()
	l.removed, l.cutSeq, l.cutHead, l.fork = true, seq, head, nil
	for id, e := range l.entries {
		if e.Seq > seq || (e.Seq == seq && id != head) {
			delete(l.entries, id)
			l.bySeq[e.Seq] = slices.DeleteFunc(l.bySeq[e.Seq], func(x ID) bool { return x == id })
		}
	}
	after := map[ID]bool{}
	for _, e := range l.Entries() {
		after[e.id] = true
	}
	var gone []*Entry
	for _, e := range before {
		if !after[e.id] {
			gone = append(gone, e)
		}
	}
	return gone
}

// Set is every author's log in one group, checked against the roster.
type Set struct {
	group roster.ID
	logs  map[keys.PublicKey]*Log
}

// NewSet makes the logs of group.
func NewSet(group roster.ID) *Set {
	return &Set{group: group, logs: map[keys.PublicKey]*Log{}}
}

// Log returns author's log, or nil.
func (s *Set) Log(author keys.PublicKey) *Log { return s.logs[author] }

// Update applies the roster: a counting removal sets its author's cutoff
// from the head its remover recorded. It returns the entries withdrawn.
func (s *Set) Update(r *roster.Roster, f *roster.Result) []*Entry {
	var gone []*Entry
	for author, l := range s.logs {
		if rid, ok := f.Removed[author]; ok {
			rm := r.Op(rid)
			gone = append(gone, l.cut(rm.LogSeq, ID(rm.LogHead))...)
		}
	}
	return gone
}

// Add checks e against the roster and its author's log and stores it. It
// reports whether e was new.
func (s *Set) Add(e *Entry, r *roster.Roster, f *roster.Result) (bool, error) {
	if e.Group != s.group || r.Group() != s.group {
		return false, ErrWrongGroup
	}
	switch f.Roles[e.Author] {
	case roster.Member, roster.Admin, roster.Owner:
	default:
		if _, removed := f.Removed[e.Author]; !removed {
			return false, ErrNotWriter // never admitted, or a mirror
		}
	}
	if ep := r.Op(e.Epoch); ep == nil || (ep.Kind != roster.Genesis && ep.Kind != roster.Remove && ep.Kind != roster.Rekey) {
		return false, ErrUnknownEpoch
	}
	l := s.logs[e.Author]
	if l == nil {
		l = newLog(e.Author)
		s.logs[e.Author] = l
	}
	if rid, removed := f.Removed[e.Author]; removed && !l.removed {
		rm := r.Op(rid)
		l.cut(rm.LogSeq, ID(rm.LogHead))
	}
	return l.add(e)
}
