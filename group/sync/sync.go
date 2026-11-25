// Package sync is what two members of a group exchange when a session
// opens (docs/groups-design.md, *Sessions*): the roster operations each
// lacks, then log heads and the entries each lacks. It is a state machine
// with no networking: the caller carries its messages over a session, in
// order, and the simulator drives two of them in-process.
package sync

import (
	"errors"
	"fmt"
	"slices"

	"github.com/getlantern/warren/group/keys"
	"github.com/getlantern/warren/group/memberlog"
	"github.com/getlantern/warren/group/roster"
)

const (
	// Budget bounds the box bytes in one batch of entries. Every entry
	// fits, so a batch always makes progress.
	Budget = 256 << 10
	// MaxBatch bounds the entries in one batch.
	MaxBatch = 64
)

// opsChunk is the operation bytes one Ops message carries, past which it
// splits; tests lower it. A single larger operation goes alone.
var opsChunk = 1 << 20

// haveChunk is the IDs one Have message carries; tests lower it.
var haveChunk = 16384

// ErrProtocol means the peer sent a message out of turn, or one that
// doesn't answer what was asked.
var ErrProtocol = errors.New("sync: protocol violation")

// Sync is one side of one session's exchange. It is not safe for
// concurrent use.
type Sync struct {
	r    *roster.Roster
	logs *memberlog.Set

	gotHave  bool
	opsDone  bool               // the peer's operations are all in, and logs updated
	logsDone bool               // the peer's log heads are all in
	theirs   map[roster.ID]bool // operations the peer holds, among this side's
	peer     map[keys.PublicKey]LogHead
	wants    map[keys.PublicKey]Want // asked and not yet answered
	walking  map[keys.PublicKey]bool // walking down a peer's branch of a fork
	stopped  map[keys.PublicKey]bool // nothing more from this peer
	sentBye  bool
	gotBye   bool
	err      error
}

// New makes one side of an exchange over r and logs, which it updates as
// operations and entries arrive. logs must be r's group's.
func New(r *roster.Roster, logs *memberlog.Set) *Sync {
	return &Sync{
		r: r, logs: logs,
		theirs:  map[roster.ID]bool{},
		peer:    map[keys.PublicKey]LogHead{},
		wants:   map[keys.PublicKey]Want{},
		walking: map[keys.PublicKey]bool{},
		stopped: map[keys.PublicKey]bool{},
	}
}

// Start returns the first messages to send.
func (s *Sync) Start() []Message {
	ids := s.r.IDs()
	var out []Message
	for len(ids) > haveChunk {
		out = append(out, Have{IDs: ids[:haveChunk], More: true})
		ids = ids[haveChunk:]
	}
	return append(out, Have{IDs: ids})
}

// Done reports whether this side has taken everything the peer offered.
// The peer may still be asking, and messages this side has returned may
// still be on their way: the session ends at Finished, not Done.
func (s *Sync) Done() bool { return s.err == nil && s.opsDone && s.logsDone && len(s.wants) == 0 }

// Finished reports whether the exchange is over: this side is done and
// has said so, and so has the peer. Streams are ordered, so everything
// either side sent (a fork proof found late, say) has arrived; the session
// can close.
func (s *Sync) Finished() bool { return s.Done() && s.sentBye && s.gotBye }

// Handle takes the peer's next message and returns the messages to send
// in reply. After an error the exchange is over: every later call returns
// it.
func (s *Sync) Handle(m Message) ([]Message, error) {
	if s.err != nil {
		return nil, s.err
	}
	out, err := s.handle(m)
	if err != nil {
		s.err = err
		return nil, err
	}
	if s.Done() && !s.sentBye {
		s.sentBye = true
		out = append(out, Bye{}) // after everything this side found
	}
	return out, nil
}

func violation(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrProtocol}, a...)...)
}

func (s *Sync) handle(m Message) ([]Message, error) {
	switch m := m.(type) {
	case Have:
		if s.gotHave {
			return nil, violation("have twice")
		}
		for _, id := range m.IDs {
			if s.r.Has(id) { // the rest are the peer's to send
				s.theirs[id] = true
			}
		}
		if m.More {
			return nil, nil
		}
		s.gotHave = true
		return s.missingOps(), nil
	case Ops:
		if !s.gotHave || s.opsDone {
			return nil, violation("operations out of turn")
		}
		for _, o := range m.Ops {
			if _, err := s.r.Add(o); err != nil {
				return nil, err
			}
		}
		if m.More {
			return nil, nil
		}
		f, err := s.r.Fold()
		if err != nil {
			return nil, err
		}
		if err := s.logs.Update(f); err != nil {
			return nil, err
		}
		s.opsDone = true
		return s.logHeads(), nil
	case Fork:
		if !s.opsDone || m.A.Author != m.B.Author {
			return nil, violation("fork proof out of turn or of two authors")
		}
		// A proof for a log this side wouldn't take, or not a fork, is
		// ignored: the peer's roster is merged, so that's its own state.
		_, _ = s.logs.AddFork(&memberlog.ForkProof{A: m.A, B: m.B})
		return nil, nil
	case Logs:
		if !s.opsDone || s.logsDone {
			return nil, violation("log heads out of turn")
		}
		for _, h := range m.Heads {
			// Only logs this side holds or would take: the roster bounds them.
			if _, _, done := s.logs.Next(h.Author); !done || s.logs.Log(h.Author) != nil {
				s.peer[h.Author] = h
			}
		}
		if m.More {
			return nil, nil
		}
		s.logsDone = true
		var out []Message
		for _, a := range sortedKeys(s.peer) {
			out = append(out, s.start(a)...)
		}
		return out, nil
	case Want:
		if !s.opsDone || s.gotBye {
			return nil, violation("want before the roster is merged, or after bye")
		}
		return []Message{Entries{Author: m.Author, Entries: s.logs.Serve(m.Author, m.Seq, m.Down, Budget, MaxBatch)}}, nil
	case Entries:
		return s.entries(m)
	case Bye:
		if s.gotBye || !s.opsDone {
			return nil, violation("bye out of turn")
		}
		s.gotBye = true
		return nil, nil
	}
	return nil, violation("unknown message")
}

// missingOps returns every operation this side holds that the peer
// doesn't, parents first, split to fit messages.
func (s *Sync) missingOps() []Message {
	var out []Message
	cur, size := Ops{}, 0
	for _, id := range s.r.IDs() {
		if s.theirs[id] || id == s.r.Group() {
			continue
		}
		o := s.r.Op(id)
		n := len(o.Encode()) + 16
		if size+n > opsChunk && len(cur.Ops) > 0 {
			cur.More = true
			out = append(out, cur)
			cur, size = Ops{}, 0
		}
		cur.Ops = append(cur.Ops, o)
		size += n
	}
	return append(out, cur)
}

// logHeads returns this side's fork proofs and log heads, split to fit
// messages.
func (s *Sync) logHeads() []Message {
	var out []Message
	cur := Logs{}
	for _, a := range s.logs.Authors() {
		l := s.logs.Log(a)
		if p := l.Fork(); p != nil {
			out = append(out, Fork{A: p.A, B: p.B})
		}
		h := LogHead{Author: a}
		if e := l.Head(); e != nil {
			h.Top, h.ID = e.Seq, e.ID()
		}
		if len(cur.Heads) == 4096 {
			cur.More = true
			out = append(out, cur)
			cur = Logs{}
		}
		cur.Heads = append(cur.Heads, h)
	}
	return append(out, cur)
}

// start decides what to ask for of a's log once the peer's heads are in.
// A peer head that differs from the entry this side shows at that sequence
// number is another branch of a fork: walk down the peer's branch to where
// it parts from this one.
func (s *Sync) start(a keys.PublicKey) []Message {
	h := s.peer[a]
	// A removed author's log fills only from its recorded head down, so it
	// never walks: its branches are settled by the head's chain.
	if _, down, _ := s.logs.Next(a); !down {
		if mine := s.logs.At(a, h.Top); mine != nil && mine.ID() != h.ID {
			return s.walk(a, h.Top)
		}
	}
	return s.want(a)
}

// want asks for more of a's log, if the peer may have it and this side
// would take it.
func (s *Sync) want(a keys.PublicKey) []Message {
	if s.stopped[a] {
		return nil
	}
	seq, down, done := s.logs.Next(a)
	if done || (!down && s.peer[a].Top < seq) {
		return nil
	}
	return s.ask(Want{Author: a, Seq: seq, Down: down})
}

// walk asks for the peer's visible chain of a's log from seq down, to find
// where its branch parts from this side's.
func (s *Sync) walk(a keys.PublicKey, seq uint64) []Message {
	if seq == 0 || s.stopped[a] {
		s.walking[a] = false
		return nil
	}
	s.walking[a] = true
	return s.ask(Want{Author: a, Seq: seq, Down: true})
}

func (s *Sync) ask(w Want) []Message {
	s.wants[w.Author] = w
	return []Message{w}
}

// point is a's fork point, or 0.
func (s *Sync) point(a keys.PublicKey) uint64 {
	if l := s.logs.Log(a); l != nil {
		if p := l.Fork(); p != nil {
			return min(p.A.Seq, p.B.Seq)
		}
	}
	return 0
}

// entries takes a batch the peer sent for a Want, then asks for more, and
// sends the peer any fork this side found or moved down meanwhile.
func (s *Sync) entries(m Entries) ([]Message, error) {
	a := m.Author
	w, ok := s.wants[a]
	if !ok {
		return nil, violation("entries not asked for")
	}
	delete(s.wants, a)
	if len(m.Entries) > MaxBatch {
		return nil, violation("%d entries in a batch", len(m.Entries))
	}
	size := 0
	for i, e := range m.Entries {
		seq := w.Seq + uint64(i)
		if w.Down {
			seq = w.Seq - uint64(i)
		}
		size += len(e.Box)
		if e.Author != a || e.Seq != seq || size > Budget {
			return nil, violation("a batch that doesn't answer the want")
		}
	}
	before := s.point(a)
	var out []Message
	if s.walking[a] {
		out = s.walked(a, m.Entries)
	} else {
		out = s.took(a, m.Entries)
	}
	if p := s.point(a); p != before {
		f := s.logs.Log(a).Fork()
		out = append(out, Fork{A: f.A, B: f.B})
	}
	return out, nil
}

// took adds a batch asked for with want, then asks for more. A fork found
// on the way may lie above where the branches part, but the peer, longer
// on its branch, sees this side's head differ from its own entry there and
// walks down itself, sending the lower proof before its Bye.
func (s *Sync) took(a keys.PublicKey, es []*memberlog.Entry) []Message {
	if len(es) == 0 {
		s.stopped[a] = true
		return nil
	}
	for _, e := range es {
		if _, err := s.logs.Add(e); err != nil {
			// The roster is merged, so a refusal is the log's own state (a
			// fork, a cutoff) or a peer serving what it shouldn't: either
			// way, take nothing more of this log from it.
			s.stopped[a] = true
			return nil
		}
	}
	return s.want(a)
}

// walked adds a batch of the peer's branch, highest first. Each entry that
// differs from this side's moves the fork proof down to it; the first one
// this side already holds is where the branches part, and ends the walk.
func (s *Sync) walked(a keys.PublicKey, es []*memberlog.Entry) []Message {
	for _, e := range es {
		isNew, err := s.logs.Add(e)
		switch {
		case err == nil && !isNew: // the same entry: the branches part above it
			s.walking[a] = false
			return nil
		case err != nil && !errors.Is(err, memberlog.ErrForked):
			s.walking[a], s.stopped[a] = false, true
			return nil
		}
	}
	if len(es) == 0 {
		s.walking[a], s.stopped[a] = false, true
		return nil
	}
	return s.walk(a, es[len(es)-1].Seq-1)
}

func sortedKeys[V any](m map[keys.PublicKey]V) []keys.PublicKey {
	out := make([]keys.PublicKey, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.SortFunc(out, func(a, b keys.PublicKey) int { return slices.Compare(a[:], b[:]) })
	return out
}
