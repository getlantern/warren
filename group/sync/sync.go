// Package sync is what two members of a group exchange when a session
// opens (docs/groups-design.md, *Sessions*): roster heads and the
// operations each lacks, then log heads and the entries each lacks. It is
// a state machine with no networking: the caller carries its messages
// over a session, in order, and the simulator drives two of them
// in-process.
package sync

import (
	"cmp"
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

// opsChunk is the operation bytes one Ops message carries; tests lower it.
var opsChunk = MaxMessage - 1024

// ErrProtocol means the peer sent a message out of turn, or one that
// doesn't answer what was asked.
var ErrProtocol = errors.New("sync: protocol violation")

// Sync is one side of one session's exchange. It is not safe for
// concurrent use.
type Sync struct {
	r    *roster.Roster
	logs *memberlog.Set

	gotHeads  bool
	opsDone   bool // the peer's operations are all in, and logs updated
	logsDone  bool // the peer's log heads are all in
	peerHeads []roster.ID
	peerTop   map[keys.PublicKey]uint64
	wants     map[keys.PublicKey]Want // asked and not yet answered
	stopped   map[keys.PublicKey]bool // nothing more from this peer
	forks     map[keys.PublicKey]Fork // from the peer, not yet taken
	err       error
}

// New makes one side of an exchange over r and logs, which it updates as
// operations and entries arrive. logs must be r's group's.
func New(r *roster.Roster, logs *memberlog.Set) *Sync {
	return &Sync{
		r: r, logs: logs,
		peerTop: map[keys.PublicKey]uint64{},
		wants:   map[keys.PublicKey]Want{},
		stopped: map[keys.PublicKey]bool{},
		forks:   map[keys.PublicKey]Fork{},
	}
}

// Start returns the first messages to send.
func (s *Sync) Start() []Message { return []Message{Heads{IDs: s.r.Heads()}} }

// Done reports whether this side has taken everything the peer offered.
// The peer may still be asking; the session ends when both are done.
func (s *Sync) Done() bool { return s.err == nil && s.opsDone && s.logsDone && len(s.wants) == 0 }

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
	return out, nil
}

func violation(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrProtocol}, a...)...)
}

func (s *Sync) handle(m Message) ([]Message, error) {
	switch m := m.(type) {
	case Heads:
		if s.gotHeads {
			return nil, violation("heads twice")
		}
		s.gotHeads, s.peerHeads = true, m.IDs
		return s.missingOps(), nil
	case Ops:
		if !s.gotHeads || s.opsDone {
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
		s.forks[m.A.Author] = m
		s.tryFork(m.A.Author)
		return nil, nil
	case Logs:
		if !s.opsDone || s.logsDone {
			return nil, violation("log heads out of turn")
		}
		for _, h := range m.Heads {
			// Only logs this side would take from: the roster bounds them.
			if _, _, done := s.logs.Next(h.Author); !done {
				s.peerTop[h.Author] = h.Top
			}
		}
		if m.More {
			return nil, nil
		}
		s.logsDone = true
		var out []Message
		for _, a := range sortedKeys(s.peerTop) {
			out = append(out, s.want(a)...)
		}
		return out, nil
	case Want:
		if !s.opsDone {
			return nil, violation("want before the roster is merged")
		}
		return []Message{Entries{Author: m.Author, Entries: s.logs.Serve(m.Author, m.Seq, m.Down, Budget, MaxBatch)}}, nil
	case Entries:
		return s.entries(m)
	}
	return nil, violation("unknown message")
}

// missingOps returns the operations the peer lacks as far as its heads
// show: every operation this side holds that isn't one of the heads it
// knows or in their history, parents first, split to fit messages. A head
// this side doesn't know means the peer is ahead there, and sends it.
func (s *Sync) missingOps() []Message {
	theirs := map[roster.ID]bool{}
	for _, h := range s.peerHeads {
		if s.r.Has(h) {
			theirs[h] = true
			for id := range s.r.History(h) {
				theirs[id] = true
			}
		}
	}
	var send []*roster.Op
	seen := map[roster.ID]bool{}
	for _, h := range s.r.Heads() {
		ids := s.r.History(h)
		ids[h] = true
		for id := range ids {
			if !theirs[id] && !seen[id] {
				seen[id] = true
				if o := s.r.Op(id); o.Kind != roster.Genesis {
					send = append(send, o)
				}
			}
		}
	}
	// Clocks strictly increase along every edge, so this puts parents first.
	slices.SortFunc(send, func(a, b *roster.Op) int {
		if c := cmp.Compare(a.Lamport, b.Lamport); c != 0 {
			return c
		}
		ai, bi := a.ID(), b.ID()
		return slices.Compare(ai[:], bi[:])
	})
	var out []Message
	cur, size := Ops{}, 0
	for _, o := range send {
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
		var top uint64
		if h := l.Head(); h != nil {
			top = h.Seq
		}
		if len(cur.Heads) == 4096 {
			cur.More = true
			out = append(out, cur)
			cur = Logs{}
		}
		cur.Heads = append(cur.Heads, LogHead{Author: a, Top: top})
	}
	return append(out, cur)
}

// want asks for more of a's log, if the peer may have it and this side
// would take it.
func (s *Sync) want(a keys.PublicKey) []Message {
	if s.stopped[a] {
		return nil
	}
	seq, down, done := s.logs.Next(a)
	if done || (!down && s.peerTop[a] < seq) {
		return nil
	}
	w := Want{Author: a, Seq: seq, Down: down}
	s.wants[a] = w
	return []Message{w}
}

// entries takes a batch the peer sent for a Want, then asks for more.
func (s *Sync) entries(m Entries) ([]Message, error) {
	w, ok := s.wants[m.Author]
	if !ok {
		return nil, violation("entries not asked for")
	}
	delete(s.wants, m.Author)
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
		if e.Author != w.Author || e.Seq != seq || size > Budget {
			return nil, violation("a batch that doesn't answer the want")
		}
	}
	if len(m.Entries) == 0 {
		s.stopped[m.Author] = true
		return nil, nil
	}
	for _, e := range m.Entries {
		if _, err := s.logs.Add(e); err != nil {
			// The roster is merged, so a refusal is the log's own state (a
			// fork, a cutoff) or a peer serving what it shouldn't: either
			// way, take nothing more of this log from it.
			s.stopped[m.Author] = true
			break
		}
	}
	s.tryFork(m.Author)
	return s.want(m.Author), nil
}

// tryFork adds a fork proof the peer sent, once both entries can be
// taken: each is checked like any entry, so a proof only counts against a
// log this side would accept them for.
func (s *Sync) tryFork(a keys.PublicKey) {
	f, ok := s.forks[a]
	if !ok {
		return
	}
	_, _ = s.logs.Add(f.A)
	_, _ = s.logs.Add(f.B)
	// Kept only while the log still takes entries: the roster bounds what
	// waits, and a proof taken, or one for a log that takes nothing, is done.
	if _, _, done := s.logs.Next(a); done {
		delete(s.forks, a)
	}
}

func sortedKeys(m map[keys.PublicKey]uint64) []keys.PublicKey {
	out := make([]keys.PublicKey, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.SortFunc(out, func(a, b keys.PublicKey) int { return slices.Compare(a[:], b[:]) })
	return out
}
