package sync

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/getlantern/warren/bencode"
	"github.com/getlantern/warren/group/keys"
	"github.com/getlantern/warren/group/memberlog"
	"github.com/getlantern/warren/group/roster"
)

// MaxMessage bounds a message's encoding. Every message the Sync sends
// fits: heads, operations and log heads are split across messages, an
// operation of roster.MaxOpBytes fits with room for its envelope, and a
// batch of entries is bounded by Budget and MaxBatch.
const MaxMessage = roster.MaxOpBytes + 4096

// maxElements bounds the values in one message: a batch, a split list of
// operations or log heads, each a few values apiece.
const maxElements = 1 << 16

// ErrMalformed means a message isn't a well-formed, canonical message, or
// carries an operation or entry that isn't; the error wraps theirs too.
var ErrMalformed = errors.New("sync: malformed message")

// A Message is one step of the exchange.
type Message interface{ kind() int64 }

// Have is the ID of every roster operation the sender holds, the first
// message each side sends, so each sends the other exactly what it lacks.
// More means another Have message follows.
type Have struct {
	IDs  []roster.ID
	More bool
}

// Ops is roster operations the peer lacks, parents before children. More
// means another Ops message follows.
type Ops struct {
	Ops  []*roster.Op
	More bool
}

// Fork is a fork proof the sender holds, so the receiver stops accepting
// that log too.
type Fork struct{ A, B *memberlog.Entry }

// Logs is the head of every log the sender holds, sent once the roster is
// merged. More means another Logs message follows.
type Logs struct {
	Heads []LogHead
	More  bool
}

// LogHead is one log's visible end: its sequence number and the entry's
// ID (zero for an empty log), so a peer holding another branch of a fork
// sees it.
type LogHead struct {
	Author keys.PublicKey
	Top    uint64
	ID     memberlog.ID
}

// Want asks for the entries of Author's log from Seq on, upward, or
// downward for a removed author's log.
type Want struct {
	Author keys.PublicKey
	Seq    uint64
	Down   bool
}

// Entries answers a Want: entries in the order asked, at most MaxBatch and
// Budget box bytes. None means the sender has nothing from there.
type Entries struct {
	Author  keys.PublicKey
	Entries []*memberlog.Entry
}

func (Have) kind() int64    { return 1 }
func (Ops) kind() int64     { return 2 }
func (Fork) kind() int64    { return 3 }
func (Logs) kind() int64    { return 4 }
func (Want) kind() int64    { return 5 }
func (Entries) kind() int64 { return 6 }

func str(b []byte) bencode.Value                  { return bencode.Value{Kind: bencode.String, Str: b} }
func num(n int64) bencode.Value                   { return bencode.Value{Kind: bencode.Int, Int: n} }
func list(vs []bencode.Value) bencode.Value       { return bencode.Value{Kind: bencode.List, List: vs} }
func pair(k string, v bencode.Value) bencode.Pair { return bencode.Pair{Key: []byte(k), Value: v} }

func flag(b bool) bencode.Value {
	if b {
		return num(1)
	}
	return num(0)
}

// Encode returns m's encoding.
func Encode(m Message) []byte {
	d := []bencode.Pair{}
	switch m := m.(type) {
	case Have:
		var ids []bencode.Value
		for _, id := range m.IDs {
			ids = append(ids, str(id[:]))
		}
		d = append(d, pair("h", list(ids)), pair("m", flag(m.More)))
	case Ops:
		d = append(d, pair("m", flag(m.More)))
		var ops []bencode.Value
		for _, o := range m.Ops {
			ops = append(ops, str(o.Encode()))
		}
		d = append(d, pair("o", list(ops)))
	case Fork:
		d = append(d, pair("a", str(m.A.Encode())), pair("b", str(m.B.Encode())))
	case Logs:
		var hs []bencode.Value
		for _, h := range m.Heads {
			hs = append(hs, list([]bencode.Value{str(h.Author[:]), num(int64(h.Top)), str(h.ID[:])}))
		}
		d = append(d, pair("l", list(hs)), pair("m", flag(m.More)))
	case Want:
		d = append(d, pair("a", str(m.Author[:])), pair("d", flag(m.Down)), pair("s", num(int64(m.Seq))))
	case Entries:
		var es []bencode.Value
		for _, e := range m.Entries {
			es = append(es, str(e.Encode()))
		}
		d = append(d, pair("a", str(m.Author[:])), pair("e", list(es)))
	}
	d = append(d, pair("t", num(m.kind())))
	return bencode.Append(nil, bencode.Value{Kind: bencode.Dict, Dict: d})
}

// Decode parses and verifies a message: canonical, its operations and
// entries each well-formed and signed by their authors.
func Decode(b []byte) (Message, error) {
	if len(b) > MaxMessage {
		return nil, ErrMalformed
	}
	v, err := bencode.DecodeLimit(b, maxElements)
	if err != nil || v.Kind != bencode.Dict {
		return nil, ErrMalformed
	}
	m, err := decode(v)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(Encode(m), b) {
		return nil, ErrMalformed // non-canonical, or fields outside its kind
	}
	return m, nil
}

func decode(v bencode.Value) (Message, error) {
	t, _ := v.Get("t")
	field := func(k string, kind bencode.Kind) (bencode.Value, bool) {
		f, ok := v.Get(k)
		return f, ok && f.Kind == kind
	}
	fixed := func(dst []byte, k string) bool {
		f, ok := field(k, bencode.String)
		if !ok || len(f.Str) != len(dst) {
			return false
		}
		copy(dst, f.Str)
		return true
	}
	boolean := func(k string) (bool, bool) {
		f, ok := field(k, bencode.Int)
		return f.Int == 1, ok && (f.Int == 0 || f.Int == 1)
	}
	switch t.Int {
	case Have{}.kind():
		hs, ok := field("h", bencode.List)
		more, ok2 := boolean("m")
		if !ok || !ok2 {
			return nil, ErrMalformed
		}
		m := Have{More: more}
		for _, h := range hs.List {
			var id roster.ID
			if h.Kind != bencode.String || len(h.Str) != len(id) {
				return nil, ErrMalformed
			}
			copy(id[:], h.Str)
			m.IDs = append(m.IDs, id)
		}
		return m, nil
	case Ops{}.kind():
		os, ok := field("o", bencode.List)
		more, ok2 := boolean("m")
		if !ok || !ok2 {
			return nil, ErrMalformed
		}
		m := Ops{More: more}
		for _, o := range os.List {
			if o.Kind != bencode.String {
				return nil, ErrMalformed
			}
			op, err := roster.Decode(o.Str)
			if err != nil {
				return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
			}
			m.Ops = append(m.Ops, op)
		}
		return m, nil
	case Fork{}.kind():
		a, ok := field("a", bencode.String)
		b, ok2 := field("b", bencode.String)
		if !ok || !ok2 {
			return nil, ErrMalformed
		}
		ea, err := memberlog.Decode(a.Str)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
		}
		eb, err := memberlog.Decode(b.Str)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
		}
		return Fork{A: ea, B: eb}, nil
	case Logs{}.kind():
		ls, ok := field("l", bencode.List)
		more, ok2 := boolean("m")
		if !ok || !ok2 {
			return nil, ErrMalformed
		}
		m := Logs{More: more}
		for _, l := range ls.List {
			var h LogHead
			if l.Kind != bencode.List || len(l.List) != 3 ||
				l.List[0].Kind != bencode.String || len(l.List[0].Str) != len(h.Author) ||
				l.List[1].Kind != bencode.Int || l.List[1].Int < 0 ||
				l.List[2].Kind != bencode.String || len(l.List[2].Str) != len(h.ID) {
				return nil, ErrMalformed
			}
			copy(h.Author[:], l.List[0].Str)
			h.Top = uint64(l.List[1].Int)
			copy(h.ID[:], l.List[2].Str)
			m.Heads = append(m.Heads, h)
		}
		return m, nil
	case Want{}.kind():
		var m Want
		s, ok := field("s", bencode.Int)
		down, ok2 := boolean("d")
		if !fixed(m.Author[:], "a") || !ok || !ok2 || s.Int < 1 {
			return nil, ErrMalformed
		}
		m.Seq, m.Down = uint64(s.Int), down
		return m, nil
	case Entries{}.kind():
		var m Entries
		es, ok := field("e", bencode.List)
		if !fixed(m.Author[:], "a") || !ok {
			return nil, ErrMalformed
		}
		for _, e := range es.List {
			if e.Kind != bencode.String {
				return nil, ErrMalformed
			}
			en, err := memberlog.Decode(e.Str)
			if err != nil {
				return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
			}
			m.Entries = append(m.Entries, en)
		}
		return m, nil
	}
	return nil, ErrMalformed
}
