package sync

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/getlantern/warren/group/keys"
	"github.com/getlantern/warren/group/memberlog"
	"github.com/getlantern/warren/group/roster"
)

func me(b byte) *keys.Identity { return keys.IdentityFromSeed([32]byte{b}) }

// group is a roster with an owner, an admin and two members.
type group struct {
	r                    *roster.Roster
	owner, admin, m1, m2 *keys.Identity
}

func newGroup(t *testing.T) *group {
	t.Helper()
	g := &group{owner: me(1), admin: me(2), m1: me(3), m2: me(4)}
	r, err := roster.Found(g.owner, "g", 1)
	if err != nil {
		t.Fatal(err)
	}
	ow := &roster.Writer{R: r, Me: g.owner}
	for _, a := range []struct {
		k    *keys.Identity
		role roster.Role
	}{{g.admin, roster.Admin}, {g.m1, roster.Member}, {g.m2, roster.Member}} {
		if _, err := ow.Add(a.k.Public(), "x", a.role, keys.PublicKey{}); err != nil {
			t.Fatal(err)
		}
	}
	g.r = r
	return g
}

// peer is one member's state: its roster copy and logs.
type peer struct {
	r    *roster.Roster
	logs *memberlog.Set
}

func fold(t *testing.T, r *roster.Roster) *roster.Result {
	t.Helper()
	f, err := r.Fold()
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// newPeer copies r as it stands.
func newPeer(t *testing.T, r *roster.Roster) *peer {
	t.Helper()
	c, err := roster.New(r.Op(r.Group()))
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range fold(t, r).Order[1:] {
		if _, err := c.Add(o); err != nil {
			t.Fatal(err)
		}
	}
	p := &peer{r: c, logs: memberlog.NewSet(c.Group())}
	p.update(t)
	return p
}

func (p *peer) update(t *testing.T) {
	t.Helper()
	if err := p.logs.Update(fold(t, p.r)); err != nil {
		t.Fatal(err)
	}
}

// writer returns a Writer on p's roster.
func (p *peer) writer(id *keys.Identity) *roster.Writer { return &roster.Writer{R: p.r, Me: id} }

// chain writes n entries by author under p's current epoch, after prev.
func (p *peer) chain(t *testing.T, author *keys.Identity, prev *memberlog.Entry, n int, size int) []*memberlog.Entry {
	t.Helper()
	f := fold(t, p.r)
	key := p.r.Keyring(author).Epochs[f.Current]
	var out []*memberlog.Entry
	for range n {
		e, err := memberlog.Write(author, p.r.Group(), prev, f.Current, key, memberlog.App, make([]byte, size))
		if err != nil {
			t.Fatal(err)
		}
		out, prev = append(out, e), e
	}
	return out
}

func (p *peer) add(t *testing.T, es ...*memberlog.Entry) {
	t.Helper()
	for _, e := range es {
		if _, err := p.logs.Add(e); err != nil {
			t.Fatalf("entry %d: %v", e.Seq, err)
		}
	}
}

// run carries messages between a and b through the wire encoding until
// neither has anything to send. tamper, if set, may drop, duplicate or
// replace each message: it returns what is delivered instead.
func run(t *testing.T, a, b *peer, tamper func(i int, m Message) []Message) (*Sync, *Sync, error) {
	t.Helper()
	sa, sb := New(a.r, a.logs), New(b.r, b.logs)
	type msg struct {
		to *Sync
		m  Message
	}
	q := []msg{}
	for _, m := range sa.Start() {
		q = append(q, msg{sb, m})
	}
	for _, m := range sb.Start() {
		q = append(q, msg{sa, m})
	}
	for i := 0; len(q) > 0; i++ {
		if i > 100000 {
			t.Fatal("the exchange doesn't end")
		}
		if sa.Finished() && sb.Finished() {
			t.Fatalf("both finished with %d messages on their way", len(q))
		}
		next := q[0]
		q = q[1:]
		ms := []Message{next.m}
		if tamper != nil {
			ms = tamper(i, next.m)
		}
		for _, m := range ms {
			b := Encode(m)
			if len(b) > MaxMessage {
				t.Fatalf("a %T of %d bytes", m, len(b))
			}
			d, err := Decode(b)
			if err != nil {
				t.Fatalf("a %T didn't decode: %v", m, err)
			}
			out, err := next.to.Handle(d)
			if err != nil {
				return sa, sb, err
			}
			back := sa
			if next.to == sa {
				back = sb
			}
			for _, o := range out {
				q = append(q, msg{back, o})
			}
		}
	}
	return sa, sb, nil
}

// state is what a peer holds, to compare two peers by.
func state(p *peer) string {
	var b bytes.Buffer
	for _, h := range p.r.Heads() {
		b.Write(h[:])
	}
	for _, a := range p.logs.Authors() {
		l := p.logs.Log(a)
		b.Write(a[:])
		for _, e := range l.Entries() {
			id := e.ID()
			b.Write(id[:])
		}
		if l.Fork() != nil {
			b.WriteString("forked")
		}
	}
	return b.String()
}

// shape is what a peer holds, by counts: operations, and each log's
// visible length and whether it forked.
func shape(p *peer) string {
	s := fmt.Sprint(p.r.Len())
	for _, a := range p.logs.Authors() {
		l := p.logs.Log(a)
		s += fmt.Sprintf(" %x:%d:%v", a[:2], len(l.Entries()), l.Fork() != nil)
	}
	return s
}

func converge(t *testing.T, a, b *peer) {
	t.Helper()
	sa, sb, err := run(t, a, b, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !sa.Finished() || !sb.Finished() {
		t.Fatalf("finished: %v %v", sa.Finished(), sb.Finished())
	}
	if state(a) != state(b) {
		t.Fatal("the peers hold different state after syncing")
	}
}

func shown(p *peer, author *keys.Identity) int {
	l := p.logs.Log(author.Public())
	if l == nil {
		return 0
	}
	return len(l.Entries())
}

func TestRosterConverges(t *testing.T) {
	g := newGroup(t)
	a, b := newPeer(t, g.r), newPeer(t, g.r)
	if _, err := a.writer(g.admin).Add(me(5).Public(), "y", roster.Member, keys.PublicKey{}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.writer(g.owner).Add(me(6).Public(), "z", roster.Member, keys.PublicKey{}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.writer(g.owner).Rekey(); err != nil {
		t.Fatal(err)
	}
	converge(t, a, b)
	if a.r.Len() != g.r.Len()+3 {
		t.Fatalf("%d operations, want %d", a.r.Len(), g.r.Len()+3)
	}
}

func TestLogsConverge(t *testing.T) {
	g := newGroup(t)
	a, b := newPeer(t, g.r), newPeer(t, g.r)
	m1 := a.chain(t, g.m1, nil, 3*MaxBatch+5, 10) // several batches
	a.add(t, m1...)
	b.add(t, m1[:7]...)                            // b has a prefix
	b.add(t, b.chain(t, g.owner, nil, 5, 1000)...) // a has none of these
	big := a.chain(t, g.m2, nil, 10, memberlog.MaxBody)
	a.add(t, big...) // more than one batch's budget
	converge(t, a, b)
	if shown(b, g.m1) != len(m1) || shown(a, g.owner) != 5 || shown(b, g.m2) != 10 {
		t.Fatalf("shown: %d %d %d", shown(b, g.m1), shown(a, g.owner), shown(b, g.m2))
	}
}

// TestNewMemberArrivesWithItsLog: the roster merges before log heads, so a
// member b hasn't heard of yet has its log taken in the same session.
func TestNewMemberArrivesWithItsLog(t *testing.T) {
	g := newGroup(t)
	a, b := newPeer(t, g.r), newPeer(t, g.r)
	n := me(7)
	if _, err := a.writer(g.admin).Add(n.Public(), "n", roster.Member, keys.PublicKey{}); err != nil {
		t.Fatal(err)
	}
	a.update(t)
	a.add(t, a.chain(t, n, nil, 4, 10)...)
	converge(t, a, b)
	if shown(b, n) != 4 {
		t.Fatalf("b shows %d of the new member's entries", shown(b, n))
	}
}

// TestRemovedLogComesTopDown: a removed author's log is sent from the
// recorded head down, the only order a member takes it in.
func TestRemovedLogComesTopDown(t *testing.T) {
	g := newGroup(t)
	a, b := newPeer(t, g.r), newPeer(t, g.r)
	es := a.chain(t, g.m1, nil, 2*MaxBatch+3, 10)
	a.add(t, es...)
	head := es[len(es)-1]
	if _, err := a.writer(g.admin).Remove(g.m1.Public(), head.Seq, head.ID()); err != nil {
		t.Fatal(err)
	}
	a.update(t)
	converge(t, a, b)
	if shown(b, g.m1) != len(es) {
		t.Fatalf("b shows %d of the removed member's %d entries", shown(b, g.m1), len(es))
	}
}

// TestLaggingMemberLearnsRemoval: b held entries past the cutoff; the
// removal reaches it and they are withdrawn.
func TestLaggingMemberLearnsRemoval(t *testing.T) {
	g := newGroup(t)
	a, b := newPeer(t, g.r), newPeer(t, g.r)
	es := a.chain(t, g.m1, nil, 7, 10)
	a.add(t, es[:5]...)
	b.add(t, es...)
	if _, err := a.writer(g.admin).Remove(g.m1.Public(), 5, es[4].ID()); err != nil {
		t.Fatal(err)
	}
	a.update(t)
	converge(t, a, b)
	if shown(b, g.m1) != 5 || len(b.logs.Withdrawn()) != 2 {
		t.Fatalf("b shows %d", shown(b, g.m1))
	}
}

func TestForkSpreads(t *testing.T) {
	g := newGroup(t)
	a, b := newPeer(t, g.r), newPeer(t, g.r)
	e1 := a.chain(t, g.m1, nil, 1, 10)[0]
	x := a.chain(t, g.m1, e1, 2, 10)
	y := a.chain(t, g.m1, e1, 1, 11)
	a.add(t, e1, x[0])
	if _, err := a.logs.Add(y[0]); !errors.Is(err, memberlog.ErrForked) {
		t.Fatalf("setup: %v", err)
	}
	b.add(t, e1, x[0], x[1]) // one branch, and further along it
	converge(t, a, b)
	if b.logs.Log(g.m1.Public()).Fork() == nil {
		t.Fatal("the fork proof didn't reach b")
	}
}

// TestForkLearnedFirst: b holds none of a forked log; the proof reaches it
// first, and it still takes the prefix a shows.
func TestForkLearnedFirst(t *testing.T) {
	g := newGroup(t)
	a, b := newPeer(t, g.r), newPeer(t, g.r)
	es := a.chain(t, g.m1, nil, 3, 10)
	y := a.chain(t, g.m1, es[1], 1, 11)
	a.add(t, es...)
	if _, err := a.logs.Add(y[0]); !errors.Is(err, memberlog.ErrForked) {
		t.Fatalf("setup: %v", err)
	}
	converge(t, a, b)
	if shown(b, g.m1) != 2 || b.logs.Log(g.m1.Public()).Fork() == nil {
		t.Fatalf("b shows %d", shown(b, g.m1))
	}
}

// TestPeerMustAnswerTheWant: a batch that isn't what was asked, or wasn't
// asked at all, ends the exchange.
func TestPeerMustAnswerTheWant(t *testing.T) {
	g := newGroup(t)
	a, b := newPeer(t, g.r), newPeer(t, g.r)
	es := a.chain(t, g.m1, nil, MaxBatch+2, 10)
	a.add(t, es...)
	for name, bad := range map[string]func(Entries) Entries{
		"too many":  func(Entries) Entries { return Entries{Author: g.m1.Public(), Entries: es} },
		"wrong seq": func(m Entries) Entries { m.Entries = m.Entries[1:]; return m },
		"wrong log": func(m Entries) Entries { m.Author = g.m2.Public(); return m },
		"another author inside": func(m Entries) Entries {
			m.Entries = []*memberlog.Entry{a.chain(t, g.m2, nil, 1, 10)[0]}
			return m
		},
		"repeated": func(m Entries) Entries { m.Entries = append(m.Entries[:1], m.Entries[0]); return m },
		"over budget": func(m Entries) Entries {
			big := a.chain(t, g.m1, nil, 5, memberlog.MaxBody)
			return Entries{Author: g.m1.Public(), Entries: big}
		},
	} {
		once := false
		_, _, err := run(t, a, newPeer(t, g.r), func(_ int, m Message) []Message {
			if e, ok := m.(Entries); ok && len(e.Entries) > 0 && !once {
				once = true // only the first batch, so nothing else trips
				return []Message{bad(e)}
			}
			return []Message{m}
		})
		if !errors.Is(err, ErrProtocol) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	_ = b
}

// TestInSyncExchangesLittle: peers already in sync send no operations and
// ask for no entries.
func TestInSyncExchangesLittle(t *testing.T) {
	g := newGroup(t)
	a, b := newPeer(t, g.r), newPeer(t, g.r)
	es := a.chain(t, g.m1, nil, 5, 10)
	a.add(t, es...)
	b.add(t, es...)
	var ops, wants int
	if _, _, err := run(t, a, b, func(_ int, m Message) []Message {
		switch m := m.(type) {
		case Ops:
			ops += len(m.Ops)
		case Want:
			wants++
		}
		return []Message{m}
	}); err != nil {
		t.Fatal(err)
	}
	if ops != 0 || wants != 0 {
		t.Fatalf("%d operations and %d wants between peers in sync", ops, wants)
	}
}

// TestOpsSplit: operations that don't fit one message go in several.
func TestOpsSplit(t *testing.T) {
	defer func(n int) { opsChunk = n }(opsChunk)
	opsChunk = 2000
	g := newGroup(t)
	a, b := newPeer(t, g.r), newPeer(t, g.r)
	for i := range 10 {
		if _, err := a.writer(g.admin).Add(me(byte(20+i)).Public(), "y", roster.Member, keys.PublicKey{}); err != nil {
			t.Fatal(err)
		}
	}
	var msgs int
	if _, _, err := run(t, a, b, func(_ int, m Message) []Message {
		if o, ok := m.(Ops); ok {
			msgs++
			size := 0
			for _, op := range o.Ops {
				size += len(op.Encode())
			}
			if len(o.Ops) > 1 && size > opsChunk {
				t.Fatalf("%d bytes of operations in one message", size)
			}
		}
		return []Message{m}
	}); err != nil {
		t.Fatal(err)
	}
	if msgs < 4 || state(a) != state(b) {
		t.Fatalf("%d Ops messages", msgs)
	}
}

// TestForkPastTheWindow: a fork proof too far past b's chain to take on
// arrival is taken once the batches bring the chain up to it.
func TestForkPastTheWindow(t *testing.T) {
	g := newGroup(t)
	a, b := newPeer(t, g.r), newPeer(t, g.r)
	es := a.chain(t, g.m1, nil, memberlog.Window+20, 1)
	y := a.chain(t, g.m1, es[len(es)-2], 1, 2)
	a.add(t, es...)
	if _, err := a.logs.Add(y[0]); !errors.Is(err, memberlog.ErrForked) {
		t.Fatalf("setup: %v", err)
	}
	converge(t, a, b)
	if b.logs.Log(g.m1.Public()).Fork() == nil {
		t.Fatal("the fork proof past the window never reached b")
	}
}

// TestTamperedExchanges: a message duplicated either fails as a protocol
// violation or changes nothing; one dropped never panics, and leaves the
// exchange unfinished unless it was a fork proof, which needs no answer. A
// dropped Bye leaves both sides done, but not finished.
func TestTamperedExchanges(t *testing.T) {
	g := newGroup(t)
	base := func() (*peer, *peer) {
		a, b := newPeer(t, g.r), newPeer(t, g.r)
		if _, err := a.writer(g.admin).Add(me(8).Public(), "y", roster.Member, keys.PublicKey{}); err != nil {
			t.Fatal(err)
		}
		a.update(t)
		e1 := a.chain(t, g.m1, nil, 1, 10)[0]
		x := a.chain(t, g.m1, e1, 1, 10)
		a.add(t, e1, x[0])
		_, _ = a.logs.Add(a.chain(t, g.m1, e1, 1, 11)[0]) // forked
		a.add(t, a.chain(t, g.m2, nil, MaxBatch+1, 10)...)
		b.add(t, b.chain(t, g.owner, nil, 3, 10)...)
		return a, b
	}
	a, b := base()
	var n int
	if _, _, err := run(t, a, b, func(i int, m Message) []Message { n = i + 1; return []Message{m} }); err != nil {
		t.Fatal(err)
	}
	// Each base writes fresh entries and operations (random nonces and
	// seals), so runs compare by shape, and the two peers by state.
	want := shape(a)
	for i := range n {
		a, b := base()
		sa, sb, err := run(t, a, b, func(j int, m Message) []Message {
			if j == i {
				return []Message{m, m}
			}
			return []Message{m}
		})
		if err != nil && !errors.Is(err, ErrProtocol) {
			t.Fatalf("message %d duplicated: %v", i, err)
		}
		if err == nil && (!sa.Finished() || !sb.Finished() || shape(a) != want || state(a) != state(b)) {
			t.Fatalf("message %d duplicated: no error, but not converged: finished %v %v\n%s\n%s\n%s", i, sa.Finished(), sb.Finished(), want, shape(a), shape(b))
		}

		a, b = base()
		var dropped Message
		sa, sb, err = run(t, a, b, func(j int, m Message) []Message {
			if j == i {
				dropped = m
				return nil
			}
			return []Message{m}
		})
		if err != nil {
			continue
		}
		// A fork proof needs no answer, so losing one costs the proof until
		// a later session; anything else lost leaves the exchange unfinished.
		if _, isFork := dropped.(Fork); !isFork && sa.Finished() && sb.Finished() {
			t.Fatalf("a dropped %T left both sides finished", dropped)
		}
		if _, isBye := dropped.(Bye); isBye && (!sa.Done() || !sb.Done()) {
			t.Fatal("a dropped Bye left a side not done")
		}
	}
}

func TestMessageRoundTrip(t *testing.T) {
	g := newGroup(t)
	p := newPeer(t, g.r)
	es := p.chain(t, g.m1, nil, 2, 10)
	op := p.r.Op(p.r.Heads()[0])
	for _, m := range []Message{
		Have{IDs: p.r.IDs()},
		Have{More: true},
		Ops{Ops: []*roster.Op{op}, More: true},
		Fork{A: es[0], B: es[1]},
		Logs{Heads: []LogHead{{Author: g.m1.Public(), Top: 9, ID: es[1].ID()}}},
		Want{Author: g.m1.Public(), Seq: 3, Down: true},
		Entries{Author: g.m1.Public(), Entries: es},
		Bye{},
	} {
		d, err := Decode(Encode(m))
		if err != nil {
			t.Fatalf("%T: %v", m, err)
		}
		if !bytes.Equal(Encode(d), Encode(m)) {
			t.Fatalf("%T changed through the wire", m)
		}
	}
	for name, b := range map[string][]byte{
		"unknown kind":   []byte("d1:ti9ee"),
		"extra field":    []byte("d1:hle1:xi1e1:ti1ee"),
		"want seq 0":     slices.Concat([]byte("d1:a32:"), make([]byte, 32), []byte("1:di0e1:si0e1:ti5ee")),
		"flag of 2":      slices.Concat([]byte("d1:a32:"), make([]byte, 32), []byte("1:di2e1:si1e1:ti5ee")),
		"trailing bytes": []byte("d1:hle1:mi0e1:ti1eex"),
		"heads no flag":  []byte("d1:hle1:ti1ee"),
		"too large":      make([]byte, MaxMessage+1),
	} {
		if _, err := Decode(b); err == nil {
			t.Fatalf("%s decoded", name)
		}
	}
}

func TestServeStaysInBudget(t *testing.T) {
	g := newGroup(t)
	p := newPeer(t, g.r)
	p.add(t, p.chain(t, g.m1, nil, 10, memberlog.MaxBody)...)
	es := p.logs.Serve(g.m1.Public(), 1, false, Budget, MaxBatch)
	size := 0
	for _, e := range es {
		size += len(e.Box)
	}
	if len(es) == 0 || size > Budget || len(es) == 10 {
		t.Fatalf("served %d entries, %d bytes", len(es), size)
	}
	if n := len(p.logs.Serve(g.m1.Public(), 1, false, Budget, 2)); n != 2 {
		t.Fatalf("served %d with a cap of 2", n)
	}
}

// TestStrangersCostNothing: log heads and fork proofs for authors the
// roster doesn't let write are not kept, and a batch nobody asked for,
// even an empty one, ends the exchange.
func TestStrangersCostNothing(t *testing.T) {
	g := newGroup(t)
	p := newPeer(t, g.r)
	s := New(p.r, p.logs)
	s.Start()
	if _, err := s.Handle(Have{IDs: p.r.IDs()}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Handle(Ops{}); err != nil {
		t.Fatal(err)
	}
	stranger := me(99)
	ep := fold(t, p.r).Current
	key := p.r.Keyring(g.m1).Epochs[ep]
	x1, _ := memberlog.Write(stranger, g.r.Group(), nil, ep, key, memberlog.App, []byte("x"))
	x2, _ := memberlog.Write(stranger, g.r.Group(), nil, ep, key, memberlog.App, []byte("y"))
	if _, err := s.Handle(Fork{A: x1, B: x2}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Handle(Logs{Heads: []LogHead{{Author: stranger.Public(), Top: 5}}}); err != nil {
		t.Fatal(err)
	}
	if len(s.peer) != 0 || p.logs.Log(stranger.Public()) != nil {
		t.Fatalf("kept %d log heads, or a log, of a stranger", len(s.peer))
	}
	if _, err := s.Handle(Entries{Author: g.m1.Public()}); !errors.Is(err, ErrProtocol) {
		t.Fatalf("an empty batch nobody asked for: %v", err)
	}
}

// TestHaveSplit: IDs that don't fit one message go in several.
func TestHaveSplit(t *testing.T) {
	defer func(n int) { haveChunk = n }(haveChunk)
	haveChunk = 1
	g := newGroup(t)
	a, b, c := newPeer(t, g.r), newPeer(t, g.r), newPeer(t, g.r)
	for i, p := range []*peer{a, b} { // concurrent ops: two heads once merged
		if _, err := p.writer(g.owner).Add(me(byte(30+i)).Public(), "y", roster.Member, keys.PublicKey{}); err != nil {
			t.Fatal(err)
		}
	}
	converge(t, a, b)
	if len(a.r.Heads()) < 2 {
		t.Fatal("setup: one head")
	}
	var heads int
	if _, _, err := run(t, a, c, func(_ int, m Message) []Message {
		if h, ok := m.(Have); ok {
			heads++
			if len(h.IDs) > haveChunk {
				t.Fatalf("%d heads in one message", len(h.IDs))
			}
		}
		return []Message{m}
	}); err != nil {
		t.Fatal(err)
	}
	if heads < 3 || state(a) != state(c) {
		t.Fatalf("%d Heads messages", heads)
	}
}

// TestLargestOpFits: an Ops message carrying one operation of the largest
// size the roster takes still decodes.
func TestLargestOpFits(t *testing.T) {
	g := newGroup(t)
	op := g.r.Op(g.r.Heads()[0])
	env := len(Encode(Ops{Ops: []*roster.Op{op}, More: true})) - len(op.Encode())
	// A longer string length prefix: up to 7 digits for roster.MaxOpBytes.
	if env+7+roster.MaxOpBytes > MaxMessage {
		t.Fatalf("an operation of %d bytes needs %d", roster.MaxOpBytes, env+7+roster.MaxOpBytes)
	}
}

// TestForkProofShowsNothingNew: taking a peer's fork proof never makes the
// app see, then withdraw, one of its entries.
func TestForkProofShowsNothingNew(t *testing.T) {
	g := newGroup(t)
	a, b := newPeer(t, g.r), newPeer(t, g.r)
	es := a.chain(t, g.m1, nil, 3, 10)
	y := a.chain(t, g.m1, es[1], 1, 11)
	a.add(t, es...)
	if _, err := a.logs.Add(y[0]); !errors.Is(err, memberlog.ErrForked) {
		t.Fatalf("setup: %v", err)
	}
	b.add(t, es[:2]...)
	converge(t, a, b)
	if n := len(b.logs.Withdrawn()); n != 0 || b.logs.Log(g.m1.Public()).Fork() == nil {
		t.Fatalf("b withdrew %d entries it never showed", n)
	}
}

// TestUnknownHeadsNotKept: IDs this side doesn't hold are of no use to
// it, so a peer listing many costs no memory.
func TestUnknownHeadsNotKept(t *testing.T) {
	g := newGroup(t)
	p := newPeer(t, g.r)
	s := New(p.r, p.logs)
	ids := make([]roster.ID, 1000)
	for i := range ids {
		ids[i] = roster.ID{byte(i), byte(i >> 8), 1}
	}
	if _, err := s.Handle(Have{IDs: ids, More: true}); err != nil {
		t.Fatal(err)
	}
	if len(s.theirs) != 0 {
		t.Fatalf("kept %d unknown IDs", len(s.theirs))
	}
}

// branches gives a and b two branches of m1's log that part above entry
// 5: a holds 1..5 then x, b holds 1..5 then y.
func branches(t *testing.T, g *group, a, b *peer, x, y int) {
	t.Helper()
	common := a.chain(t, g.m1, nil, 5, 10)
	a.add(t, common...)
	b.add(t, common...)
	a.add(t, a.chain(t, g.m1, common[4], x, 11)...)
	b.add(t, b.chain(t, g.m1, common[4], y, 12)...)
}

// TestBranchesOfEqualLength: two members on different branches of a fork,
// each as long as the other, find it, and both show only what precedes
// where the branches part.
func TestBranchesOfEqualLength(t *testing.T) {
	g := newGroup(t)
	a, b := newPeer(t, g.r), newPeer(t, g.r)
	branches(t, g, a, b, 5, 5)
	converge(t, a, b)
	if shown(a, g.m1) != 5 || shown(b, g.m1) != 5 || a.logs.Log(g.m1.Public()).Fork() == nil {
		t.Fatalf("shown %d and %d, want 5 each", shown(a, g.m1), shown(b, g.m1))
	}
}

// TestBranchesOfUnequalLength: the shorter branch's member finds the fork
// at its own top; the walk down still finds where the branches part, and
// both members agree in the same session.
func TestBranchesOfUnequalLength(t *testing.T) {
	for _, n := range [][2]int{{5, 7}, {7, 5}, {2 * MaxBatch, 3}} {
		g := newGroup(t)
		a, b := newPeer(t, g.r), newPeer(t, g.r)
		branches(t, g, a, b, n[0], n[1])
		converge(t, a, b)
		if shown(a, g.m1) != 5 || shown(b, g.m1) != 5 {
			t.Fatalf("%v: shown %d and %d, want 5 each", n, shown(a, g.m1), shown(b, g.m1))
		}
	}
}

// TestOneOpAheadSendsOne: a peer one operation ahead gets nothing, and
// sends just that operation.
func TestOneOpAheadSendsOne(t *testing.T) {
	g := newGroup(t)
	a, b := newPeer(t, g.r), newPeer(t, g.r)
	if _, err := b.writer(g.owner).Rekey(); err != nil {
		t.Fatal(err)
	}
	ops := 0
	if _, _, err := run(t, a, b, func(_ int, m Message) []Message {
		if o, ok := m.(Ops); ok {
			ops += len(o.Ops)
		}
		return []Message{m}
	}); err != nil {
		t.Fatal(err)
	}
	if ops != 1 || state(a) != state(b) {
		t.Fatalf("%d operations sent for a peer one ahead", ops)
	}
}

func TestDecodeErrorsAreMalformed(t *testing.T) {
	g := newGroup(t)
	p := newPeer(t, g.r)
	es := p.chain(t, g.m1, nil, 1, 10)
	b := Encode(Entries{Author: g.m1.Public(), Entries: es})
	i := bytes.Index(b, es[0].Sig[:8])
	b[i] ^= 1 // a bad signature inside a well-formed message
	if _, err := Decode(b); !errors.Is(err, ErrMalformed) || !errors.Is(err, memberlog.ErrSignature) {
		t.Fatalf("a bad entry signature: %v", err)
	}
}

// TestWalkStopsWhereBranchesPart: finding a fork above a long shared
// prefix doesn't resend the prefix.
func TestWalkStopsWhereBranchesPart(t *testing.T) {
	g := newGroup(t)
	a, b := newPeer(t, g.r), newPeer(t, g.r)
	common := a.chain(t, g.m1, nil, 4*MaxBatch, 10)
	a.add(t, common...)
	b.add(t, common...)
	top := common[len(common)-1]
	a.add(t, a.chain(t, g.m1, top, 3, 11)...)
	b.add(t, b.chain(t, g.m1, top, 3, 12)...)
	sent := 0
	if _, _, err := run(t, a, b, func(_ int, m Message) []Message {
		if e, ok := m.(Entries); ok {
			sent += len(e.Entries)
		}
		return []Message{m}
	}); err != nil {
		t.Fatal(err)
	}
	if shown(a, g.m1) != len(common) || shown(b, g.m1) != len(common) || sent > 2*MaxBatch {
		t.Fatalf("shown %d and %d of %d, %d entries sent", shown(a, g.m1), shown(b, g.m1), len(common), sent)
	}
}

// TestRemovedLogNeverWalks: a removed author's visible head differing from
// this side's (two pre-removal branches) still leads to the top-down fill
// from the recorded head, not a walk the peer can't serve.
func TestRemovedLogNeverWalks(t *testing.T) {
	g := newGroup(t)
	p, r := newPeer(t, g.r), newPeer(t, g.r)
	x := p.chain(t, g.m1, nil, 5, 10)
	y := r.chain(t, g.m1, x[0], 3, 11) // r's branch parts above entry 1
	p.add(t, x[0], x[1])
	r.add(t, x[0])
	r.add(t, y...)
	rm, err := p.writer(g.admin).Remove(g.m1.Public(), 5, x[4].ID())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.r.Add(rm); err != nil {
		t.Fatal(err)
	}
	p.update(t)
	r.update(t)
	p.add(t, x[4]) // the recorded head, anchored
	if _, _, err := run(t, p, r, nil); err != nil {
		t.Fatal(err)
	}
	if seq, _, _ := r.logs.Next(g.m1.Public()); seq != 4 {
		t.Fatalf("r's next is %d: the recorded head never came", seq)
	}
}

// TestByeComesLast: a side says Bye only after everything it found, so
// a driver closing once both are finished loses nothing.
func TestByeComesLast(t *testing.T) {
	for _, n := range [][2]int{{5, 5}, {5, 7}, {7, 5}, {2 * MaxBatch, 3}} {
		g := newGroup(t)
		a, b := newPeer(t, g.r), newPeer(t, g.r)
		branches(t, g, a, b, n[0], n[1])
		converge(t, a, b) // run fails if both finish with messages queued
	}
}

func TestByeOutOfTurn(t *testing.T) {
	g := newGroup(t)
	p := newPeer(t, g.r)
	s := New(p.r, p.logs)
	if _, err := s.Handle(Bye{}); !errors.Is(err, ErrProtocol) {
		t.Fatalf("bye before the roster: %v", err)
	}
	es := p.chain(t, g.m1, nil, 2, 10)
	// A peer that said Bye only answers Wants. (Ops and Logs after Bye are
	// also out of turn by their own checks; Want, Fork and Bye rely on
	// this one.)
	for _, m := range []Message{Want{Author: g.m1.Public(), Seq: 1}, Fork{A: es[0], B: es[1]}, Bye{}} {
		s2 := New(p.r, p.logs)
		for _, m := range []Message{Have{IDs: p.r.IDs()}, Ops{}, Logs{}, Bye{}} {
			if _, err := s2.Handle(m); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := s2.Handle(m); !errors.Is(err, ErrProtocol) {
			t.Fatalf("a %T after bye: %v", m, err)
		}
	}
	s = New(p.r, p.logs)
	for _, m := range []Message{Have{IDs: p.r.IDs()}, Ops{}} {
		if _, err := s.Handle(m); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Handle(Bye{}); !errors.Is(err, ErrProtocol) {
		t.Fatalf("bye before log heads: %v", err)
	}
}
