package memberlog

import (
	"errors"
	"math"
	"testing"

	"github.com/getlantern/warren/group/keys"
	"github.com/getlantern/warren/group/roster"
)

func me(b byte) *keys.Identity { return keys.IdentityFromSeed([32]byte{b}) }

// fixture is a group with an owner, an admin, a member and a mirror.
type fixture struct {
	r                            *roster.Roster
	owner, admin, member, mirror *keys.Identity
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	x := &fixture{owner: me(1), admin: me(2), member: me(3), mirror: me(4)}
	r, err := roster.Found(x.owner, "g", 1)
	if err != nil {
		t.Fatal(err)
	}
	ow := &roster.Writer{R: r, Me: x.owner}
	for _, a := range []struct {
		k    *keys.Identity
		role roster.Role
	}{{x.admin, roster.Admin}, {x.member, roster.Member}, {x.mirror, roster.Mirror}} {
		if _, err := ow.Add(a.k.Public(), "x", a.role, keys.PublicKey{}); err != nil {
			t.Fatal(err)
		}
	}
	x.r = r
	return x
}

func (x *fixture) fold(t *testing.T) *roster.Result {
	t.Helper()
	f, err := x.r.Fold()
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// epoch returns the current epoch and its key, as id holds it.
func (x *fixture) epoch(t *testing.T, id *keys.Identity) (roster.ID, keys.EpochKey) {
	t.Helper()
	f := x.fold(t)
	k, ok := x.r.Keyring(id).Epochs[f.Current]
	if !ok {
		t.Fatal("no current epoch key")
	}
	return f.Current, k
}

// chain writes n entries by author.
func (x *fixture) chain(t *testing.T, author *keys.Identity, n int) []*Entry {
	t.Helper()
	ep, key := x.epoch(t, author)
	var out []*Entry
	var prev *Entry
	for i := range n {
		e, err := Write(author, x.r.Group(), prev, ep, key, App, []byte{byte(i)})
		if err != nil {
			t.Fatal(err)
		}
		out, prev = append(out, e), e
	}
	return out
}

func TestEntryRoundTrip(t *testing.T) {
	x := newFixture(t)
	ep, key := x.epoch(t, x.member)
	e, err := Write(x.member, x.r.Group(), nil, ep, key, App, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := Decode(e.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if d.ID() != e.ID() {
		t.Fatal("the ID changed through the wire")
	}
	kind, body, err := d.Open(key)
	if err != nil || kind != App || string(body) != "hello" {
		t.Fatalf("open: %v %q %v", kind, body, err)
	}
	if _, _, err := d.Open(keys.EpochKey{9}); !errors.Is(err, ErrOpen) {
		t.Fatalf("opened under the wrong key: %v", err)
	}
}

func TestEntryRejects(t *testing.T) {
	x := newFixture(t)
	es := x.chain(t, x.member, 2)
	e := es[1]

	// A box moved onto another entry's header doesn't open.
	// Entry 2's box and nonce under entry 1's header: only the header
	// differs, so this fails only because the header is authenticated.
	_, key := x.epoch(t, x.member)
	if _, _, err := e.Open(key); err != nil {
		t.Fatalf("entry 2 doesn't open as written: %v", err)
	}
	moved := *es[0]
	moved.Box, moved.Nonce = e.Box, e.Nonce
	if _, _, err := moved.Open(key); !errors.Is(err, ErrOpen) {
		t.Fatalf("a box opened under another header: %v", err)
	}

	tampered := *e
	tampered.Seq = 5
	if _, err := Decode(tampered.Encode()); !errors.Is(err, ErrSignature) {
		t.Fatalf("a changed sequence number: %v", err)
	}
	first := *es[0]
	first.Prev = ID{1} // entry 1 must carry no prev, and doesn't encode one
	if _, err := Decode(first.Encode()); err != nil {
		t.Fatalf("entry 1's prev is dropped from the encoding: %v", err)
	}
	if _, err := Decode(append(e.Encode(), 'x')); !errors.Is(err, ErrMalformed) {
		t.Fatalf("a trailing byte: %v", err)
	}
	if _, err := Write(x.member, x.r.Group(), nil, roster.ID{}, keys.EpochKey{}, App, make([]byte, MaxBody+1)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("an oversized body: %v", err)
	}
}

func TestChainInAnyOrder(t *testing.T) {
	x := newFixture(t)
	es := x.chain(t, x.member, 4)
	s := NewSet(x.r.Group())
	f := x.fold(t)
	for _, i := range []int{2, 0, 3, 1} {
		if _, err := add(s, es[i], f); err != nil {
			t.Fatal(err)
		}
	}
	got := s.Log(x.member.Public()).Entries()
	if len(got) != 4 || got[3].ID() != es[3].ID() {
		t.Fatalf("got %d entries", len(got))
	}
	if fresh, err := add(s, es[1], f); fresh || err != nil {
		t.Fatalf("a duplicate: %v %v", fresh, err)
	}
}

func TestGapHidesLaterEntries(t *testing.T) {
	x := newFixture(t)
	es := x.chain(t, x.member, 3)
	s := NewSet(x.r.Group())
	f := x.fold(t)
	for _, e := range []*Entry{es[0], es[2]} {
		if _, err := add(s, e, f); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(s.Log(x.member.Public()).Entries()); n != 1 {
		t.Fatalf("%d entries visible across a gap", n)
	}
}

func TestForks(t *testing.T) {
	x := newFixture(t)
	ep, key := x.epoch(t, x.member)
	g := x.r.Group()
	a1, _ := Write(x.member, g, nil, ep, key, App, []byte("a1"))
	a2, _ := Write(x.member, g, a1, ep, key, App, []byte("a2"))
	b2, _ := Write(x.member, g, a1, ep, key, App, []byte("b2"))
	other1, _ := Write(x.member, g, nil, ep, key, App, []byte("other1"))
	c2, _ := Write(x.member, g, other1, ep, key, App, []byte("c2"))

	f := x.fold(t)
	s := NewSet(g)
	for _, e := range []*Entry{a1, a2} {
		if _, err := add(s, e, f); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := add(s, b2, f); !errors.Is(err, ErrForked) {
		t.Fatalf("two entries at one sequence number: %v", err)
	}
	l := s.Log(x.member.Public())
	if p := l.Fork(); p == nil || p.A.Seq != p.B.Seq {
		t.Fatal("no fork proof")
	}
	if len(l.Entries()) != 1 {
		t.Fatal("the forked sequence number is still visible")
	}
	a3, _ := Write(x.member, g, a2, ep, key, App, []byte("a3"))
	if _, err := add(s, a3, f); !errors.Is(err, ErrForked) {
		t.Fatalf("a forked log accepted more: %v", err)
	}

	// An entry whose prev contradicts the held chain is also a fork.
	s2 := NewSet(g)
	if _, err := add(s2, a1, f); err != nil {
		t.Fatal(err)
	}
	if _, err := add(s2, c2, f); !errors.Is(err, ErrForked) {
		t.Fatalf("an entry chained to another history: %v", err)
	}
	checkCounts(t, s.Log(x.member.Public()))
	checkCounts(t, s2.Log(x.member.Public()))
}

func TestRosterChecks(t *testing.T) {
	x := newFixture(t)
	f := x.fold(t)
	g := x.r.Group()
	ep, key := x.epoch(t, x.member)
	s := NewSet(g)

	stranger := me(9)
	e, _ := Write(stranger, g, nil, ep, key, App, nil)
	if _, err := add(s, e, f); !errors.Is(err, ErrNotWriter) {
		t.Fatalf("a stranger: %v", err)
	}
	e, _ = Write(x.mirror, g, nil, ep, key, App, nil)
	if _, err := add(s, e, f); !errors.Is(err, ErrNotWriter) {
		t.Fatalf("a mirror: %v", err)
	}
	e, _ = Write(x.member, g, nil, roster.ID{7}, key, App, nil)
	if _, err := add(s, e, f); !errors.Is(err, ErrUnknownEpoch) {
		t.Fatalf("an unknown epoch: %v", err)
	}
	e, _ = Write(x.member, roster.ID{8}, nil, ep, key, App, nil)
	if _, err := add(s, e, f); !errors.Is(err, ErrWrongGroup) {
		t.Fatalf("another group: %v", err)
	}
}

func TestRemovalCutoff(t *testing.T) {
	x := newFixture(t)
	es := x.chain(t, x.member, 5)
	g := x.r.Group()
	s := NewSet(g)
	f := x.fold(t)
	for _, e := range es {
		if _, err := add(s, e, f); err != nil {
			t.Fatal(err)
		}
	}
	// The admin had seen up to entry 3 when it removed the member.
	if _, err := (&roster.Writer{R: x.r, Me: x.admin}).Remove(x.member.Public(), 3, es[2].ID()); err != nil {
		t.Fatal(err)
	}
	f = x.fold(t)
	update(t, s, f)
	gone := s.Withdrawn()
	if len(gone) != 2 || gone[0].Seq < 4 || gone[1].Seq < 4 {
		t.Fatalf("withdrew %d entries", len(gone))
	}
	l := s.Log(x.member.Public())
	if got := l.Entries(); len(got) != 3 || got[2].ID() != es[2].ID() {
		t.Fatalf("%d entries after the cutoff", len(got))
	}
	if _, err := add(s, es[4], f); !errors.Is(err, ErrPastCutoff) {
		t.Fatalf("an entry past the cutoff: %v", err)
	}

	// A different history the removed member signs below the cutoff is
	// refused, not stored, and doesn't count as a fork that would hide the
	// entries it wrote before removal.
	ep := es[0].Epoch
	key := x.r.Keyring(x.member).Epochs[ep]
	for i := range 100 {
		forged, err := Write(x.member, g, es[0], ep, key, App, []byte{byte(i)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := add(s, forged, f); !errors.Is(err, ErrOffChain) {
			t.Fatalf("a removed author's other history below the cutoff: %v", err)
		}
	}
	if got := l.Entries(); len(got) != 3 || got[1].ID() != es[1].ID() || l.Fork() != nil || len(l.bySeq) != 3 {
		t.Fatalf("the forged history was kept: %d held", len(l.bySeq))
	}
	checkCounts(t, s.Log(x.member.Public()))
}

// TestRemovedLogFillsFromTheHead: a member that learns of a removal before
// any of the removed author's entries accepts them from the head down, and
// refuses ones not yet anchored.
func TestRemovedLogFillsFromTheHead(t *testing.T) {
	x := newFixture(t)
	es := x.chain(t, x.member, 4)
	if _, err := (&roster.Writer{R: x.r, Me: x.admin}).Remove(x.member.Public(), 3, es[2].ID()); err != nil {
		t.Fatal(err)
	}
	f := x.fold(t)
	s := NewSet(x.r.Group())
	if _, err := add(s, es[0], f); !errors.Is(err, ErrOffChain) {
		t.Fatalf("entry 1 before the head: %v", err)
	}
	if _, err := add(s, es[3], f); !errors.Is(err, ErrPastCutoff) {
		t.Fatalf("entry 4, past the head: %v", err)
	}
	for _, i := range []int{2, 1, 0} {
		if _, err := add(s, es[i], f); err != nil {
			t.Fatalf("entry %d, top-down: %v", i+1, err)
		}
	}
	if got := s.Log(x.member.Public()).Entries(); len(got) != 3 {
		t.Fatalf("%d entries", len(got))
	}
	checkCounts(t, s.Log(x.member.Public()))
}

func TestRemovalBeforeAnyEntrySeen(t *testing.T) {
	x := newFixture(t)
	es := x.chain(t, x.member, 2)
	if _, err := (&roster.Writer{R: x.r, Me: x.admin}).Remove(x.member.Public(), 0, [32]byte{}); err != nil {
		t.Fatal(err)
	}
	f := x.fold(t)
	s := NewSet(x.r.Group())
	if _, err := add(s, es[0], f); !errors.Is(err, ErrPastCutoff) {
		t.Fatalf("an entry from a member removed before any was seen: %v", err)
	}
	if l := s.Log(x.member.Public()); l != nil && len(l.Entries()) != 0 {
		t.Fatal("entries visible")
	}
}

// TestLaggingMemberKeepsEntries: a member that holds a removed author's
// early entries but not the recorded head keeps showing them, and drops
// one only when the head's chain contradicts it.
func TestLaggingMemberKeepsEntries(t *testing.T) {
	x := newFixture(t)
	es := x.chain(t, x.member, 3)
	s := NewSet(x.r.Group())
	f := x.fold(t)
	for _, e := range es[:2] {
		if _, err := add(s, e, f); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := (&roster.Writer{R: x.r, Me: x.admin}).Remove(x.member.Public(), 3, es[2].ID()); err != nil {
		t.Fatal(err)
	}
	f = x.fold(t)
	update(t, s, f)
	l := s.Log(x.member.Public())
	if len(s.Withdrawn()) != 0 || len(l.Entries()) != 2 {
		t.Fatalf("a lagging member lost entries on the head's chain: %d left", len(l.Entries()))
	}
	if _, err := add(s, es[2], f); err != nil {
		t.Fatal(err)
	}
	if len(l.Entries()) != 3 || l.low != 1 {
		t.Fatalf("the head didn't anchor the held chain: %d visible, low %d", len(l.Entries()), l.low)
	}
	checkCounts(t, s.Log(x.member.Public()))
}

// TestHeadEvictsContradictedEntry: when the head's chain names a different
// entry than one held, the held one is withdrawn and reported.
func TestHeadEvictsContradictedEntry(t *testing.T) {
	x := newFixture(t)
	ep, key := x.epoch(t, x.member)
	g := x.r.Group()
	a1, _ := Write(x.member, g, nil, ep, key, App, []byte("a1"))
	a2, _ := Write(x.member, g, a1, ep, key, App, []byte("a2"))
	b2, _ := Write(x.member, g, a1, ep, key, App, []byte("b2"))
	b3, _ := Write(x.member, g, b2, ep, key, App, []byte("b3"))
	s := NewSet(g)
	f := x.fold(t)
	for _, e := range []*Entry{a1, a2} {
		if _, err := add(s, e, f); err != nil {
			t.Fatal(err)
		}
	}
	// The remover had seen the b branch.
	if _, err := (&roster.Writer{R: x.r, Me: x.admin}).Remove(x.member.Public(), 3, b3.ID()); err != nil {
		t.Fatal(err)
	}
	f = x.fold(t)
	if _, err := add(s, b3, f); err != nil { // add's Update applies the removal
		t.Fatal(err)
	}
	gone := s.Withdrawn()
	if len(gone) != 1 || gone[0].ID() != a2.ID() {
		t.Fatalf("withdrew %d entries", len(gone))
	}
	if _, err := add(s, b2, f); err != nil {
		t.Fatal(err)
	}
	if got := s.Log(x.member.Public()).Entries(); len(got) != 3 || got[1].ID() != b2.ID() {
		t.Fatalf("%d entries visible", len(got))
	}
	checkCounts(t, s.Log(x.member.Public()))
}

// TestRemovalThatStopsCounting: a log cut by a removal is a member's log
// again once that removal no longer counts.
func TestRemovalThatStopsCounting(t *testing.T) {
	x := newFixture(t)
	es := x.chain(t, x.member, 3)
	s := NewSet(x.r.Group())
	f := x.fold(t)
	for _, e := range es {
		if _, err := add(s, e, f); err != nil {
			t.Fatal(err)
		}
	}
	// A removal written in a copy where the admin hasn't seen its own
	// demotion: in the merged roster it doesn't count.
	stale, err := roster.New(x.r.Op(x.r.Group()))
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range f.Order[1:] {
		if _, err := stale.Add(o); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := (&roster.Writer{R: x.r, Me: x.owner}).SetRole(x.admin.Public(), roster.Member); err != nil {
		t.Fatal(err)
	}
	rm, err := (&roster.Writer{R: stale, Me: x.admin}).Remove(x.member.Public(), 1, es[0].ID())
	if err != nil {
		t.Fatal(err)
	}
	// First a member sees only the removal.
	if _, err := stale.Fold(); err != nil {
		t.Fatal(err)
	}
	sf, _ := stale.Fold()
	update(t, s, sf)
	if len(s.Log(x.member.Public()).Entries()) != 1 {
		t.Fatal("setup: the removal should cut the log")
	}
	// Then the demotion, which sorts first, so the removal stops counting.
	if _, err := x.r.Add(rm); err != nil {
		t.Fatal(err)
	}
	f = x.fold(t)
	if f.Counts[rm.ID()] {
		t.Fatal("setup: the removal should no longer count")
	}
	update(t, s, f)
	for _, e := range es[1:] {
		if _, err := add(s, e, f); err != nil {
			t.Fatalf("an entry from a member no longer removed: %v", err)
		}
	}
	if len(s.Log(x.member.Public()).Entries()) != 3 {
		t.Fatal("the log wasn't restored")
	}
	checkCounts(t, s.Log(x.member.Public()))
}

func TestEpochMustCount(t *testing.T) {
	x := newFixture(t)
	s := NewSet(x.r.Group())
	// A rekey by a member doesn't count; an entry under it is refused.
	rk := &roster.Op{Group: x.r.Group(), Kind: roster.Rekey, Parents: x.r.Heads(), CommitSecret: [32]byte{1}, CommitEpoch: [32]byte{2}}
	for _, p := range rk.Parents {
		rk.Lamport = max(rk.Lamport, x.r.Op(p).Lamport)
	}
	rk.Lamport++
	rk.Sign(x.member)
	if _, err := x.r.Add(rk); err != nil {
		t.Fatal(err)
	}
	f := x.fold(t)
	e, _ := Write(x.member, x.r.Group(), nil, rk.ID(), keys.EpochKey{3}, App, nil)
	if _, err := add(s, e, f); !errors.Is(err, ErrUnknownEpoch) {
		t.Fatalf("an entry under a non-counting rekey: %v", err)
	}
}

func TestRemovedMirrorStillNoWriter(t *testing.T) {
	x := newFixture(t)
	ep, key := x.epoch(t, x.member)
	if _, err := (&roster.Writer{R: x.r, Me: x.admin}).Remove(x.mirror.Public(), 1, [32]byte{1}); err != nil {
		t.Fatal(err)
	}
	f := x.fold(t)
	e, _ := Write(x.mirror, x.r.Group(), nil, ep, key, App, nil)
	if _, err := add(NewSet(x.r.Group()), e, f); !errors.Is(err, ErrNotWriter) {
		t.Fatalf("a removed mirror: %v", err)
	}
}

func TestWindow(t *testing.T) {
	x := newFixture(t)
	ep, key := x.epoch(t, x.member)
	f := x.fold(t)
	first, _ := Write(x.member, x.r.Group(), nil, ep, key, App, nil)
	far := first
	for range Window + 1 {
		far, _ = Write(x.member, x.r.Group(), far, ep, key, App, nil)
	}
	s := NewSet(x.r.Group())
	if _, err := add(s, far, f); !errors.Is(err, ErrTooFar) {
		t.Fatalf("an entry %d past an empty log: %v", far.Seq, err)
	}
	if _, err := add(s, first, f); err != nil {
		t.Fatal(err)
	}
}

// TestCutKeepsForkHidden: cutting a forked log doesn't reveal either branch
// past the fork point until the remover's head anchors one.
func TestCutKeepsForkHidden(t *testing.T) {
	x := newFixture(t)
	ep, key := x.epoch(t, x.member)
	g := x.r.Group()
	a1, _ := Write(x.member, g, nil, ep, key, App, []byte("a1"))
	a2, _ := Write(x.member, g, a1, ep, key, App, []byte("a2"))
	b2, _ := Write(x.member, g, a1, ep, key, App, []byte("b2"))
	b3, _ := Write(x.member, g, b2, ep, key, App, []byte("b3"))
	s := NewSet(g)
	f := x.fold(t)
	for _, e := range []*Entry{a1, a2} {
		if _, err := add(s, e, f); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := add(s, b2, f); !errors.Is(err, ErrForked) {
		t.Fatal(err)
	}
	if gone := s.Withdrawn(); len(gone) != 1 || gone[0].ID() != a2.ID() {
		t.Fatalf("the fork withdrew %d entries", len(gone))
	}
	if _, err := (&roster.Writer{R: x.r, Me: x.admin}).Remove(x.member.Public(), 3, b3.ID()); err != nil {
		t.Fatal(err)
	}
	f = x.fold(t)
	update(t, s, f)
	l := s.Log(x.member.Public())
	if n := len(l.Entries()); n != 1 {
		t.Fatalf("cutting a forked log showed %d entries", n)
	}
	if gone := s.Withdrawn(); len(gone) != 0 {
		t.Fatalf("the cut withdrew %d entries already withdrawn", len(gone))
	}
	for _, e := range []*Entry{b3, b2} {
		if _, err := add(s, e, f); err != nil {
			t.Fatal(err)
		}
	}
	if got := l.Entries(); len(got) != 3 || got[1].ID() != b2.ID() {
		t.Fatalf("the head's chain didn't show past the fork point: %d", len(got))
	}
	checkCounts(t, s.Log(x.member.Public()))
}

// add gives s fold f (as a caller does when its roster changes) and adds e.
func add(s *Set, e *Entry, f *roster.Result) (bool, error) {
	if err := s.Update(f); err != nil {
		return false, err
	}
	return s.Add(e)
}

func update(t *testing.T, s *Set, f *roster.Result) {
	t.Helper()
	if err := s.Update(f); err != nil {
		t.Fatal(err)
	}
}

func TestAddNeedsAFold(t *testing.T) {
	x := newFixture(t)
	e := x.chain(t, x.member, 1)[0]
	if _, err := NewSet(x.r.Group()).Add(e); !errors.Is(err, ErrNoRoster) {
		t.Fatalf("an Add before any Update: %v", err)
	}
}

func TestMaxAhead(t *testing.T) {
	x := newFixture(t)
	ep, key := x.epoch(t, x.member)
	f := x.fold(t)
	s := NewSet(x.r.Group())
	update(t, s, f)
	// A full-size entry 1, so with the budget full it can't fit except
	// through the gap-closing exemption.
	first, err := Write(x.member, x.r.Group(), nil, ep, key, App, make([]byte, MaxBody))
	if err != nil {
		t.Fatal(err)
	}
	prev := first
	held, heldBytes := 0, 0
	for range 100 {
		var err error
		if prev, err = Write(x.member, x.r.Group(), prev, ep, key, App, make([]byte, MaxBody)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Add(prev); errors.Is(err, ErrTooFar) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		held++
		heldBytes += len(prev.Box)
	}
	if heldBytes > MaxAhead || heldBytes+len(prev.Box) <= MaxAhead || held == 100 {
		t.Fatalf("held %d entries (%d bytes) past a gap; the refused one would make %d", held, heldBytes, heldBytes+len(prev.Box))
	}
	// With the budget full, the entry that closes the gap is still taken,
	// and what was held ahead shows.
	if _, err := s.Add(first); err != nil {
		t.Fatalf("the gap-closing entry with the budget full: %v", err)
	}
	if n := len(s.Log(x.member.Public()).Entries()); n != held+1 {
		t.Fatalf("%d visible after closing the gap, want %d", n, held+1)
	}
	checkCounts(t, s.Log(x.member.Public()))
}

// TestForkSurvivesLiftedRemoval: a forked log stays forked, through the
// real fold path, when a removal that had cut it stops counting.
func TestForkSurvivesLiftedRemoval(t *testing.T) {
	x := newFixture(t)
	ep, key := x.epoch(t, x.member)
	g := x.r.Group()
	w := func(prev *Entry, body string) *Entry {
		e, err := Write(x.member, g, prev, ep, key, App, []byte(body))
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	a1 := w(nil, "a1")
	a2, b2 := w(a1, "a2"), w(a1, "b2")
	s := NewSet(g)
	f := x.fold(t)
	update(t, s, f)
	for _, e := range []*Entry{a1, a2} {
		if _, err := s.Add(e); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Add(b2); !errors.Is(err, ErrForked) {
		t.Fatal(err)
	}
	s.Withdrawn()
	// A removal written where the admin hasn't seen its own demotion, which
	// sorts first in the merged roster, so the removal stops counting.
	stale, err := roster.New(x.r.Op(x.r.Group()))
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range f.Order[1:] {
		if _, err := stale.Add(o); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := (&roster.Writer{R: x.r, Me: x.owner}).SetRole(x.admin.Public(), roster.Member); err != nil {
		t.Fatal(err)
	}
	rm, err := (&roster.Writer{R: stale, Me: x.admin}).Remove(x.member.Public(), 2, b2.ID())
	if err != nil {
		t.Fatal(err)
	}
	sf, err := stale.Fold()
	if err != nil {
		t.Fatal(err)
	}
	update(t, s, sf)
	if l := s.Log(x.member.Public()); !l.removed || l.cutSeq != 2 {
		t.Fatal("setup: the stale fold should cut the log")
	}
	if _, err := x.r.Add(rm); err != nil {
		t.Fatal(err)
	}
	update(t, s, x.fold(t))
	l := s.Log(x.member.Public())
	if l.removed || l.Fork() == nil || len(l.Entries()) != 1 || len(s.Withdrawn()) != 0 {
		t.Fatalf("after a lifted removal: removed %v, fork %v, %d visible", l.removed, l.Fork() != nil, len(l.Entries()))
	}
	checkCounts(t, l)
}

// checkCounts recomputes the held and shown byte counts from scratch.
func checkCounts(t *testing.T, l *Log) {
	t.Helper()
	held, shown := 0, 0
	for seq, e := range l.bySeq {
		held += len(e.Box)
		if seq <= l.top {
			shown += len(e.Box)
		}
	}
	if held != l.held || shown != l.shown {
		t.Fatalf("counts drifted: held %d (tracked %d), shown %d (tracked %d)", held, l.held, shown, l.shown)
	}
}

// stalePair returns a roster copy as of fold f (where the admin is still an
// admin) after demoting the admin in the real roster, so that a removal the
// admin writes in the copy won't count once merged.
func (x *fixture) stalePair(t *testing.T, f *roster.Result) *roster.Roster {
	t.Helper()
	stale, err := roster.New(x.r.Op(x.r.Group()))
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range f.Order[1:] {
		if _, err := stale.Add(o); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := (&roster.Writer{R: x.r, Me: x.owner}).SetRole(x.admin.Public(), roster.Member); err != nil {
		t.Fatal(err)
	}
	return stale
}

func TestAddVerifiesWhatItStores(t *testing.T) {
	x := newFixture(t)
	s := NewSet(x.r.Group())
	update(t, s, x.fold(t))
	e := x.chain(t, x.member, 1)[0]
	mutated := *e
	mutated.Seq = 7
	if _, err := s.Add(&mutated); !errors.Is(err, ErrSignature) {
		t.Fatalf("a mutated entry: %v", err)
	}
	ep, _ := x.epoch(t, x.member)
	unsigned := &Entry{Group: x.r.Group(), Author: x.member.Public(), Seq: 1, Epoch: ep, Box: make([]byte, 40)}
	if _, err := s.Add(unsigned); err == nil {
		t.Fatal("an unsigned entry was accepted")
	}
}

func TestReadsAreCopies(t *testing.T) {
	x := newFixture(t)
	s := NewSet(x.r.Group())
	update(t, s, x.fold(t))
	es := x.chain(t, x.member, 2)
	for _, e := range es {
		if _, err := s.Add(e); err != nil {
			t.Fatal(err)
		}
	}
	es[1].Box[0] ^= 1 // the caller's own entry, after adding it
	l := s.Log(x.member.Public())
	h := l.Head()
	h.Box[0] ^= 1
	h.Seq = 99
	l.Entries()[0].Box[0] ^= 1
	_, key := x.epoch(t, x.member)
	for _, e := range l.Entries() {
		if _, _, err := e.Open(key); err != nil || e.Seq > 2 {
			t.Fatal("a caller's change reached the log")
		}
	}
	checkCounts(t, l)
}

func TestForkFoundAtCapacity(t *testing.T) {
	x := newFixture(t)
	ep, key := x.epoch(t, x.member)
	g := x.r.Group()
	s := NewSet(g)
	update(t, s, x.fold(t))
	first, _ := Write(x.member, g, nil, ep, key, App, nil)
	prev := first
	var second *Entry
	for {
		var err error
		if prev, err = Write(x.member, g, prev, ep, key, App, make([]byte, MaxBody)); err != nil {
			t.Fatal(err)
		}
		if second == nil {
			second = prev
		}
		if _, err := s.Add(prev); errors.Is(err, ErrTooFar) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
	}
	other, _ := Write(x.member, g, first, ep, key, App, make([]byte, MaxBody))
	if other.Seq != second.Seq {
		t.Fatal("setup")
	}
	if _, err := s.Add(other); !errors.Is(err, ErrForked) {
		t.Fatalf("a conflicting entry with the budget full: %v", err)
	}
	if s.Log(x.member.Public()).Fork() == nil {
		t.Fatal("no fork proof")
	}
}

// TestEpochThatStopsCountingHides: an entry under an epoch a later fold no
// longer counts leaves view, with what follows it.
func TestEpochThatStopsCountingHides(t *testing.T) {
	x := newFixture(t)
	f := x.fold(t)
	stale := x.stalePair(t, f)
	rm, err := (&roster.Writer{R: stale, Me: x.admin}).Remove(x.mirror.Public(), 0, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	sf, err := stale.Fold()
	if err != nil {
		t.Fatal(err)
	}
	// The owner, seeing only the stale roster, writes under the removal's
	// epoch.
	key := stale.Keyring(x.owner).Epochs[rm.ID()]
	e1, _ := Write(x.owner, x.r.Group(), nil, rm.ID(), key, App, []byte("1"))
	e2, _ := Write(x.owner, x.r.Group(), e1, rm.ID(), key, App, []byte("2"))
	s := NewSet(x.r.Group())
	update(t, s, sf)
	for _, e := range []*Entry{e1, e2} {
		if _, err := s.Add(e); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := x.r.Add(rm); err != nil {
		t.Fatal(err)
	}
	update(t, s, x.fold(t))
	if n := len(s.Log(x.owner.Public()).Entries()); n != 0 {
		t.Fatalf("%d entries under a no-longer-counting epoch still show", n)
	}
	if n := len(s.Withdrawn()); n != 2 {
		t.Fatalf("withdrew %d", n)
	}
	// Back on the stale fold, where it counts, they show again.
	update(t, s, sf)
	if n := len(s.Log(x.owner.Public()).Entries()); n != 2 {
		t.Fatalf("%d entries after the epoch counts again", n)
	}
	checkCounts(t, s.Log(x.owner.Public()))
}

// TestLiftedCutTrims: a lifted removal leaves the log within a live log's
// bounds, though the head's chain had filled more.
func TestLiftedCutTrims(t *testing.T) {
	x := newFixture(t)
	f := x.fold(t)
	ep, key := x.epoch(t, x.member)
	g := x.r.Group()
	var es []*Entry
	var prev *Entry
	for range 80 {
		e, err := Write(x.member, g, prev, ep, key, App, make([]byte, MaxBody))
		if err != nil {
			t.Fatal(err)
		}
		es, prev = append(es, e), e
	}
	stale := x.stalePair(t, f)
	rm, err := (&roster.Writer{R: stale, Me: x.admin}).Remove(x.member.Public(), 80, es[79].ID())
	if err != nil {
		t.Fatal(err)
	}
	sf, err := stale.Fold()
	if err != nil {
		t.Fatal(err)
	}
	s := NewSet(g)
	update(t, s, sf)
	for i := 79; i >= 1; i-- { // top-down, entry 1 withheld
		if _, err := s.Add(es[i]); err != nil {
			t.Fatal(err)
		}
	}
	l := s.Log(x.member.Public())
	if l.ahead() <= MaxAhead {
		t.Fatal("setup: the head's chain should hold more than a live log may")
	}
	if _, err := x.r.Add(rm); err != nil {
		t.Fatal(err)
	}
	update(t, s, x.fold(t))
	if l.removed || l.ahead() > MaxAhead {
		t.Fatalf("after the lift: removed %v, %d bytes held ahead", l.removed, l.ahead())
	}
	checkCounts(t, l)
}

func TestWriteRefusesUnencodableSeq(t *testing.T) {
	x := newFixture(t)
	ep, key := x.epoch(t, x.member)
	last := &Entry{Group: x.r.Group(), Author: x.member.Public(), Seq: math.MaxInt64}
	if _, err := Write(x.member, x.r.Group(), last, ep, key, App, nil); !errors.Is(err, ErrMalformed) {
		t.Fatalf("a successor of the last encodable entry: %v", err)
	}
	// A predecessor at sequence 0 isn't an entry: its successor would be
	// entry 1 sealed under a Prev the wire never carries.
	zero := x.chain(t, x.member, 1)[0].clone()
	zero.Seq = 0
	if _, err := Write(x.member, x.r.Group(), zero, ep, key, App, nil); !errors.Is(err, ErrMalformed) {
		t.Fatalf("a predecessor at sequence 0: %v", err)
	}
}

func TestDecodeRefusesEmptyBox(t *testing.T) {
	x := newFixture(t)
	e := x.chain(t, x.member, 1)[0]
	c := *e
	c.Box = nil
	c.Sig = x.member.Sign(c.signed())
	if _, err := Decode(c.Encode()); !errors.Is(err, ErrMalformed) {
		t.Fatalf("an empty box: %v", err)
	}
}

func TestUpdateRefusesForeignFold(t *testing.T) {
	x := newFixture(t)
	other, err := roster.Found(me(9), "h", 1)
	if err != nil {
		t.Fatal(err)
	}
	of, err := other.Fold()
	if err != nil {
		t.Fatal(err)
	}
	s := NewSet(x.r.Group())
	if err := s.Update(of); !errors.Is(err, ErrWrongGroup) {
		t.Fatalf("another group's fold: %v", err)
	}
	if _, err := s.Add(x.chain(t, x.member, 1)[0]); !errors.Is(err, ErrNoRoster) {
		t.Fatalf("a refused fold was kept: %v", err)
	}
}

// TestRemovedHeadUnderStaleEpoch: a removed author's recorded head under an
// epoch that stopped counting still anchors the eligible entries below it,
// so a fresh member shows what one that held them all along shows.
func TestRemovedHeadUnderStaleEpoch(t *testing.T) {
	x := newFixture(t)
	es := x.chain(t, x.member, 2)
	f := x.fold(t)
	stale := x.stalePair(t, f)
	rm, err := (&roster.Writer{R: stale, Me: x.admin}).Remove(x.mirror.Public(), 0, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	e3, err := Write(x.member, x.r.Group(), es[1], rm.ID(), stale.Keyring(x.member).Epochs[rm.ID()], App, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x.r.Add(rm); err != nil {
		t.Fatal(err)
	}
	if _, err := (&roster.Writer{R: x.r, Me: x.owner}).Remove(x.member.Public(), 3, e3.ID()); err != nil {
		t.Fatal(err)
	}
	s := NewSet(x.r.Group())
	update(t, s, x.fold(t))
	for _, e := range []*Entry{e3, es[1], es[0]} {
		if _, err := s.Add(e); err != nil {
			t.Fatalf("entry %d: %v", e.Seq, err)
		}
	}
	l := s.Log(x.member.Public())
	if n := len(l.Entries()); n != 2 {
		t.Fatalf("%d entries show, want the 2 under a counting epoch", n)
	}
	checkCounts(t, l)
}

// TestHidingKeepsBounds: entries a fold hides are held ahead within a live
// log's bounds.
func TestHidingKeepsBounds(t *testing.T) {
	x := newFixture(t)
	f := x.fold(t)
	stale := x.stalePair(t, f)
	rm, err := (&roster.Writer{R: stale, Me: x.admin}).Remove(x.mirror.Public(), 0, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	sf, err := stale.Fold()
	if err != nil {
		t.Fatal(err)
	}
	key := stale.Keyring(x.owner).Epochs[rm.ID()]
	s := NewSet(x.r.Group())
	update(t, s, sf)
	var prev *Entry
	for range 80 {
		if prev, err = Write(x.owner, x.r.Group(), prev, rm.ID(), key, App, make([]byte, MaxBody)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Add(prev); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := x.r.Add(rm); err != nil {
		t.Fatal(err)
	}
	update(t, s, x.fold(t))
	l := s.Log(x.owner.Public())
	if l.top != 0 || l.ahead() > MaxAhead {
		t.Fatalf("after the epoch stopped counting: top %d, %d bytes held ahead", l.top, l.ahead())
	}
	checkCounts(t, l)
}
