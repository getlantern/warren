package session

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/getlantern/warren/bencode"
	"github.com/getlantern/warren/group/keys"
	"github.com/getlantern/warren/group/memberlog"
	"github.com/getlantern/warren/group/roster"
	gsync "github.com/getlantern/warren/group/sync"
)

var now = time.Unix(1_800_000_000, 0)

func me(b byte) *keys.Identity { return keys.IdentityFromSeed([32]byte{b}) }

// group is a roster with an owner and two members, and G.
type group struct {
	r                    *roster.Roster
	rBefore              *roster.Roster // as newGroup made it
	g                    keys.Secret
	owner, m1, m2, other *keys.Identity
}

func newGroup(t *testing.T) *group {
	t.Helper()
	x := &group{owner: me(1), m1: me(2), m2: me(3), other: me(9)}
	r, err := roster.Found(x.owner, "g", 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []*keys.Identity{x.m1, x.m2} {
		if _, err := (&roster.Writer{R: r, Me: x.owner}).Add(m.Public(), "m", roster.Member, keys.PublicKey{}); err != nil {
			t.Fatal(err)
		}
	}
	x.r, x.g = r, r.Keyring(x.owner).Secrets[r.Group()]
	x.rBefore = copyRoster(t, r)
	return x
}

// member is one member's copy of the roster and its logs.
type member struct {
	id   *keys.Identity
	r    *roster.Roster
	logs *memberlog.Set
}

func copyRoster(t *testing.T, r *roster.Roster) *roster.Roster {
	t.Helper()
	c, err := roster.New(r.Op(r.Group()))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range r.IDs() {
		if id != r.Group() {
			if _, err := c.Add(r.Op(id)); err != nil {
				t.Fatal(err)
			}
		}
	}
	return c
}

func (x *group) member(t *testing.T, id *keys.Identity, r *roster.Roster) *member {
	t.Helper()
	m := &member{id: id, r: copyRoster(t, r), logs: memberlog.NewSet(r.Group())}
	f, err := m.r.Fold()
	if err != nil {
		t.Fatal(err)
	}
	if err := m.logs.Update(f); err != nil {
		t.Fatal(err)
	}
	return m
}

func (x *group) rendezvous(id *keys.Identity) keys.PublicKey {
	return id.Rendezvous(x.g, keys.PeriodOf(now)).Public()
}

// call runs a session between caller and callee over a pipe: the caller
// signing as callerKey, calling the callee's rendezvous key.
func (x *group) call(t *testing.T, caller, callee *member, callerKey keys.PublicKey) (keys.PublicKey, keys.PublicKey, error, error) {
	t.Helper()
	return x.callWith(t, caller, callee, callerKey, nil)
}

// callWith is call, the caller signing over callerSecret if set: a proof
// made for another connection.
func (x *group) callWith(t *testing.T, caller, callee *member, callerKey keys.PublicKey, callerSecret []byte) (keys.PublicKey, keys.PublicKey, error, error) {
	t.Helper()
	a, b := net.Pipe()
	secret := []byte("0123456789abcdef0123456789abcdef")
	cs := secret
	if callerSecret != nil {
		cs = callerSecret
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	type res struct {
		peer keys.PublicKey
		err  error
	}
	done := make(chan res, 1)
	go func() {
		p, err := Run(ctx, b, Config{Me: callee.id, Group: x.g, Roster: callee.r, Logs: callee.logs, Secret: secret,
			Local: x.rendezvous(callee.id), Peer: callerKey, Now: now})
		if err != nil {
			b.Close()
		}
		done <- res{p, err}
	}()
	p, err := Run(ctx, a, Config{Me: caller.id, Group: x.g, Roster: caller.r, Logs: caller.logs, Secret: cs, Caller: true,
		Local: callerKey, Peer: x.rendezvous(callee.id), Now: now})
	if err != nil {
		a.Close()
	}
	r := <-done
	a.Close()
	b.Close()
	return p, r.peer, err, r.err
}

func TestMembersSync(t *testing.T) {
	x := newGroup(t)
	a, b := x.member(t, x.m1, x.r), x.member(t, x.m2, x.r)
	ep := x.r.Keyring(x.m1)
	f, _ := x.r.Fold()
	e, err := memberlog.Write(x.m1, x.r.Group(), nil, f.Current, ep.Epochs[f.Current], memberlog.App, []byte("hi"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.logs.Add(e); err != nil {
		t.Fatal(err)
	}
	pa, pb, ea, eb := x.call(t, a, b, x.rendezvous(x.m1))
	if ea != nil || eb != nil {
		t.Fatalf("session: %v / %v", ea, eb)
	}
	if pa != x.m2.Public() || pb != x.m1.Public() {
		t.Fatal("each side should see the other's member key")
	}
	if l := b.logs.Log(x.m1.Public()); l == nil || len(l.Entries()) != 1 {
		t.Fatal("the entry didn't sync")
	}
}

func TestStrangerRefused(t *testing.T) {
	x := newGroup(t)
	a, b := x.member(t, x.m1, x.r), x.member(t, x.m2, x.r)
	a.id = x.other // signs as a key not on the roster
	_, _, _, eb := x.call(t, a, b, x.rendezvous(x.m1))
	if !errors.Is(eb, ErrNotMember) {
		t.Fatalf("callee admitted a stranger: %v", eb)
	}
}

func TestRemovedMemberRefused(t *testing.T) {
	x := newGroup(t)
	a := x.member(t, x.m1, x.r)
	if _, err := (&roster.Writer{R: x.r, Me: x.owner}).Remove(x.m1.Public(), 0, [32]byte{}); err != nil {
		t.Fatal(err)
	}
	b := x.member(t, x.m2, x.r) // knows of the removal
	_, _, _, eb := x.call(t, a, b, x.rendezvous(x.m1))
	if !errors.Is(eb, ErrNotMember) {
		t.Fatalf("callee admitted a removed member: %v", eb)
	}
}

// TestTransportKeyMustBeTheMembers: a member calling under another
// member's rendezvous key (or any key not its own) is refused.
func TestTransportKeyMustBeTheMembers(t *testing.T) {
	x := newGroup(t)
	a, b := x.member(t, x.m1, x.r), x.member(t, x.m2, x.r)
	_, _, _, eb := x.call(t, a, b, x.rendezvous(x.owner))
	if !errors.Is(eb, ErrTransportKey) {
		t.Fatalf("a member calling under another's rendezvous key: %v", eb)
	}
}

// TestSyncSessionAdmitsNewMember: a member the callee hasn't heard of yet
// calls under the sync key, presents the add that admits it, and syncs.
func TestSyncSessionAdmitsNewMember(t *testing.T) {
	x := newGroup(t)
	b := x.member(t, x.m2, x.r) // the callee, before the newcomer's add
	newcomer := me(7)
	if _, err := (&roster.Writer{R: x.r, Me: x.owner}).Add(newcomer.Public(), "n", roster.Member, keys.PublicKey{}); err != nil {
		t.Fatal(err)
	}
	n := x.member(t, newcomer, x.r)
	syncKey := x.g.SyncKey(keys.PeriodOf(now), x.rendezvous(x.m2)).Public()
	pa, pb, ea, eb := x.call(t, n, b, syncKey)
	if ea != nil || eb != nil {
		t.Fatalf("sync session: %v / %v", ea, eb)
	}
	if pa != x.m2.Public() || pb != newcomer.Public() {
		t.Fatal("wrong peers")
	}
	f, _ := b.r.Fold()
	if f.Roles[newcomer.Public()] != roster.Member {
		t.Fatal("the callee didn't learn of the newcomer")
	}
}

// TestSyncSessionStillNeedsMembership: the sync key alone (G) admits
// nobody: a caller whose chain doesn't admit its key is refused.
func TestSyncSessionStillNeedsMembership(t *testing.T) {
	x := newGroup(t)
	b := x.member(t, x.m2, x.r)
	a := x.member(t, x.other, x.r) // holds G, never admitted
	syncKey := x.g.SyncKey(keys.PeriodOf(now), x.rendezvous(x.m2)).Public()
	_, _, _, eb := x.call(t, a, b, syncKey)
	if !errors.Is(eb, ErrNotMember) {
		t.Fatalf("a sync-key caller with no add was admitted: %v", eb)
	}
}

// TestProofBinding: a proof is bound to the group, the role, both
// transport keys and the connection secret.
func TestProofBinding(t *testing.T) {
	x := newGroup(t)
	g := x.r.Group()
	ra, rb, rc := x.rendezvous(x.m1), x.rendezvous(x.m2), x.rendezvous(x.owner)
	sig := x.m1.Sign(proof(g, true, ra, rb, []byte("secret")))
	for name, other := range map[string][]byte{
		"another secret": proof(g, true, ra, rb, []byte("other")),
		"reflected":      proof(g, false, ra, rb, []byte("secret")),
		"another callee": proof(g, true, ra, rc, []byte("secret")),
		"another caller": proof(g, true, rc, rb, []byte("secret")),
		"another group":  proof(roster.ID{1}, true, ra, rb, []byte("secret")),
	} {
		if x.m1.Public().Verify(other, sig) {
			t.Fatalf("a proof verified for %s", name)
		}
	}
}

// TestCapturedProofCantBeReplayed: a member who saw another's proof when
// called by it can't replay it to a third member under the sync key, with
// the same secret.
func TestCapturedProofCantBeReplayed(t *testing.T) {
	x := newGroup(t)
	c := x.member(t, x.owner, x.r) // the third member, called
	secret := []byte("0123456789abcdef0123456789abcdef")
	// What m2 saw when m1 called it.
	captured := x.m1.Sign(proof(x.r.Group(), true, x.rendezvous(x.m1), x.rendezvous(x.m2), secret))
	syncKey := x.g.SyncKey(keys.PeriodOf(now), x.rendezvous(x.owner)).Public()
	a, b := net.Pipe()
	defer a.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := Run(ctx, b, Config{Me: c.id, Group: x.g, Roster: c.r, Logs: c.logs, Secret: secret,
			Local: x.rendezvous(x.owner), Peer: syncKey, Now: now})
		done <- err
	}()
	// The replayer reads the callee's hello and sends m1's key and proof.
	s := newSession(Config{}, a)
	if _, _, err := s.read(); err != nil {
		t.Fatal(err)
	}
	pub := x.m1.Public()
	hello := bencode.Append(nil, bencode.Value{Kind: bencode.Dict, Dict: []bencode.Pair{
		{Key: []byte("h"), Value: bencode.Value{Kind: bencode.List}},
		{Key: []byte("k"), Value: bencode.Value{Kind: bencode.String, Str: pub[:]}},
		{Key: []byte("s"), Value: bencode.Value{Kind: bencode.String, Str: captured}},
	}})
	f := binary.BigEndian.AppendUint32(nil, uint32(len(hello)+1))
	a.Write(append(append(f, frameHello), hello...))
	if err := <-done; !errors.Is(err, ErrBadProof) {
		t.Fatalf("a replayed proof: %v", err)
	}
}

// TestFailedSessionReturns: a peer that sends garbage and never reads
// doesn't leave Run blocked writing.
func TestFailedSessionReturns(t *testing.T) {
	x := newGroup(t)
	b := x.member(t, x.m2, x.r)
	p, q := net.Pipe()
	defer p.Close()
	done := make(chan error, 1)
	go func() {
		_, err := Run(context.Background(), q, Config{Me: b.id, Group: x.g, Roster: b.r, Logs: b.logs,
			Secret: []byte("s"), Local: x.rendezvous(x.m2), Peer: x.rendezvous(x.m1), Now: now})
		done <- err
	}()
	p.Write([]byte{0, 0, 0, 2, 'z', 'z'}) // a frame of no known kind; then never read
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("garbage was accepted")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run stayed blocked after the session failed")
	}
}

// TestChainAcrossFrames: an add chain larger than one frame still admits
// the newcomer; one past the cap is refused.
func TestChainAcrossFrames(t *testing.T) {
	defer func(c, o int) { chainChunk, maxChainOps = c, o }(chainChunk, maxChainOps)
	chainChunk = 1 // one operation a frame
	x := newGroup(t)
	b := x.member(t, x.m2, x.r)
	for range 5 {
		if _, err := (&roster.Writer{R: x.r, Me: x.owner}).Rekey(); err != nil {
			t.Fatal(err)
		}
	}
	newcomer := me(7)
	if _, err := (&roster.Writer{R: x.r, Me: x.owner}).Add(newcomer.Public(), "n", roster.Member, keys.PublicKey{}); err != nil {
		t.Fatal(err)
	}
	n := x.member(t, newcomer, x.r)
	syncKey := x.g.SyncKey(keys.PeriodOf(now), x.rendezvous(x.m2)).Public()
	if _, _, ea, eb := x.call(t, n, b, syncKey); ea != nil || eb != nil {
		t.Fatalf("a chain over several frames: %v / %v", ea, eb)
	}
	maxChainOps = 2
	b2 := x.member(t, x.m1, x.rBefore)
	if _, _, _, eb := x.call(t, n, b2, x.g.SyncKey(keys.PeriodOf(now), x.rendezvous(x.m1)).Public()); !errors.Is(eb, ErrChainTooLarge) {
		t.Fatalf("a chain past the cap: %v", eb)
	}
}

// TestTransportPeriodWindow: a rendezvous key of the next or previous
// period is accepted (a call across a period boundary), one two away isn't.
func TestTransportPeriodWindow(t *testing.T) {
	x := newGroup(t)
	p := keys.PeriodOf(now)
	for _, c := range []struct {
		period uint64
		ok     bool
	}{{p - 1, true}, {p + 1, true}, {p - 2, false}, {p + 2, false}} {
		a, b := x.member(t, x.m1, x.r), x.member(t, x.m2, x.r)
		_, _, _, eb := x.call(t, a, b, x.m1.Rendezvous(x.g, c.period).Public())
		if c.ok && eb != nil {
			t.Fatalf("period %+d refused: %v", int64(c.period)-int64(p), eb)
		}
		if !c.ok && !errors.Is(eb, ErrTransportKey) {
			t.Fatalf("period %+d: %v", int64(c.period)-int64(p), eb)
		}
	}
}

// TestProofFromAnotherConnectionRefused: a member-key proof made over
// another connection's secret is refused.
func TestProofFromAnotherConnectionRefused(t *testing.T) {
	x := newGroup(t)
	a, b := x.member(t, x.m1, x.r), x.member(t, x.m2, x.r)
	_, _, ea, eb := x.callWith(t, a, b, x.rendezvous(x.m1), []byte("another connection's secret....."))
	if !errors.Is(eb, ErrBadProof) && !errors.Is(ea, ErrBadProof) {
		t.Fatalf("a proof over another secret: %v / %v", ea, eb)
	}
}

// TestRefusedCallerLeavesRosterAlone: a sync-key caller that isn't
// admitted (its chain doesn't admit it) leaves no operation in the
// callee's roster.
func TestRefusedCallerLeavesRosterAlone(t *testing.T) {
	x := newGroup(t)
	b := x.member(t, x.m2, x.r)
	before := b.r.Len()
	// An op b lacks, which the refused caller presents.
	if _, err := (&roster.Writer{R: x.r, Me: x.owner}).Rekey(); err != nil {
		t.Fatal(err)
	}
	a := x.member(t, x.other, x.r) // holds G and the new op, never admitted
	syncKey := x.g.SyncKey(keys.PeriodOf(now), x.rendezvous(x.m2)).Public()
	if _, _, _, eb := x.call(t, a, b, syncKey); !errors.Is(eb, ErrNotMember) {
		t.Fatalf("setup: %v", eb)
	}
	if b.r.Len() != before {
		t.Fatalf("a refused caller added %d operations", b.r.Len()-before)
	}
}

// TestSendChainSplits: a chain past chainChunk goes in several frames.
func TestSendChainSplits(t *testing.T) {
	defer func(c int) { chainChunk = c }(chainChunk)
	x := newGroup(t)
	var ops []*roster.Op
	for _, id := range x.r.IDs() {
		if id != x.r.Group() {
			ops = append(ops, x.r.Op(id))
		}
	}
	chainChunk = 1
	s := newSession(Config{}, nil)
	s.sendChain(ops)
	if len(s.queue) != len(ops) {
		t.Fatalf("%d frames for %d operations, one each at this chunk size", len(s.queue), len(ops))
	}
}

// TestSendChainFitsFrames: many small operations at the default chunk
// size, with their encoding overhead, still fit each frame.
func TestSendChainFitsFrames(t *testing.T) {
	x := newGroup(t)
	op := x.r.Op(x.r.IDs()[1])
	ops := make([]*roster.Op, 4*chainChunk/len(op.Encode()))
	for i := range ops {
		ops[i] = op
	}
	s := newSession(Config{}, nil)
	s.sendChain(ops)
	for _, f := range s.queue {
		if len(f)-4 > maxFrame {
			t.Fatalf("a %d-byte chain frame, past the %d limit", len(f)-4, maxFrame)
		}
	}
}

// TestFailedSyncKeepsLogsCurrent: a peer that sends a removal in an
// unfinished batch of operations and drops leaves the callee's logs
// following the roster that now holds it.
func TestFailedSyncKeepsLogsCurrent(t *testing.T) {
	x := newGroup(t)
	c := x.member(t, x.owner, x.r) // the callee, before the removal
	rm, err := (&roster.Writer{R: x.r, Me: x.owner}).Remove(x.m2.Public(), 0, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("0123456789abcdef0123456789abcdef")
	a, b := net.Pipe()
	done := make(chan error, 1)
	go func() {
		_, err := Run(context.Background(), b, Config{Me: c.id, Group: x.g, Roster: c.r, Logs: c.logs, Secret: secret,
			Local: x.rendezvous(x.owner), Peer: x.rendezvous(x.m1), Now: now})
		done <- err
	}()
	// m1, admitted properly, then a batch with More and a drop.
	peer := newSession(Config{Me: x.m1, Roster: x.r, Secret: secret, Caller: true,
		Local: x.rendezvous(x.m1), Peer: x.rendezvous(x.owner)}, a)
	go func() {
		for {
			if _, _, err := peer.read(); err != nil {
				return
			}
		}
	}()
	frame := func(kind byte, body []byte) []byte {
		return append(append(binary.BigEndian.AppendUint32(nil, uint32(len(body)+1)), kind), body...)
	}
	sig := x.m1.Sign(peer.proofFor(true))
	pub := x.m1.Public()
	hello := bencode.Append(nil, bencode.Value{Kind: bencode.Dict, Dict: []bencode.Pair{
		{Key: []byte("h"), Value: bencode.Value{Kind: bencode.List}},
		{Key: []byte("k"), Value: bencode.Value{Kind: bencode.String, Str: pub[:]}},
		{Key: []byte("s"), Value: bencode.Value{Kind: bencode.String, Str: sig}},
	}})
	a.Write(frame(frameHello, hello))
	a.Write(frame(frameSync, gsync.Encode(gsync.Have{IDs: c.r.IDs()})))
	a.Write(frame(frameSync, gsync.Encode(gsync.Ops{Ops: []*roster.Op{rm}, More: true})))
	a.Close()
	if err := <-done; err == nil {
		t.Fatal("an unfinished session succeeded")
	}
	if _, down, _ := c.logs.Next(x.m2.Public()); !down {
		t.Fatal("the logs didn't follow a removal the roster took before the drop")
	}
}

// TestSendNeverBlocks: frames queue without blocking while the peer isn't
// reading, so two sides answering each other's bursts can't deadlock.
func TestSendNeverBlocks(t *testing.T) {
	a, b := net.Pipe() // nobody reads b
	defer a.Close()
	defer b.Close()
	s := newSession(Config{}, a)
	go s.write()
	done := make(chan struct{})
	go func() {
		for range 5000 {
			s.send(frameSync, make([]byte, 100))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("send blocked on a peer that isn't reading")
	}
	if s.backlogged() {
		t.Fatal("half a megabyte queued counted as a backlog")
	}
}

// TestBacklogFails: past maxQueued bytes unread, the session fails and
// closes the connection rather than queue without bound.
func TestBacklogFails(t *testing.T) {
	defer func(q int) { maxQueued = q }(maxQueued)
	maxQueued = 1000
	a, b := net.Pipe()
	defer b.Close()
	s := newSession(Config{}, a)
	for range 20 {
		s.send(frameSync, make([]byte, 100))
	}
	if !s.backlogged() {
		t.Fatal("a queue past the cap wasn't failed")
	}
	if _, err := a.Write([]byte{0}); err == nil {
		t.Fatal("the connection stayed open past the cap")
	}
}

// TestSyncCallerChecksCalleeFirst: a sync-key caller sends nothing of the
// roster to a callee whose hello doesn't verify.
func TestSyncCallerChecksCalleeFirst(t *testing.T) {
	x := newGroup(t)
	n := x.member(t, x.m1, x.r)
	syncKey := x.g.SyncKey(keys.PeriodOf(now), x.rendezvous(x.m2))
	a, b := net.Pipe()
	done := make(chan error, 1)
	go func() {
		_, err := Run(context.Background(), a, Config{Me: n.id, Group: x.g, Roster: n.r, Logs: n.logs, Secret: []byte("secret"),
			Caller: true, Local: syncKey.Public(), Peer: x.rendezvous(x.m2), Now: now})
		done <- err
	}()
	// A callee posing as m2, with a proof that doesn't verify.
	pub := x.m2.Public()
	hello := bencode.Append(nil, bencode.Value{Kind: bencode.Dict, Dict: []bencode.Pair{
		{Key: []byte("h"), Value: bencode.Value{Kind: bencode.List}},
		{Key: []byte("k"), Value: bencode.Value{Kind: bencode.String, Str: pub[:]}},
		{Key: []byte("s"), Value: bencode.Value{Kind: bencode.String, Str: make([]byte, 64)}},
	}})
	b.Write(append(append(binary.BigEndian.AppendUint32(nil, uint32(len(hello)+1)), frameHello), hello...))
	gotc := make(chan []byte, 1)
	go func() {
		var got []byte
		buf := make([]byte, 1<<16)
		for {
			k, err := b.Read(buf)
			got = append(got, buf[:k]...)
			if err != nil {
				gotc <- got
				return
			}
		}
	}()
	if err := <-done; !errors.Is(err, ErrBadProof) {
		t.Fatalf("a callee with a bad proof: %v", err)
	}
	b.Close()
	if got := <-gotc; len(got) > 0 {
		t.Fatalf("the caller sent %d bytes to a callee it hadn't admitted", len(got))
	}
}

// TestManyHeadsCapped: a roster with more heads than a hello may name
// still has sessions: the hello advertises at most maxHeads.
func TestManyHeadsCapped(t *testing.T) {
	defer func(h int) { maxHeads = h }(maxHeads)
	x := newGroup(t)
	// Two concurrent rekeys, written on copies and merged: two heads.
	other := copyRoster(t, x.r)
	if _, err := (&roster.Writer{R: x.r, Me: x.owner}).Rekey(); err != nil {
		t.Fatal(err)
	}
	op, err := (&roster.Writer{R: other, Me: x.owner}).Rekey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x.r.Add(op); err != nil {
		t.Fatal(err)
	}
	if len(x.r.Heads()) != 2 {
		t.Fatalf("setup: %d heads", len(x.r.Heads()))
	}
	maxHeads = 1
	a, b := x.member(t, x.m1, x.r), x.member(t, x.m2, x.r)
	if _, _, ea, eb := x.call(t, a, b, x.rendezvous(x.m1)); ea != nil || eb != nil {
		t.Fatalf("a roster with more heads than a hello names: %v / %v", ea, eb)
	}
}
