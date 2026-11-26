package session

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/getlantern/warren/group/keys"
	"github.com/getlantern/warren/group/memberlog"
	"github.com/getlantern/warren/group/roster"
)

var now = time.Unix(1_800_000_000, 0)

func me(b byte) *keys.Identity { return keys.IdentityFromSeed([32]byte{b}) }

// group is a roster with an owner and two members, and G.
type group struct {
	r                    *roster.Roster
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

// TestProofBoundToConnection: a proof signed for one connection's secret
// fails on another.
func TestProofBoundToConnection(t *testing.T) {
	x := newGroup(t)
	sig := x.m1.Sign(proof([]byte("secret one"), true))
	if x.m1.Public().Verify(proof([]byte("secret two"), true), sig) {
		t.Fatal("a proof verified on another connection's secret")
	}
	if x.m1.Public().Verify(proof([]byte("secret one"), false), sig) {
		t.Fatal("a caller's proof verified as a callee's")
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
