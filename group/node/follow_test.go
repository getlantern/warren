package node

import (
	"context"
	"testing"
	"time"

	"github.com/getlantern/warren/group/keys"
	"github.com/getlantern/warren/group/memberlog"
	"github.com/getlantern/warren/group/roster"
)

// rekey has n's member rekey through n.
func rekey(t *testing.T, ctx context.Context, n *Node) {
	t.Helper()
	if err := n.Do(ctx, func(r *roster.Roster, _ *memberlog.Set) error {
		_, err := (&roster.Writer{R: r, Me: n.cfg.Me}).Rekey()
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// TestRekeyPropagates: after the owner rekeys, it reaches a member still
// on the old secret under that secret (kept for Grace), and the member
// follows to the new one.
func TestRekeyPropagates(t *testing.T) {
	seed := network(t, 10)
	x := newGroup(t)
	owner := x.join(t, host(t, seed), x.owner, x.r)
	m1 := x.join(t, host(t, seed), x.m1, x.r)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	old := owner.Group()
	rekey(t, ctx, owner)
	g := owner.Group()
	if g == old {
		t.Fatal("the owner didn't follow its rekey")
	}
	p := keys.PeriodOf(time.Now())
	if !owner.listensUnder(x.owner.Rendezvous(g, p).Public()) || !owner.listensUnder(x.owner.Rendezvous(old, p).Public()) {
		t.Fatal("the owner isn't listening under both the new secret and the superseded one")
	}
	if err := owner.Call(ctx, x.m1.Public()); err != nil {
		t.Fatalf("the owner couldn't reach a member still on the old secret: %v", err)
	}
	eventually(t, "the member didn't follow to the new secret", func() bool { return m1.Group() == g })
	eventually(t, "the member isn't listening under the new secret", func() bool {
		return m1.listensUnder(x.m1.Rendezvous(g, p).Public())
	})
}

// TestOfflineMemberWithinGrace: a member offline during a rekey comes back
// on the old secret and reaches the owner under it, within Grace, getting
// the rekey.
func TestOfflineMemberWithinGrace(t *testing.T) {
	seed := network(t, 10)
	x := newGroup(t)
	owner := x.join(t, host(t, seed), x.owner, x.r)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rekey(t, ctx, owner) // on the owner's own roster: x.r doesn't see it
	m1 := x.join(t, host(t, seed), x.m1, x.r)
	if m1.Group() != x.g {
		t.Fatal("the returning member isn't on the old secret")
	}
	if err := m1.Call(ctx, x.owner.Public()); err != nil {
		t.Fatalf("a member back within Grace couldn't reach the owner: %v", err)
	}
	if m1.Group() != owner.Group() {
		t.Fatal("the member didn't get the rekey")
	}
}

// TestGraceExpires: past Grace, the owner stops listening under the
// superseded secret and admitting members' keys from it.
func TestGraceExpires(t *testing.T) {
	seed := network(t, 6)
	x := newGroup(t)
	now := time.Now()
	h := host(t, seed)
	c := copyRoster(t, x.r)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	n, err := h.Join(ctx, Config{Me: x.owner, Group: x.g, Roster: c, Logs: memberlogSet(t, c), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	old := n.Group()
	rekey(t, ctx, n)
	p := keys.PeriodOf(now)
	memberOld := x.m1.Rendezvous(old, p).Public()
	if !n.listensUnder(x.owner.Rendezvous(old, p).Public()) || !n.admits(memberOld) {
		t.Fatal("not listening under, or admitting from, the superseded secret within Grace")
	}
	now = now.Add(Grace + time.Minute)
	if err := n.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	q := keys.PeriodOf(now)
	if n.listensUnder(x.owner.Rendezvous(old, q).Public()) || n.admits(x.m1.Rendezvous(old, q).Public()) {
		t.Fatal("still listening under, or admitting from, a secret past Grace")
	}
	if !n.listensUnder(x.owner.Rendezvous(n.Group(), q).Public()) {
		t.Fatal("not listening under the current secret")
	}
}
