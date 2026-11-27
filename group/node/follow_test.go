package node

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/getlantern/warren/dht"
	"github.com/getlantern/warren/group/directory"
	"github.com/getlantern/warren/group/join"
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

// TestIntermediateSecretKept: a node that learns two rekeys at once keeps
// the middle secret for Grace too, so a member admitted while it was
// current (and holding no other) still reaches it.
func TestIntermediateSecretKept(t *testing.T) {
	seed := network(t, 10)
	x := newGroup(t)
	a := x.join(t, host(t, seed), x.m1, x.r) // on G0
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// Elsewhere: a rekey to G1, a newcomer admitted under it, a rekey to G2.
	later := copyRoster(t, x.r)
	ow := &roster.Writer{R: later, Me: x.owner}
	rk1, err := ow.Rekey()
	if err != nil {
		t.Fatal(err)
	}
	newcomer := me(55)
	if _, err := ow.Add(newcomer.Public(), "n", roster.Member, keys.PublicKey{}); err != nil {
		t.Fatal(err)
	}
	snapshot := copyRoster(t, later) // the newcomer's view: G1 current
	if _, err := ow.Rekey(); err != nil {
		t.Fatal(err)
	}
	f, _ := later.Fold()
	ops := f.Order[1:]
	if err := a.Do(ctx, func(r *roster.Roster, _ *memberlog.Set) error { // both rekeys at once
		for _, o := range ops {
			if _, err := r.Add(o); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	g1 := later.Keyring(x.owner).Secrets[rk1.ID()]
	p := keys.PeriodOf(time.Now())
	if !a.listensUnder(x.m1.Rendezvous(g1, p).Public()) {
		t.Fatal("the node dropped the intermediate secret")
	}
	saved := *x
	saved.g = g1
	n := saved.join(t, host(t, seed), newcomer, snapshot)
	if n.Group() != g1 {
		t.Fatal("the newcomer isn't on the intermediate secret")
	}
	if err := n.Call(ctx, x.m1.Public()); err != nil {
		t.Fatalf("a member on the intermediate secret couldn't reach the node: %v", err)
	}
}

// TestJoinTwiceRefusedAfterRekey: once a node follows a rekey, joining the
// same group as the same member on the new secret is still refused.
func TestJoinTwiceRefusedAfterRekey(t *testing.T) {
	seed := network(t, 6)
	x := newGroup(t)
	h := host(t, seed)
	n := x.join(t, h, x.owner, x.r)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rekey(t, ctx, n)
	c := copyRoster(t, x.r)
	if _, err := h.Join(ctx, Config{Me: x.owner, Group: n.Group(), Roster: c, Logs: memberlogSet(t, c)}); !errors.Is(err, ErrJoined) {
		t.Fatalf("a second join on the new secret: %v, want ErrJoined", err)
	}
}

// TestNoJoinsWithoutNewListeners: when the listener table is too full to
// listen under a new secret, the admin refuses joins rather than hand out
// a secret it doesn't listen under.
func TestNoJoinsWithoutNewListeners(t *testing.T) {
	seed := network(t, 10)
	x := newGroup(t)
	h := host(t, seed)
	owner := x.join(t, h, x.owner, x.r)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	issued, err := owner.Invite(ctx, 1, time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range dht.MaxListeners - 4 { // two rendezvous keys, two invite keys
		if err := h.ep.AddListener(ctx, keys.CryptoSigner(me(byte(100+i)).Rendezvous(x.g, 0))); err != nil {
			t.Fatal(err)
		}
	}
	rekey(t, ctx, owner)
	if owner.listensUnder(x.owner.Rendezvous(owner.Group(), keys.PeriodOf(time.Now())).Public()) {
		t.Fatal("the new secret's listeners fit a full table")
	}
	if _, err := host(t, seed).JoinByInvite(ctx, issued.Invite, me(56), "n", joinCfg); !errors.Is(err, join.ErrAdminBehind) {
		t.Fatalf("a join without listeners on the new secret: %v, want ErrAdminBehind", err)
	}
}

// TestDirectoryAfterRekey: after a rekey, members publish to and read the
// new secret's directory.
func TestDirectoryAfterRekey(t *testing.T) {
	seed := network(t, 10)
	x := newGroup(t)
	fixed := time.Now()
	x.clock = func() time.Time { return fixed }
	owner := x.join(t, host(t, seed), x.owner, x.r)
	m1 := x.join(t, host(t, seed), x.m1, x.r)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rekey(t, ctx, owner)
	if err := owner.Call(ctx, x.m1.Public()); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the member didn't follow", func() bool { return m1.Group() == owner.Group() })
	if err := m1.Publish(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := owner.Directory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got[x.m1.Public()]; !ok {
		t.Fatal("the new secret's directory didn't show the member")
	}
	// The old secret's directory holds nothing of it.
	old, err := (&directory.Directory{Group: x.g, Shards: owner.shards, Store: owner.h.ep.DHT(), Now: x.clock}).Read(ctx, keys.PeriodOf(fixed), []keys.PublicKey{x.owner.Public(), x.m1.Public(), x.m2.Public()})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := old[x.m1.Public()]; ok {
		t.Fatal("the member published to the old secret's directory")
	}
}

// TestRejectedRekeyNotListened: a rekey that doesn't count (here, by an
// admin demoted concurrently, which the demotion rule drops) adds no
// listener, though the node can open its secret.
func TestRejectedRekeyNotListened(t *testing.T) {
	seed := network(t, 6)
	x := newGroup(t)
	a2 := me(57)
	if _, err := (&roster.Writer{R: x.r, Me: x.owner}).Add(a2.Public(), "a2", roster.Admin, keys.PublicKey{}); err != nil {
		t.Fatal(err)
	}
	n := x.join(t, host(t, seed), x.m1, x.r)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	stale := copyRoster(t, x.r)
	rk, err := (&roster.Writer{R: stale, Me: a2}).Rekey() // a2 doesn't know of its demotion
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&roster.Writer{R: x.r, Me: x.owner}).SetRole(a2.Public(), roster.Member); err != nil {
		t.Fatal(err)
	}
	f0, _ := x.r.Fold()
	if err := n.Do(ctx, func(r *roster.Roster, _ *memberlog.Set) error {
		for _, o := range append(f0.Order[1:], rk) {
			if _, err := r.Add(o); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var counts, held bool
	var bogus keys.Secret
	_ = n.Do(ctx, func(r *roster.Roster, _ *memberlog.Set) error {
		f, _ := r.Fold()
		counts = f.Counts[rk.ID()]
		bogus, held = r.Keyring(x.m1).Secrets[rk.ID()]
		return nil
	})
	if counts || !held {
		t.Fatalf("the setup: the rekey counts=%v, its secret held=%v", counts, held)
	}
	if n.listensUnder(x.m1.Rendezvous(bogus, keys.PeriodOf(time.Now())).Public()) {
		t.Fatal("a rekey that doesn't count got a listener")
	}
}

// TestIntermediateKeptBeforeCurrentDelivered: a newcomer that learns an
// intermediate secret while it doesn't yet hold the current one (a rekey
// made without it, pending a deliver) still keeps the intermediate one.
func TestIntermediateKeptBeforeCurrentDelivered(t *testing.T) {
	seed := network(t, 6)
	x := newGroup(t)
	newcomer := me(58)
	ow := &roster.Writer{R: x.r, Me: x.owner}
	pre := copyRoster(t, x.r) // before the newcomer's add
	if _, err := ow.Add(newcomer.Public(), "n", roster.Member, keys.PublicKey{}); err != nil {
		t.Fatal(err)
	}
	n := x.join(t, host(t, seed), newcomer, x.r) // on G0
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rk1, err := ow.Rekey() // G1, sealed to the newcomer
	if err != nil {
		t.Fatal(err)
	}
	// G2, concurrent, made without the newcomer, and later in the order.
	pw := &roster.Writer{R: pre, Me: x.owner}
	for i := range 4 {
		if _, err := pw.Invite(me(byte(200+i)).Public(), 1, time.Now().Add(time.Hour).Unix()); err != nil {
			t.Fatal(err)
		}
	}
	rk2, err := pw.Rekey()
	if err != nil {
		t.Fatal(err)
	}
	fp, _ := pre.Fold()
	if err := n.Do(ctx, func(r *roster.Roster, _ *memberlog.Set) error {
		for _, o := range append(fp.Order[1:], rk1, rk2) {
			if _, err := r.Add(o); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var current roster.ID
	var g1 keys.Secret
	var holdsCurrent bool
	_ = n.Do(ctx, func(r *roster.Roster, _ *memberlog.Set) error {
		f, _ := r.Fold()
		current = f.Current
		k := r.Keyring(newcomer)
		g1 = k.Secrets[rk1.ID()]
		_, holdsCurrent = k.Secrets[f.Current]
		return nil
	})
	if current != rk2.ID() || holdsCurrent {
		t.Fatalf("the setup: current is rk2=%v, held=%v", current == rk2.ID(), holdsCurrent)
	}
	if !n.listensUnder(newcomer.Rendezvous(g1, keys.PeriodOf(time.Now())).Public()) {
		t.Fatal("the intermediate secret was dropped while the current one was pending")
	}
}

// TestSightingsPublishedUnderTheirSecret: a member reached under the old
// secret isn't published as seen under the new one.
func TestSightingsPublishedUnderTheirSecret(t *testing.T) {
	seed := network(t, 10)
	x := newGroup(t)
	fixed := time.Now()
	x.clock = func() time.Time { return fixed }
	owner := x.join(t, host(t, seed), x.owner, x.r)
	x.join(t, host(t, seed), x.m1, x.r)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := owner.Call(ctx, x.m1.Public()); err != nil { // reached under G0
		t.Fatal(err)
	}
	rekey(t, ctx, owner) // the member hasn't heard
	if err := owner.Publish(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := owner.Directory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got[x.owner.Public()]; !ok {
		t.Fatal("the owner's own entry is missing")
	}
	if _, ok := got[x.m1.Public()]; ok {
		t.Fatal("a member reached under the old secret was published under the new one")
	}
}

// TestHistoryNotListened: a node starting on a roster rekeyed before it
// started holds the old secret but doesn't listen under it: the roster's
// history is past its window, so only a replacement it sees runs one.
func TestHistoryNotListened(t *testing.T) {
	seed := network(t, 6)
	x := newGroup(t)
	old := x.g
	if _, err := (&roster.Writer{R: x.r, Me: x.owner}).Rekey(); err != nil {
		t.Fatal(err)
	}
	f, _ := x.r.Fold()
	x.g = x.r.Keyring(x.owner).Secrets[f.Current]
	n := x.join(t, host(t, seed), x.owner, x.r)
	if _, held := x.r.Keyring(x.owner).Secrets[x.r.Group()]; !held {
		t.Fatal("the setup: the owner doesn't hold the old secret")
	}
	p := keys.PeriodOf(time.Now())
	if n.listensUnder(x.owner.Rendezvous(old, p).Public()) {
		t.Fatal("a node listens under a secret superseded before it started")
	}
	if !n.listensUnder(x.owner.Rendezvous(x.g, p).Public()) {
		t.Fatal("not listening under the current secret")
	}
}
