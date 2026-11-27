package roster

import (
	"errors"
	"testing"
	"time"

	"github.com/getlantern/warren/group/keys"
)

var inviteNow = time.Unix(1_800_000_000, 0)

func clock() time.Time { return inviteNow }

// invite records a fresh invite with uses and an hour to run.
func invite(t *testing.T, r *Roster, by *keys.Identity, b byte, uses uint32) keys.PublicKey {
	t.Helper()
	inv := me(b).Public()
	if _, err := (&Writer{R: r, Me: by, Now: clock}).Invite(inv, uses, inviteNow.Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	return inv
}

func inviteState(t *testing.T, r *Roster, inv keys.PublicKey) *InviteState {
	t.Helper()
	f, err := r.Fold()
	if err != nil {
		t.Fatal(err)
	}
	s := f.Invites[inv]
	if s == nil {
		t.Fatal("the invite isn't recorded")
	}
	return s
}

func TestInviteRecorded(t *testing.T) {
	r, owner, admin, member := group(t)
	inv := invite(t, r, admin, 50, 2)
	s := inviteState(t, r, inv)
	if s.Uses != 2 || s.Used != 0 || s.Dead || s.Expires != inviteNow.Add(time.Hour).Unix() || !s.Usable(inviteNow) {
		t.Fatalf("recorded as %+v", s)
	}
	exp := inviteNow.Add(time.Hour).Unix()
	for name, try := range map[string]func() error{
		"the same key again": func() error { _, err := (&Writer{R: r, Me: owner}).Invite(inv, 1, exp); return err },
		"by a member":        func() error { _, err := (&Writer{R: r, Me: member}).Invite(me(51).Public(), 1, exp); return err },
		"with no uses":       func() error { _, err := (&Writer{R: r, Me: owner}).Invite(me(52).Public(), 0, exp); return err },
		"with too many uses": func() error {
			_, err := (&Writer{R: r, Me: owner}).Invite(me(53).Public(), MaxUses+1, exp)
			return err
		},
	} {
		if err := try(); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestInviteSpent: each add or rejoin's deliver naming an invite spends a
// use, and a spent invite can't be named again.
func TestInviteSpent(t *testing.T) {
	r, _, admin, member := group(t)
	inv := invite(t, r, admin, 50, 2)
	w := &Writer{R: r, Me: admin, Now: clock}
	if _, err := w.Add(me(60).Public(), "new", Member, inv); err != nil {
		t.Fatal(err)
	}
	if s := inviteState(t, r, inv); s.Used != 1 || !s.Usable(inviteNow) {
		t.Fatalf("after an add: %+v", s)
	}
	// A rejoin spends one too. The member must lack keys to deliver: the
	// owner rekeys in a copy that hasn't seen the member's add.
	missKeys(t, r, member)
	if _, err := w.Deliver(member.Public(), inv); err != nil {
		t.Fatal(err)
	}
	if s := inviteState(t, r, inv); s.Used != 2 || s.Usable(inviteNow) {
		t.Fatalf("after a rejoin: %+v", s)
	}
	if _, err := w.Add(me(61).Public(), "another", Member, inv); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("a spent invite admitted another: %v", err)
	}
}

func TestInviteRefusedWhenUnusable(t *testing.T) {
	r, owner, admin, _ := group(t)
	inv := invite(t, r, admin, 50, 1)
	late := &Writer{R: r, Me: admin, Now: func() time.Time { return inviteNow.Add(time.Hour) }}
	if _, err := late.Add(me(60).Public(), "late", Member, inv); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("an expired invite admitted: %v", err)
	}
	w := &Writer{R: r, Me: admin, Now: clock}
	if _, err := w.Add(me(60).Public(), "stranger", Member, me(59).Public()); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("an unrecorded invite admitted: %v", err)
	}
	// A removal kills the invites issued before it, not those after.
	victim := me(70)
	if _, err := w.Add(victim.Public(), "victim", Member, keys.PublicKey{}); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Writer{R: r, Me: owner}).Remove(victim.Public(), 0, [32]byte{}); err != nil {
		t.Fatal(err)
	}
	if s := inviteState(t, r, inv); !s.Dead || s.Usable(inviteNow) {
		t.Fatalf("an invite issued before a removal survived it: %+v", s)
	}
	if _, err := w.Add(me(60).Public(), "after", Member, inv); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("a dead invite admitted: %v", err)
	}
	fresh := invite(t, r, admin, 51, 1)
	if s := inviteState(t, r, fresh); s.Dead {
		t.Fatal("an invite issued after the removal is dead")
	}
	if _, err := w.Add(me(60).Public(), "after", Member, fresh); err != nil {
		t.Fatal(err)
	}
}

// TestInviteOverspentConcurrently: two admins approving one single-use
// invite at once both admit their joiner; the fold counts both uses rather
// than dropping an admission.
func TestInviteOverspentConcurrently(t *testing.T) {
	r, owner, admin, _ := group(t)
	inv := invite(t, r, admin, 50, 1)
	c := r.Clone()
	a, err := (&Writer{R: r, Me: admin, Now: clock}).Add(me(60).Public(), "a", Member, inv)
	if err != nil {
		t.Fatal(err)
	}
	b, err := (&Writer{R: c, Me: owner, Now: clock}).Add(me(61).Public(), "b", Member, inv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add(b); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Add(a); err != nil {
		t.Fatal(err)
	}
	for _, x := range []*Roster{r, c} {
		f, err := x.Fold()
		if err != nil {
			t.Fatal(err)
		}
		if f.Roles[me(60).Public()] != Member || f.Roles[me(61).Public()] != Member {
			t.Fatal("an admission was dropped")
		}
		if s := f.Invites[inv]; s.Used != 2 || s.Usable(inviteNow) {
			t.Fatalf("an overspent invite reads %+v", s)
		}
	}
}

// TestInviteFirstRecordStands: a second invite op for one key (only a
// hand-made one; the writer refuses) doesn't reset its uses.
func TestInviteFirstRecordStands(t *testing.T) {
	r, _, admin, _ := group(t)
	inv := invite(t, r, admin, 50, 1)
	w := &Writer{R: r, Me: admin, Now: clock}
	if _, err := w.Add(me(60).Public(), "a", Member, inv); err != nil {
		t.Fatal(err)
	}
	o := w.base(Invite)
	o.Invite, o.Expires, o.Uses = inv, inviteNow.Add(2*time.Hour).Unix(), 5
	o.Sign(admin)
	if _, err := r.Add(o); err != nil {
		t.Fatal(err)
	}
	if s := inviteState(t, r, inv); s.Uses != 1 || s.Used != 1 {
		t.Fatalf("a later record reset the invite: %+v", s)
	}
}

// missKeys has the owner rekey in a copy of r holding only the genesis and
// the adds of the admin and also, so m lacks the new keys once r takes the
// rekey and they hold them.
func missKeys(t *testing.T, r *Roster, m *keys.Identity, also ...*keys.Identity) {
	t.Helper()
	stale, err := New(r.Op(r.Group()))
	if err != nil {
		t.Fatal(err)
	}
	holders := map[keys.PublicKey]bool{me(2).Public(): true}
	for _, id := range also {
		holders[id.Public()] = true
	}
	for _, o := range r.order() { // parents before children
		if o.Kind == Add && holders[o.Target] {
			if _, err := stale.Add(o); err != nil {
				t.Fatal(err)
			}
		}
	}
	rk, err := (&Writer{R: stale, Me: me(1)}).Rekey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add(rk); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Keyring(m).Epochs[rk.ID()]; ok {
		t.Fatal("the member got the rekey")
	}
}

// TestInviteOnlyCounting: an invite op that doesn't count (a member can't
// invite) records nothing.
func TestInviteOnlyCounting(t *testing.T) {
	r, _, _, member := group(t)
	o := (&Writer{R: r, Me: member}).base(Invite)
	o.Invite, o.Expires, o.Uses = me(50).Public(), inviteNow.Add(time.Hour).Unix(), 1
	o.Sign(member)
	if _, err := r.Add(o); err != nil {
		t.Fatal(err)
	}
	f, err := r.Fold()
	if err != nil {
		t.Fatal(err)
	}
	if f.Invites[me(50).Public()] != nil {
		t.Fatal("a member's invite was recorded")
	}
}

// TestMemberCantSpendInvite: a member's deliver naming an invite, even an
// empty one made by hand, spends nothing, and the writer won't make one.
func TestMemberCantSpendInvite(t *testing.T) {
	r, _, admin, member := group(t)
	inv := invite(t, r, admin, 50, 1)
	o := (&Writer{R: r, Me: member}).base(Deliver)
	o.Target, o.Invite = member.Public(), inv
	o.Sign(member)
	if _, err := Decode(o.Encode()); err != nil {
		t.Fatalf("the hand-made deliver doesn't decode: %v", err)
	}
	if _, err := r.Add(o); err != nil {
		t.Fatal(err)
	}
	if s := inviteState(t, r, inv); s.Used != 0 || !s.Usable(inviteNow) {
		t.Fatalf("a member's deliver spent the invite: %+v", s)
	}
	other := me(61)
	if _, err := (&Writer{R: r, Me: admin}).Add(other.Public(), "other", Member, keys.PublicKey{}); err != nil {
		t.Fatal(err)
	}
	missKeys(t, r, other, member) // the member holds keys other lacks
	mw := &Writer{R: r, Me: member, Now: clock}
	if _, err := mw.Deliver(other.Public(), inv); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("a member's writer answered an invite: %v", err)
	}
	if _, err := mw.Deliver(other.Public(), keys.PublicKey{}); err != nil {
		t.Fatalf("a member's deliver with no invite: %v", err)
	}
}

// TestDeliverRefusesUnusableInvite: a rejoin's deliver, to a member that
// does lack keys, refuses an invite that isn't usable.
func TestDeliverRefusesUnusableInvite(t *testing.T) {
	r, owner, admin, member := group(t)
	missKeys(t, r, member)
	expired := invite(t, r, admin, 50, 1)
	spent := invite(t, r, admin, 51, 1)
	if _, err := (&Writer{R: r, Me: admin, Now: clock}).Add(me(60).Public(), "a", Member, spent); err != nil {
		t.Fatal(err)
	}
	w := &Writer{R: r, Me: admin, Now: clock}
	late := &Writer{R: r, Me: admin, Now: func() time.Time { return inviteNow.Add(time.Hour) }}
	for name, try := range map[string]func() error{
		"expired":    func() error { _, err := late.Deliver(member.Public(), expired); return err },
		"spent":      func() error { _, err := w.Deliver(member.Public(), spent); return err },
		"unrecorded": func() error { _, err := w.Deliver(member.Public(), me(59).Public()); return err },
	} {
		if err := try(); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	victim := me(70)
	if _, err := w.Add(victim.Public(), "victim", Member, keys.PublicKey{}); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Writer{R: r, Me: owner}).Remove(victim.Public(), 0, [32]byte{}); err != nil {
		t.Fatal(err)
	}
	missKeys(t, r, member) // the remove's rekey reached the member; miss another
	if _, err := w.Deliver(member.Public(), expired); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("dead: %v", err)
	}
	if _, err := w.Deliver(member.Public(), keys.PublicKey{}); err != nil {
		t.Fatalf("a deliver with no invite, to the same member: %v", err)
	}
}

func TestDecodeBoundsUses(t *testing.T) {
	r, _, admin, _ := group(t)
	for _, c := range []struct {
		uses uint32
		ok   bool
	}{{MaxUses, true}, {MaxUses + 1, false}} {
		o := (&Writer{R: r, Me: admin}).base(Invite)
		o.Invite, o.Expires, o.Uses = me(50).Public(), inviteNow.Add(time.Hour).Unix(), c.uses
		o.Sign(admin)
		if _, err := Decode(o.Encode()); (err == nil) != c.ok {
			t.Errorf("uses %d: %v", c.uses, err)
		}
	}
}

// TestDemotedAdminCantBackdateSpend: an admin demoted after an invite can't
// spend it with a deliver backdated to before its demotion.
func TestDemotedAdminCantBackdateSpend(t *testing.T) {
	r, owner, admin, _ := group(t)
	inv := invite(t, r, admin, 50, 1)
	ow := &Writer{R: r, Me: owner, Now: clock}
	invite(t, r, owner, 51, 1) // so the demotion sorts after the backdated deliver
	if _, err := ow.SetRole(admin.Public(), Member); err != nil {
		t.Fatal(err)
	}
	f, err := r.Fold()
	if err != nil {
		t.Fatal(err)
	}
	invOp := r.Op(f.Invites[inv].Op)
	o := &Op{Group: r.group, Kind: Deliver, Parents: []ID{invOp.ID()}, Lamport: invOp.Lamport + 1,
		Target: admin.Public(), Invite: inv}
	o.Sign(admin)
	if _, err := r.Add(o); err != nil {
		t.Fatal(err)
	}
	if s := inviteState(t, r, inv); s.Used != 0 {
		t.Fatalf("a demoted admin's backdated deliver spent the invite: %+v", s)
	}
}

// TestConcurrentApprovalsOfOneJoiner: two admins admitting the same joiner
// at once under different invites both spend their invite, though only one
// add counts.
func TestConcurrentApprovalsOfOneJoiner(t *testing.T) {
	r, owner, admin, _ := group(t)
	a := invite(t, r, admin, 50, 1)
	b := invite(t, r, owner, 51, 1)
	c := r.Clone()
	joiner := me(60).Public()
	x, err := (&Writer{R: r, Me: admin, Now: clock}).Add(joiner, "j", Member, a)
	if err != nil {
		t.Fatal(err)
	}
	y, err := (&Writer{R: c, Me: owner, Now: clock}).Add(joiner, "j", Member, b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add(y); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Add(x); err != nil {
		t.Fatal(err)
	}
	for _, ro := range []*Roster{r, c} {
		f, err := ro.Fold()
		if err != nil {
			t.Fatal(err)
		}
		if f.Roles[joiner] != Member {
			t.Fatal("the joiner wasn't admitted")
		}
		if f.Invites[a].Used != 1 || f.Invites[b].Used != 1 {
			t.Fatalf("uses: %d and %d, want 1 each", f.Invites[a].Used, f.Invites[b].Used)
		}
	}
	// A causal duplicate (the admin had seen the admission) spends nothing.
	d := invite(t, r, admin, 52, 1)
	o := (&Writer{R: r, Me: admin}).base(Add)
	o.Target, o.Role, o.Name, o.Invite = joiner, Member, "j", d
	o.Sign(admin)
	if _, err := r.Add(o); err != nil {
		t.Fatal(err)
	}
	if s := inviteState(t, r, d); s.Used != 0 {
		t.Fatalf("a causal duplicate add spent its invite: %+v", s)
	}
}

// TestFoldScalesWithDuplicateAdds: a long chain of same-role duplicate adds,
// some naming an invite, folds without refolding each one's history.
func TestFoldScalesWithDuplicateAdds(t *testing.T) {
	r, _, admin, member := group(t)
	inv := invite(t, r, admin, 50, 1)
	w := &Writer{R: r, Me: admin}
	const n = 6000
	for i := range n {
		o := w.base(Add)
		o.Target, o.Role, o.Name = member.Public(), Member, "m"
		if i%2 == 0 { // half name an invite, which asks about their history
			o.Invite = inv
		}
		o.Sign(admin)
		if _, err := r.Add(o); err != nil {
			t.Fatal(err)
		}
	}
	start := time.Now()
	f, err := r.Fold()
	if err != nil {
		t.Fatal(err)
	}
	if f.Invites[inv].Used != 0 {
		t.Fatal("causal duplicate adds spent the invite")
	}
	if d := time.Since(start); d > 2*time.Second && !raceEnabled { // quadratic takes seconds; linear, milliseconds
		t.Fatalf("folding %d duplicate adds took %v", n, d)
	} else {
		t.Logf("folded in %v", d)
	}
}

// TestAddOfOwnerSpendsNothing: an add naming the owner, who was never
// added, can't count and spends nothing.
func TestAddOfOwnerSpendsNothing(t *testing.T) {
	r, owner, admin, _ := group(t)
	inv := invite(t, r, admin, 50, 1)
	o := (&Writer{R: r, Me: admin}).base(Add)
	o.Target, o.Role, o.Name, o.Invite = owner.Public(), Member, "o", inv
	o.Sign(admin)
	if _, err := r.Add(o); err != nil {
		t.Fatal(err)
	}
	if s := inviteState(t, r, inv); s.Used != 0 {
		t.Fatalf("an add of the owner spent the invite: %+v", s)
	}
}
