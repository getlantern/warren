package roster

import (
	"testing"

	"github.com/getlantern/warren/group/keys"
)

func needs(t *testing.T, r *Roster) bool {
	t.Helper()
	f, err := r.Fold()
	if err != nil {
		t.Fatal(err)
	}
	return r.NeedsRekey(f)
}

// TestNeedsRekeyNotForPlainRemoval: a removal's own rekey seals the new
// keys to everyone but the removed member, so nothing more is called for;
// nor does a mirror holding the current group secret, which it's meant to.
func TestNeedsRekeyNotForPlainRemoval(t *testing.T) {
	r, owner, _, member := group(t)
	if needs(t, r) {
		t.Fatal("a fresh roster calls for a rekey")
	}
	mirror := me(20)
	ow := &Writer{R: r, Me: owner}
	if _, err := ow.Add(mirror.Public(), "mirror", Mirror, keys.PublicKey{}); err != nil {
		t.Fatal(err)
	}
	if _, err := ow.Remove(member.Public(), 0, [32]byte{}); err != nil {
		t.Fatal(err)
	}
	if needs(t, r) {
		t.Fatal("a plain removal, or a mirror's group secret, calls for a rekey")
	}
}

// TestNeedsRekeyConcurrentRemovals: two admins removing two members at
// once each seal their new keys to the other removed member.
func TestNeedsRekeyConcurrentRemovals(t *testing.T) {
	r, owner, admin, member := group(t)
	x := me(21)
	if _, err := (&Writer{R: r, Me: owner}).Add(x.Public(), "x", Member, keys.PublicKey{}); err != nil {
		t.Fatal(err)
	}
	c := r.Clone()
	a, err := (&Writer{R: r, Me: owner}).Remove(member.Public(), 0, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := (&Writer{R: c, Me: admin}).Remove(x.Public(), 0, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add(b); err != nil {
		t.Fatal(err)
	}
	_ = a
	if !needs(t, r) {
		t.Fatal("concurrent removals, each sealing to the other's target, don't call for a rekey")
	}
}

// TestNeedsRekeyMirrorEpoch: a mirror that holds the current epoch key (from
// a demoted admin's add of it as a member, which the demotion drops but
// whose seals remain) calls for a rekey.
func TestNeedsRekeyMirrorEpoch(t *testing.T) {
	r, owner, admin, _ := group(t)
	k := me(22)
	stale := r.Clone()
	if _, err := (&Writer{R: stale, Me: admin}).Add(k.Public(), "k", Member, keys.PublicKey{}); err != nil {
		t.Fatal(err) // the admin hasn't seen its demotion
	}
	ow := &Writer{R: r, Me: owner}
	if _, err := ow.SetRole(admin.Public(), Member); err != nil {
		t.Fatal(err)
	}
	if _, err := ow.Add(k.Public(), "k", Mirror, keys.PublicKey{}); err != nil {
		t.Fatal(err)
	}
	if needs(t, r) {
		t.Fatal("the setup: a mirror's group secret alone calls for a rekey")
	}
	for _, id := range stale.IDs() {
		if _, err := r.Add(stale.Op(id)); err != nil {
			t.Fatal(err)
		}
	}
	f, _ := r.Fold()
	if f.Roles[k.Public()] != Mirror {
		t.Fatalf("the setup: k is %v, want a mirror", f.Roles[k.Public()])
	}
	if !needs(t, r) {
		t.Fatal("a mirror holding the current epoch key doesn't call for a rekey")
	}
}
