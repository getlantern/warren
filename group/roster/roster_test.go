package roster

import (
	"bytes"
	"errors"
	"runtime"
	"testing"
	"time"

	"filippo.io/edwards25519"
	"github.com/getlantern/warren/bencode"
	"github.com/getlantern/warren/group/keys"
)

func me(b byte) *keys.Identity { return keys.IdentityFromSeed([32]byte{b}) }

// group founds a group by owner and adds admin as an admin and member as a
// member, all in one roster.
func group(t *testing.T) (*Roster, *keys.Identity, *keys.Identity, *keys.Identity) {
	t.Helper()
	owner, admin, member := me(1), me(2), me(3)
	r, err := Found(owner, "family", 3)
	if err != nil {
		t.Fatal(err)
	}
	ow := &Writer{R: r, Me: owner}
	if _, err := ow.Add(admin.Public(), "admin", Admin, keys.PublicKey{}); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Writer{R: r, Me: admin}).Add(member.Public(), "member", Member, keys.PublicKey{}); err != nil {
		t.Fatal(err)
	}
	return r, owner, admin, member
}

func TestFlow(t *testing.T) {
	r, owner, admin, member := group(t)
	f, err := r.Fold()
	if err != nil {
		t.Fatal(err)
	}
	if f.Roles[owner.Public()] != Owner || f.Roles[admin.Public()] != Admin || f.Roles[member.Public()] != Member {
		t.Fatalf("roles %v", f.Roles)
	}
	// Every member holds the current keys, checked against their commitments.
	for _, id := range []*keys.Identity{owner, admin, member} {
		k := r.Keyring(id)
		if _, ok := k.Secrets[f.Current]; !ok {
			t.Fatalf("%x lacks the current group secret", id.Public())
		}
		if _, ok := k.Epochs[f.Current]; !ok {
			t.Fatalf("%x lacks the current epoch key", id.Public())
		}
	}

	// A removal rekeys: everyone left gets the new keys, the removed member
	// keeps only the old ones.
	rm, err := (&Writer{R: r, Me: admin}).Remove(member.Public(), 7, [32]byte{7})
	if err != nil {
		t.Fatal(err)
	}
	f, _ = r.Fold()
	if f.Current != rm.ID() || f.Roles[member.Public()] != None || f.Removed[member.Public()] != rm.ID() {
		t.Fatalf("after removal: current %x, member %v", f.Current[:4], f.Roles[member.Public()])
	}
	if _, ok := r.Keyring(member).Epochs[rm.ID()]; ok {
		t.Fatal("the removed member got the new epoch key")
	}
	if _, ok := r.Keyring(owner).Epochs[rm.ID()]; !ok {
		t.Fatal("the owner didn't get the new epoch key")
	}

	// Removed keys never come back; admins can't add admins; only the
	// owner promotes.
	if _, err := (&Writer{R: r, Me: admin}).Add(member.Public(), "again", Member, keys.PublicKey{}); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("re-adding a removed key: %v", err)
	}
	if _, err := (&Writer{R: r, Me: admin}).Add(me(4).Public(), "x", Admin, keys.PublicKey{}); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("an admin adding an admin: %v", err)
	}
	if _, err := (&Writer{R: r, Me: admin}).SetRole(admin.Public(), Member); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("an admin changing a role: %v", err)
	}
	if _, err := (&Writer{R: r, Me: owner}).SetRole(admin.Public(), Member); err != nil {
		t.Fatal(err)
	}
	if f, _ = r.Fold(); f.Roles[admin.Public()] != Member {
		t.Fatal("the demotion didn't take")
	}
}

func TestMirrorGetsNoEpochKeys(t *testing.T) {
	r, owner, _, _ := group(t)
	mirror := me(9)
	if _, err := (&Writer{R: r, Me: owner}).Add(mirror.Public(), "mirror", Mirror, keys.PublicKey{}); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Writer{R: r, Me: owner}).Rekey(); err != nil {
		t.Fatal(err)
	}
	f, _ := r.Fold()
	k := r.Keyring(mirror)
	if len(k.Epochs) != 0 {
		t.Fatal("a mirror holds epoch keys")
	}
	if _, ok := k.Secrets[f.Current]; !ok {
		t.Fatal("a mirror lacks the current group secret")
	}
	// Nothing left to deliver it.
	if _, err := (&Writer{R: r, Me: owner}).Deliver(mirror.Public(), keys.PublicKey{}); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("delivering to a mirror that holds everything it may: %v", err)
	}
}

func TestDeliverFillsGaps(t *testing.T) {
	r, owner, admin, member := group(t)
	// The owner rekeys in a copy that hasn't seen the member's add, so the
	// member misses the new keys; the admin, seeing both, delivers them.
	stale, err := New(r.Op(r.Group()))
	if err != nil {
		t.Fatal(err)
	}
	var adminAdd *Op
	for _, o := range r.ops {
		if o.Kind == Add && o.Target == admin.Public() {
			adminAdd = o
		}
	}
	if _, err := stale.Add(adminAdd); err != nil {
		t.Fatal(err)
	}
	rk, err := (&Writer{R: stale, Me: owner}).Rekey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add(rk); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Keyring(member).Epochs[rk.ID()]; ok {
		t.Fatal("the member got a rekey made without it")
	}
	if _, err := (&Writer{R: r, Me: admin}).Deliver(member.Public(), keys.PublicKey{}); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Keyring(member).Epochs[rk.ID()]; !ok {
		t.Fatal("the deliver didn't fill the gap")
	}
	if _, err := (&Writer{R: r, Me: admin}).Deliver(member.Public(), keys.PublicKey{}); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("a second deliver with nothing new: %v", err)
	}
}

func TestDecodeRoundTrip(t *testing.T) {
	r, _, _, _ := group(t)
	for _, o := range r.ops {
		d, err := Decode(o.Encode())
		if err != nil {
			t.Fatalf("%v: %v", o, err)
		}
		if d.ID() != o.ID() || !bytes.Equal(d.Encode(), o.Encode()) {
			t.Fatalf("%v didn't round-trip", o)
		}
	}
}

func anyAdd(t *testing.T) *Op {
	r, _, _, _ := group(t)
	for _, o := range r.ops {
		if o.Kind == Add {
			return o
		}
	}
	t.Fatal("no add")
	return nil
}

func TestDecodeRejects(t *testing.T) {
	o := anyAdd(t)
	enc := o.Encode()

	bad := bytes.Clone(enc)
	bad[len(bad)-3] ^= 1 // inside the signature
	if _, err := Decode(bad); !errors.Is(err, ErrSignature) {
		t.Fatalf("a flipped signature byte: %v", err)
	}

	v, err := bencode.Decode(enc)
	if err != nil {
		t.Fatal(err)
	}
	reencode := func(f func(d []bencode.Pair) []bencode.Pair) []byte {
		d := f(append([]bencode.Pair{}, v.Dict...))
		var b []byte
		b = append(b, 'd')
		for _, p := range d { // in the given order, not sorted
			b = bencode.AppendBytes(b, p.Key)
			b = bencode.Append(b, p.Value)
		}
		return append(b, 'e')
	}
	for name, b := range map[string][]byte{
		"unsorted keys": reencode(func(d []bencode.Pair) []bencode.Pair { d[0], d[1] = d[1], d[0]; return d }),
		"an unknown key": reencode(func(d []bencode.Pair) []bencode.Pair {
			return append(d, bencode.Pair{Key: []byte("zz"), Value: num(1)})
		}),
		"an explicit zero shard count": reencode(func(d []bencode.Pair) []bencode.Pair {
			return append(d[:len(d)-1:len(d)-1], bencode.Pair{Key: []byte("s"), Value: num(0)}, d[len(d)-1])
		}),
		"a trailing byte": append(bytes.Clone(enc), 'x'),
	} {
		if _, err := Decode(b); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestDecodeRejectsSmallOrderKeys(t *testing.T) {
	o := anyAdd(t)
	c := *o
	c.Target = keys.PublicKey(edwards25519.NewIdentityPoint().Bytes())
	c.Sign(me(2))
	if _, err := Decode(c.Encode()); !errors.Is(err, ErrMalformed) {
		t.Fatalf("a small-order target: %v", err)
	}
}

func TestAddRefuses(t *testing.T) {
	r, owner, _, _ := group(t)
	other, err := Found(me(5), "other", 1)
	if err != nil {
		t.Fatal(err)
	}
	o, err := (&Writer{R: other, Me: me(5)}).Rekey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add(o); !errors.Is(err, ErrWrongGroup) {
		t.Fatalf("another group's op: %v", err)
	}
	orphan := &Op{Group: r.group, Kind: Rekey, Lamport: 9, Parents: []ID{{1}}}
	orphan.Sign(owner)
	if _, err := r.Add(orphan); !errors.Is(err, ErrMissingParent) {
		t.Fatalf("an op with a missing parent: %v", err)
	}
	if fresh, err := r.Add(r.Op(r.Heads()[0])); fresh || err != nil {
		t.Fatalf("re-adding a held op: %v, %v", fresh, err)
	}
}

// TestKeyringChecksCommitments: a key that doesn't match its maker's
// commitment is ignored, whoever sealed it.
func TestKeyringChecksCommitments(t *testing.T) {
	r, owner, admin, member := group(t)
	// A rekey made without the member, so the member holds none of its keys.
	stale, err := New(r.Op(r.Group()))
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range r.ops {
		if o.Kind == Add && o.Target == admin.Public() {
			if _, err := stale.Add(o); err != nil {
				t.Fatal(err)
			}
		}
	}
	rk, err := (&Writer{R: stale, Me: owner}).Rekey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add(rk); err != nil {
		t.Fatal(err)
	}
	// The owner delivers the member a wrong key for that rekey.
	o := (&Writer{R: r, Me: owner}).base(Deliver)
	o.Target = member.Public()
	if err := seal(o, member.Public(), []entry{{made: rk.ID(), key: [32]byte{0xbb}}}); err != nil {
		t.Fatal(err)
	}
	o.Sign(owner)
	if _, err := r.Add(o); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Keyring(member).Epochs[rk.ID()]; ok {
		t.Fatal("a key not matching its commitment was accepted")
	}
}

func TestLamportMustFollowParents(t *testing.T) {
	r, owner, _, _ := group(t)
	for _, delta := range []int64{-1, 0, 2, 1 << 40} {
		o := (&Writer{R: r, Me: owner}).base(Rekey)
		o.Lamport = uint64(int64(o.Lamport) + delta - 1)
		o.Sign(owner)
		if _, err := r.Add(o); !errors.Is(err, ErrLamport) {
			t.Fatalf("clock off by %d: %v", delta-1, err)
		}
	}
	g := r.Op(r.Group())
	bad := *g
	bad.Lamport = 2
	bad.Sign(owner)
	if _, err := New(&bad); !errors.Is(err, ErrMalformed) {
		t.Fatalf("a genesis with clock 2: %v", err)
	}
}

// TestLyingHoldsDontStarve: a member's seal claiming the recipient already
// holds a key it never got doesn't stop an admin delivering it.
func TestLyingHoldsDontStarve(t *testing.T) {
	r, owner, admin, member := group(t)
	// The owner rekeys in a copy that hasn't seen the member's add, so the
	// member misses the new keys.
	stale, err := New(r.Op(r.Group()))
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range r.ops {
		if o.Kind == Add && o.Target == admin.Public() {
			if _, err := stale.Add(o); err != nil {
				t.Fatal(err)
			}
		}
	}
	rk, err := (&Writer{R: stale, Me: owner}).Rekey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add(rk); err != nil {
		t.Fatal(err)
	}
	// The member lies that it already holds the rekey's keys, so nobody
	// delivers them.
	lie := (&Writer{R: r, Me: member}).base(Deliver)
	lie.Target = member.Public()
	if err := seal(lie, member.Public(), nil); err != nil {
		t.Fatal(err)
	}
	lie.Seals[0].Holds = []KeyRef{{Made: rk.ID()}, {Made: rk.ID(), Secret: true}}
	lie.Sign(member)
	if _, err := r.Add(lie); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Keyring(member).Epochs[rk.ID()]; ok {
		t.Fatal("setup: the member already holds the rekey's epoch key")
	}
	if _, err := (&Writer{R: r, Me: admin}).Deliver(member.Public(), keys.PublicKey{}); err != nil {
		t.Fatalf("the lie stopped the admin's deliver: %v", err)
	}
	if _, ok := r.Keyring(member).Epochs[rk.ID()]; !ok {
		t.Fatal("the member still lacks the rekey's epoch key")
	}
}

func TestDecodeChecksTargets(t *testing.T) {
	r, owner, admin, _ := group(t)
	w := &Writer{R: r, Me: owner}
	noTarget := w.base(Add)
	noTarget.Role = Member
	noTarget.Sign(owner)
	if _, err := Decode(noTarget.Encode()); !errors.Is(err, ErrMalformed) {
		t.Fatalf("an add with no target: %v", err)
	}
	rekeyWithTarget := w.base(Rekey)
	rekeyWithTarget.Target = admin.Public()
	rekeyWithTarget.Sign(owner)
	if _, err := Decode(rekeyWithTarget.Encode()); !errors.Is(err, ErrMalformed) {
		t.Fatalf("a rekey with a target: %v", err)
	}
	twice := w.base(Deliver)
	twice.Target = admin.Public()
	for range 2 {
		if err := seal(twice, admin.Public(), nil); err != nil {
			t.Fatal(err)
		}
	}
	twice.Sign(owner)
	if _, err := Decode(twice.Encode()); !errors.Is(err, ErrMalformed) {
		t.Fatalf("two seals to one key: %v", err)
	}
}

func TestWritersStayDecodable(t *testing.T) {
	long := string(bytes.Repeat([]byte("x"), MaxName+1))
	if _, err := Found(me(1), long, 3); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("a long group name: %v", err)
	}
	if _, err := Found(me(1), "g", MaxShards+1); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("too many shards: %v", err)
	}
	r, owner, _, _ := group(t)
	if _, err := (&Writer{R: r, Me: owner}).Add(me(7).Public(), long, Member, keys.PublicKey{}); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("a long display name: %v", err)
	}
	if r.History(ID{9}) != nil {
		t.Fatal("History of an unknown op isn't nil")
	}
}

// TestRosterIsolated: what callers get back, and what they passed in,
// can't change the roster.
func TestRosterIsolated(t *testing.T) {
	r, _, admin, _ := group(t)
	rk, err := (&Writer{R: r, Me: admin}).Rekey()
	if err != nil {
		t.Fatal(err)
	}
	before, _ := r.Fold()
	h := r.History(rk.ID())
	for id := range h {
		delete(h, id)
	}
	rk.Name = "changed after adding"
	rk.Parents = nil
	r.Op(rk.ID()).Name = "changed after reading"
	for _, o := range before.Order {
		o.Parents, o.Lamport = nil, 0
	}
	after, err := r.Fold()
	if err != nil {
		t.Fatal(err)
	}
	if !after.Counts[rk.ID()] || after.Current != before.Current || r.Op(rk.ID()).Name != "" || len(r.Heads()) != 1 {
		t.Fatal("a caller's change reached the roster")
	}
	// The changed op is no longer the signed one.
	if _, err := r.Add(rk); err == nil {
		t.Fatal("a changed op was accepted as already held")
	}
}

func TestLogHeadAtSeqZero(t *testing.T) {
	r, _, admin, member := group(t)
	rm, err := (&Writer{R: r, Me: admin}).Remove(member.Public(), 0, [32]byte{9})
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Op(rm.ID()); got.LogSeq != 0 || got.LogHead != [32]byte{9} {
		t.Fatalf("the log head at sequence 0 was lost: %d %x", got.LogSeq, got.LogHead[:2])
	}
}

func TestDecodeRejectsFieldsOutsideKind(t *testing.T) {
	r, owner, admin, _ := group(t)
	w := &Writer{R: r, Me: owner}
	for name, set := range map[string]func(o *Op){
		"a role on a rekey":     func(o *Op) { o.Role = Member },
		"a name on a rekey":     func(o *Op) { o.Name = "x" },
		"a log head on a rekey": func(o *Op) { o.LogSeq = 3 },
		"an expiry on a rekey":  func(o *Op) { o.Expires = 5 },
		"an invite with no expiry": func(o *Op) {
			o.Kind, o.Invite, o.CommitSecret, o.CommitEpoch = Invite, admin.Public(), [32]byte{}, [32]byte{}
		},
	} {
		o := w.base(Rekey)
		set(o)
		o.Sign(owner)
		if _, err := Decode(o.Encode()); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestFoldScales: a long chain of one admin's operations folds in time
// linear in the chain per authority check, not quadratic or worse.
func TestFoldScales(t *testing.T) {
	r, _, admin, _ := group(t)
	w := &Writer{R: r, Me: admin}
	inv := me(8).Public()
	const n = 3000
	for i := range n {
		o := w.base(Invite)
		o.Invite, o.Expires = inv, int64(i+1)
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
	if d := time.Since(start); d > 5*time.Second && !raceEnabled {
		t.Fatalf("folding %d ops took %v", n, d)
	} else {
		t.Logf("folded %d ops in %v", len(f.Order), d)
	}
}

// TestFoldScalesAfterRemoval: removing or demoting an author with a long
// chain of ops folds in linear memory: the view rules ask a different
// ancestor per op, which must not be memoized pairwise.
func TestFoldScalesAfterRemoval(t *testing.T) {
	for _, demote := range []bool{false, true} {
		r, owner, admin, _ := group(t)
		w := &Writer{R: r, Me: admin}
		inv := me(8).Public()
		const n = 3000
		for i := range n {
			o := w.base(Invite)
			o.Invite, o.Expires = inv, int64(i+1)
			o.Sign(admin)
			if _, err := r.Add(o); err != nil {
				t.Fatal(err)
			}
		}
		ow := &Writer{R: r, Me: owner}
		var err error
		if demote {
			_, err = ow.SetRole(admin.Public(), Member)
		} else {
			_, err = ow.Remove(admin.Public(), 0, [32]byte{})
		}
		if err != nil {
			t.Fatal(err)
		}
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		start := time.Now()
		if _, err := r.Fold(); err != nil {
			t.Fatal(err)
		}
		d := time.Since(start)
		runtime.ReadMemStats(&after)
		if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 200<<20 || (d > 5*time.Second && !raceEnabled) {
			t.Fatalf("demote=%v: folding %d ops allocated %d MB in %v", demote, n, alloc>>20, d)
		} else {
			t.Logf("demote=%v: folded in %v, allocating %d MB", demote, d, alloc>>20)
		}
	}
}

// TestFoldScalesWithTurnover: many members added and removed fold quickly:
// the view rules skip removed keys that never wrote anything.
func TestFoldScalesWithTurnover(t *testing.T) {
	r, owner, _, _ := group(t)
	ow := &Writer{R: r, Me: owner}
	for i := range 300 {
		k := keys.IdentityFromSeed([32]byte{0xf0, byte(i), byte(i >> 8)}).Public()
		if _, err := ow.Add(k, "m", Member, keys.PublicKey{}); err != nil {
			t.Fatal(err)
		}
		if _, err := ow.Remove(k, 0, [32]byte{}); err != nil {
			t.Fatal(err)
		}
	}
	fresh, err := New(r.Op(r.Group()))
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range r.order()[1:] {
		if _, err := fresh.Add(o); err != nil {
			t.Fatal(err)
		}
	}
	start := time.Now()
	if _, err := fresh.Fold(); err != nil { // cold: no views cached
		t.Fatal(err)
	}
	// About 40 ms with the skip; the walk of every removed key's history
	// took about 700 ms.
	if d := time.Since(start); d > 350*time.Millisecond && !raceEnabled {
		t.Fatalf("a cold fold of %d ops took %v", fresh.Len(), d)
	} else {
		t.Logf("a cold fold of %d ops took %v", fresh.Len(), d)
	}
}

// TestPromotionDoesntTrustOldLists: a member's deliver, written while it
// was a member, stays untrusted after the member is promoted.
func TestPromotionDoesntTrustOldLists(t *testing.T) {
	r, owner, admin, member := group(t)
	newcomer := me(6)
	if _, err := (&Writer{R: r, Me: owner}).Add(newcomer.Public(), "n", Member, keys.PublicKey{}); err != nil {
		t.Fatal(err)
	}
	stale, err := New(r.Op(r.Group()))
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range r.ops {
		if o.Kind == Add && o.Target == admin.Public() {
			if _, err := stale.Add(o); err != nil {
				t.Fatal(err)
			}
		}
	}
	rk, err := (&Writer{R: stale, Me: owner}).Rekey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add(rk); err != nil {
		t.Fatal(err)
	}
	// The member, still a member, lies that the newcomer has the rekey's keys,
	// then is promoted.
	lie := (&Writer{R: r, Me: member}).base(Deliver)
	lie.Target = newcomer.Public()
	if err := seal(lie, newcomer.Public(), nil); err != nil {
		t.Fatal(err)
	}
	lie.Seals[0].Holds = []KeyRef{{Made: rk.ID()}, {Made: rk.ID(), Secret: true}}
	lie.Sign(member)
	if _, err := r.Add(lie); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Writer{R: r, Me: owner}).SetRole(member.Public(), Admin); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Writer{R: r, Me: admin}).Deliver(newcomer.Public(), keys.PublicKey{}); err != nil {
		t.Fatalf("the promoted member's old lie stopped the deliver: %v", err)
	}
}

func TestDecodeRejectsBadSealRecipient(t *testing.T) {
	r, owner, admin, _ := group(t)
	o := (&Writer{R: r, Me: owner}).base(Deliver)
	o.Target = admin.Public()
	o.Seals = []Seal{{To: keys.PublicKey(edwards25519.NewIdentityPoint().Bytes()), Box: []byte{1}}}
	o.Sign(owner)
	if _, err := Decode(o.Encode()); !errors.Is(err, ErrMalformed) {
		t.Fatalf("a seal to a small-order key: %v", err)
	}
}

// TestFoldScalesWithAdmissions: a cold fold of many distinct admissions,
// each of whose views folds its whole prefix.
func TestFoldScalesWithAdmissions(t *testing.T) {
	r, owner, _, _ := group(t)
	ow := &Writer{R: r, Me: owner}
	const n = 500
	for i := range n {
		k := keys.IdentityFromSeed([32]byte{0xe0, byte(i), byte(i >> 8)}).Public()
		if _, err := ow.Add(k, "m", Member, keys.PublicKey{}); err != nil {
			t.Fatal(err)
		}
	}
	fresh, err := New(r.Op(r.Group()))
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range r.order()[1:] {
		if _, err := fresh.Add(o); err != nil {
			t.Fatal(err)
		}
	}
	start := time.Now()
	if _, err := fresh.Fold(); err != nil {
		t.Fatal(err)
	}
	// About 50 ms: each admission's view folds its prefix, quadratic in
	// principle but small at group sizes.
	if d := time.Since(start); d > time.Second && !raceEnabled {
		t.Fatalf("a cold fold of %d admissions took %v", n, d)
	}
}

// TestUnseenPromotionDoesntTrustLists: a member's deliver written before it
// saw its promotion (which sorts first) isn't recorded as an admin's.
func TestUnseenPromotionDoesntTrustLists(t *testing.T) {
	r, owner, _, member := group(t)
	stale, err := New(r.Op(r.Group()))
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range r.order()[1:] {
		if _, err := stale.Add(o); err != nil {
			t.Fatal(err)
		}
	}
	promo, err := (&Writer{R: r, Me: owner}).SetRole(member.Public(), Admin)
	if err != nil {
		t.Fatal(err)
	}
	// In the copy without the promotion the member writes twice, so its
	// second deliver's clock is above the promotion's.
	sw := &Writer{R: stale, Me: member}
	var lie *Op
	for range 2 {
		lie = sw.base(Deliver)
		lie.Target = owner.Public()
		if err := seal(lie, owner.Public(), nil); err != nil {
			t.Fatal(err)
		}
		lie.Sign(member)
		if _, err := stale.Add(lie); err != nil {
			t.Fatal(err)
		}
	}
	for _, o := range stale.order() {
		if _, err := r.Add(o); err != nil && !errors.Is(err, ErrWrongGroup) {
			t.Fatal(err)
		}
	}
	f, err := r.Fold()
	if err != nil {
		t.Fatal(err)
	}
	if !f.Counts[promo.ID()] || !f.Counts[lie.ID()] || lie.Lamport <= promo.Lamport {
		t.Fatal("setup: the promotion should count and sort before the deliver")
	}
	if f.As[lie.ID()] != Member {
		t.Fatalf("a deliver written before its author saw its promotion is recorded as %v", f.As[lie.ID()])
	}
}

// TestLargeGroupOpsDecode: a rekey sealed to hundreds of members stays
// decodable (a datagram's bencode budget would refuse it).
func TestLargeGroupOpsDecode(t *testing.T) {
	r, owner, _, _ := group(t)
	ow := &Writer{R: r, Me: owner}
	for i := range 200 {
		k := keys.IdentityFromSeed([32]byte{0xd0, byte(i)}).Public()
		if _, err := ow.Add(k, "m", Member, keys.PublicKey{}); err != nil {
			t.Fatal(err)
		}
	}
	rk, err := ow.Rekey()
	if err != nil {
		t.Fatalf("a rekey to 200+ members: %v", err)
	}
	if len(rk.Seals) < 200 {
		t.Fatalf("rekey sealed to %d", len(rk.Seals))
	}
	if _, err := Decode(rk.Encode()); err != nil {
		t.Fatal(err)
	}
	big := make([]byte, MaxOpBytes+1)
	if _, err := Decode(big); !errors.Is(err, ErrMalformed) {
		t.Fatalf("an oversized encoding: %v", err)
	}
}

// TestRemovedAdminListsUntrusted: a removed admin's seal key lists stop
// counting, so its lie can't keep a member from getting a key.
func TestRemovedAdminListsUntrusted(t *testing.T) {
	r, owner, admin, member := group(t)
	stale, err := New(r.Op(r.Group()))
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range r.ops {
		if o.Kind == Add && o.Target == admin.Public() {
			if _, err := stale.Add(o); err != nil {
				t.Fatal(err)
			}
		}
	}
	rk, err := (&Writer{R: stale, Me: owner}).Rekey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add(rk); err != nil {
		t.Fatal(err)
	}
	lie := (&Writer{R: r, Me: admin}).base(Deliver)
	lie.Target = member.Public()
	if err := seal(lie, member.Public(), nil); err != nil {
		t.Fatal(err)
	}
	lie.Seals[0].Holds = []KeyRef{{Made: rk.ID()}, {Made: rk.ID(), Secret: true}}
	lie.Sign(admin)
	if _, err := r.Add(lie); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Writer{R: r, Me: owner}).Remove(admin.Public(), 0, [32]byte{}); err != nil {
		t.Fatal(err)
	}
	// The owner's removal rekeyed; the member still lacks rk's keys, and
	// the removed admin's lie no longer hides that.
	if _, err := (&Writer{R: r, Me: owner}).Deliver(member.Public(), keys.PublicKey{}); err != nil {
		t.Fatalf("the removed admin's lie stopped the deliver: %v", err)
	}
	if _, ok := r.Keyring(member).Epochs[rk.ID()]; !ok {
		t.Fatal("the member still lacks the rekey's epoch key")
	}
}

func TestDecodeBoundsValues(t *testing.T) {
	// A list of empty lists within the byte bound but past the value bound.
	b := []byte("d1:al")
	for len(b) < MaxOpBytes-4 {
		b = append(b, 'l', 'e')
	}
	b = append(b, 'e', 'e')
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if _, err := Decode(b); !errors.Is(err, ErrMalformed) {
		t.Fatalf("a document of half a million values: %v", err)
	}
	runtime.ReadMemStats(&after)
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 64<<20 {
		t.Fatalf("decoding it allocated %d MB", alloc>>20)
	}
}

// TestWritersRefuseTooManyValues: a rekey whose seals exceed the decoder's
// value budget, though under the byte bound, fails with ErrTooLarge.
func TestWritersRefuseTooManyValues(t *testing.T) {
	r, owner, _, _ := group(t)
	ow := &Writer{R: r, Me: owner}
	o := ow.base(Rekey)
	o.CommitSecret, o.CommitEpoch = [32]byte{1}, [32]byte{2}
	for i := range 4300 { // eight values a seal: past the budget
		k := keys.IdentityFromSeed([32]byte{0xc0, byte(i), byte(i >> 8)}).Public()
		if err := seal(o, k, []entry{{secret: true}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ow.finish(o); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("a rekey past the value budget: %v (%d bytes)", err, len(o.Encode()))
	}
	if len(o.Encode()) > MaxOpBytes {
		t.Fatal("setup: the op should be under the byte bound")
	}
}
