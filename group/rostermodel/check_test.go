package rostermodel

import (
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"slices"
	"strings"
	"testing"
)

var depth = flag.Int("roster.depth", 4, "actions explored past the setup (6 for a full run, about six minutes)")

const (
	O Key = iota + 1 // owner
	A                // admin
	B                // admin
	M                // member
	N                // joiner, added during exploration
)

var keyNames = map[Key]string{O: "O", A: "A", B: "B", M: "M", N: "N"}

func (k Key) String() string { return keyNames[k] }

var replicas = []Key{O, A, B, M}

// world is every replica's store.
type world map[Key]Store

func (w world) clone() world {
	c := world{}
	for k, s := range w {
		c[k] = s.Clone()
	}
	return c
}

func (w world) key() [32]byte {
	h := sha256.New()
	var b [8]byte
	for _, r := range replicas {
		ids := make([]ID, 0, len(w[r]))
		for id := range w[r] {
			ids = append(ids, id)
		}
		slices.Sort(ids)
		for _, id := range ids {
			binary.BigEndian.PutUint64(b[:], uint64(id))
			h.Write(b[:])
		}
		h.Write([]byte{0xff})
	}
	return [32]byte(h.Sum(nil))
}

func (w world) union() Store {
	u := Store{}
	for _, s := range w {
		for id, o := range s {
			u[id] = o
		}
	}
	return u
}

func setup(t *testing.T, rules Rules) world {
	s := NewGenesis(O)
	for _, st := range []struct {
		author, target Key
		role           Role
	}{{O, A, Admin}, {O, B, Admin}, {A, M, Member}} {
		if Author(s, rules, Add, st.author, st.target, st.role) == nil {
			t.Fatalf("setup: %v can't add %v", st.author, st.target)
		}
	}
	w := world{}
	for _, r := range replicas {
		w[r] = s.Clone()
	}
	return w
}

type action struct {
	desc string
	do   func(w world) bool
}

func actions(w world, rules Rules) []action {
	var as []action
	op := func(r Key, kind Kind, target Key, role Role, malicious bool) {
		desc := fmt.Sprintf("%v %v %v", r, kind, target)
		if kind == Add {
			desc += " as " + role.String()
		}
		if malicious {
			desc += " (backdated)"
		}
		as = append(as, action{desc, func(w world) bool {
			if malicious {
				return AuthorBackdated(w[r], kind, r, target, role) != nil
			}
			return Author(w[r], rules, kind, r, target, role) != nil
		}})
	}
	for _, r := range replicas {
		f, err := Fold(w[r])
		if err != nil {
			continue
		}
		switch f.Roles[r] {
		case Owner, Admin:
			op(r, Rekey, 0, None, false)
			for _, t := range []Key{A, B, M, N} {
				op(r, Remove, t, None, false)
			}
			if f.Roles[r] == Owner {
				op(r, Add, N, Admin, false)
			} else {
				op(r, Add, N, Member, false)
				op(r, Add, N, Mirror, false)
			}
		}
		if f.Roles[r] != None {
			for _, t := range []Key{O, A, B, M, N} {
				if t != r {
					op(r, Deliver, t, None, false)
				}
			}
		}
		// A compromised device signing what its role has no authority for.
		switch f.Roles[r] {
		case Admin:
			other := A
			if r == A {
				other = B
			}
			as = append(as, rogue(r, Remove, O, None), rogue(r, Remove, other, None), rogue(r, Add, N, Admin))
		case Member, Mirror:
			as = append(as, rogue(r, Rekey, 0, None), rogue(r, Add, N, Member), rogue(r, Remove, A, None))
		}
		if f.Removed[r] != 0 {
			op(r, Add, N, Member, true)
			op(r, Rekey, 0, None, true)
			op(r, Deliver, N, None, true)
			op(r, Remove, M, None, true)
		}
		for _, s := range replicas {
			if s == r {
				continue
			}
			as = append(as, action{fmt.Sprintf("%v syncs from %v", r, s), func(w world) bool {
				grew := false
				for id, o := range w[s] {
					if w[r][id] == nil {
						w[r][id] = o
						grew = true
					}
				}
				return grew
			}})
		}
	}
	return as
}

// rogue writes an operation its author has no authority for, sealing
// nothing, as a compromised admin could.
func rogue(r Key, kind Kind, target Key, role Role) action {
	return action{fmt.Sprintf("%v %v %v as %v (rogue)", r, kind, target, role), func(w world) bool {
		s := w[r]
		o := newOp(s, kind, r, target, role, s.Heads(), 0)
		o.Rogue = true
		finish(s, o)
		return true
	}}
}

// maxPasses is the most passes any fold in a run needed.
var maxPasses int

// check returns the first property the folded union of every replica's
// operations violates, after the doc's recovery (step 3 of Removal) runs.
func check(u Store, rules Rules, pred func(Store, *Result) bool) error {
	f, err := Fold(u)
	if err != nil {
		return err
	}
	maxPasses = max(maxPasses, f.Passes)
	if f.Roles[O] != Owner {
		return fmt.Errorf("owner lost its role: %v", f.Roles[O])
	}
	for _, o := range f.Order {
		if o.Rogue && f.Counts[o.ID] {
			return fmt.Errorf("rogue %v %v by %v counts", o.Kind, o.Target, o.Author)
		}
	}
	for _, o := range f.Order {
		if o.Backdated && f.Counts[o.ID] && f.Removed[o.Author] != 0 {
			return fmt.Errorf("backdated %v by removed %v counts", o.Kind, o.Author)
		}
	}
	// Past (not current) epoch keys can reach a key that ends up a mirror
	// or off the roster: an honest author seals to the roster as it sees
	// it, and concurrency can change that. The design states this window;
	// the current keys are what a corrective rekey protects.
	epochs, gs := u.Holdings()
	leak := leaked(f, epochs, gs)
	if leak != "" && !pred(u, f) {
		return fmt.Errorf("no corrective rekey is called for, yet %s", leak)
	}

	// Recovery: the owner, seeing everything, rekeys if the predicate calls
	// for it; then members deliver what others lack until nothing changes.
	r := u.Clone()
	if pred(r, f) && Author(r, rules, Rekey, O, 0, None) == nil {
		return fmt.Errorf("owner can't issue the corrective rekey")
	}
	for range 8 {
		f2, err := Fold(r)
		if err != nil {
			return fmt.Errorf("during recovery: %w", err)
		}
		grew := false
		for _, k := range sortedKeys(f2.Roles) {
			for _, t := range sortedKeys(f2.Roles) {
				if k != t && Author(r, rules, Deliver, k, t, None) != nil {
					grew = true
				}
			}
		}
		if !grew {
			break
		}
	}
	if f, err = Fold(r); err != nil {
		return fmt.Errorf("after recovery: %w", err)
	}
	epochs, gs = r.Holdings()
	if leak := leaked(f, epochs, gs); leak != "" {
		return fmt.Errorf("after recovery, %s", leak)
	}
	// Every epoch key a member holds stays readable to every other member,
	// including those made by a rekey that lost the total order.
	for k, role := range f.Roles {
		if role == Mirror {
			continue
		}
		for j, other := range f.Roles {
			if other == Mirror {
				continue
			}
			for e := range epochs[j] {
				if !epochs[k][e] {
					return fmt.Errorf("after recovery, %v %v lacks an epoch key %v holds", role, k, j)
				}
			}
		}
	}
	for k, role := range f.Roles {
		if !gs[k][f.Current] {
			return fmt.Errorf("after recovery, %v %v lacks the current group secret", role, k)
		}
		if role != Mirror && !epochs[k][f.Current] {
			return fmt.Errorf("after recovery, %v %v lacks the current epoch key", role, k)
		}
	}
	return nil
}

// leaked describes a key off the roster holding a current key, or a mirror
// holding the current epoch key.
func leaked(f *Result, epochs, gs map[Key]map[ID]bool) string {
	for _, k := range sortedKeysOf(epochs) {
		r := f.Roles[k]
		switch {
		case r == None && epochs[k][f.Current]:
			return fmt.Sprintf("%v, off the roster, holds the current epoch key", k)
		case r == None && gs[k][f.Current]:
			return fmt.Sprintf("%v, off the roster, holds the current group secret", k)
		case r == Mirror && epochs[k][f.Current]:
			return fmt.Sprintf("mirror %v holds the current epoch key", k)
		}
	}
	return ""
}

func sortedKeysOf(m map[Key]map[ID]bool) []Key {
	out := make([]Key, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// docPredicate is Removal step 3 as written: the current keys were sealed
// or delivered to a member the fold removed.
func docPredicate(u Store, f *Result) bool {
	epochs, gs := u.Holdings()
	for k := range f.Removed {
		if epochs[k][f.Current] || gs[k][f.Current] {
			return true
		}
	}
	return false
}

// explore runs every interleaving of actions to the given depth, checking
// the union at each state, and returns the first violation with its trace.
func explore(t *testing.T, rules Rules, pred func(Store, *Result) bool, depth int) (states int, failure string) {
	if depth < 0 {
		t.Fatalf("-roster.depth must be at least 0, not %d", depth)
	}
	start := setup(t, rules)
	// seen records the most depth left any visit had, so a state first
	// reached deep is explored again when a shorter path reaches it.
	seen := map[[32]byte]int{}
	var trace []string
	var dfs func(w world, d int) bool
	dfs = func(w world, d int) bool {
		k := w.key()
		left, ok := seen[k]
		if ok && left >= d {
			return false
		}
		seen[k] = d
		if !ok {
			if err := check(w.union(), rules, pred); err != nil {
				failure = fmt.Sprintf("%v\n  after: %s", err, strings.Join(trace, "; "))
				return true
			}
		}
		if d == 0 {
			return false
		}
		for _, a := range actions(w, rules) {
			next := w.clone()
			if !a.do(next) {
				continue
			}
			trace = append(trace, a.desc)
			if dfs(next, d-1) {
				return true
			}
			trace = trace[:len(trace)-1]
		}
		return false
	}
	dfs(start, depth)
	return len(seen), failure
}

// TestRosterModel model-checks the roster rules, with Removal step 3's
// corrective-rekey condition as written. Honest concurrency can also put the
// current keys on a mirror or on a key whose add didn't count, but only by a
// key-maker that hadn't seen a removal, which then also sealed them to the
// removed member, so the written condition fires.
func TestRosterModel(t *testing.T) {
	maxPasses = 0
	states, failure := explore(t, Rules{}, docPredicate, *depth)
	t.Logf("%d states explored to depth %d; folds took at most %d passes", states, *depth, maxPasses)
	if failure != "" {
		t.Fatal(failure)
	}
	// Owner operations decide admins, admins' decide members, and members'
	// decide nothing, so the view rule settles quickly.
	if maxPasses > 3 {
		t.Errorf("a fold took %d passes", maxPasses)
	}
}

// TestMutations breaks each rule in turn and checks the explorer catches it,
// so a passing TestRosterModel means the properties have teeth.
func TestMutations(t *testing.T) {
	for _, m := range []string{
		"no view rule", "admins add admins", "admins remove admins", "owner removable",
		"members add", "members rekey", "deliver off the roster",
	} {
		t.Run(m, func(t *testing.T) {
			mutation = m
			defer func() { mutation = "" }()
			_, failure := explore(t, Rules{}, docPredicate, *depth)
			if failure == "" {
				t.Fatal("mutation not caught")
			}
			t.Logf("caught: %s", failure)
		})
	}
}

// TestNoCorrectiveRekey checks the corrective rekey is needed: without it,
// a removed member keeps the current keys.
func TestNoCorrectiveRekey(t *testing.T) {
	_, failure := explore(t, Rules{}, func(Store, *Result) bool { return false }, *depth)
	if failure == "" {
		t.Fatal("no counterexample found")
	}
	t.Logf("counterexample: %s", failure)
}

// TestDeliverAfterAnyRemove shows the doc's first wording of the deliver
// rule fails: withholding keys after any remove of the recipient, counting
// or not, starves a member whose remove didn't count.
func TestDeliverAfterAnyRemove(t *testing.T) {
	_, failure := explore(t, Rules{DeliverAfterAnyRemove: true}, docPredicate, *depth)
	if failure == "" {
		t.Fatal("no counterexample found")
	}
	t.Logf("counterexample: %s", failure)
}
