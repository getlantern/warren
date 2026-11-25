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

var depth = flag.Int("roster.depth", 4, "actions explored past the setup (5 for a full run, about nine minutes: add -timeout=1h)")

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
		if kind == Add || kind == SetRole {
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
				// Promote or demote each, whichever its role allows, so
				// demote-then-promote chains get explored.
				for _, k := range []Key{A, B, M, N} {
					switch f.Roles[k] {
					case Admin:
						op(r, SetRole, k, Member, false)
					case Member:
						op(r, SetRole, k, Admin, false)
					}
				}
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
		case Owner:
			// Roles change only through role operations, not by re-adding.
			as = append(as, rogue(r, Add, M, Admin))
		case Admin:
			other := A
			if r == A {
				other = B
			}
			// Re-adding N as a member is a role change once N is a mirror,
			// and a re-add once it's removed: neither may count.
			as = append(as, rogue(r, Remove, O, None), rogue(r, Add, N, Admin), rogue(r, SetRole, M, Admin))
			if f.Roles[other] == Admin {
				as = append(as, rogue(r, Remove, other, None), rogue(r, SetRole, other, Member))
			}
			if f.Roles[N] != None || f.Removed[N] != 0 {
				as = append(as, rogue(r, Add, N, Member))
			}
		case Member:
			as = append(as, rogue(r, Rekey, 0, None), rogue(r, Add, N, Member), rogue(r, Remove, A, None))
		}
		if f.Removed[r] != 0 || demoted(f, r) {
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

// rogue writes an operation its author has no authority for, as a
// compromised device could: a remove or rekey seals its new keys as an
// honest one would, since only its authority is forged.
func rogue(r Key, kind Kind, target Key, role Role) action {
	return action{fmt.Sprintf("%v %v %v as %v (rogue)", r, kind, target, role), func(w world) bool {
		s := w[r]
		o := newOp(s, kind, r, target, role, s.Heads(), 0)
		o.Rogue = true
		if kind == Remove || kind == Rekey {
			f, err := Fold(s)
			if err != nil {
				return false
			}
			for _, k := range sortedKeys(f.Roles) {
				if kind == Remove && k == target {
					continue
				}
				sl := Seal{To: k, Gs: []ID{self}}
				if f.Roles[k] != Mirror {
					sl.Epochs = []ID{self}
				}
				o.Seals = append(o.Seals, sl)
			}
		}
		finish(s, o)
		return true
	}}
}

// memberLeak selects the seals of malicious operations that don't count,
// by authors still on the roster: a member can hand the keys it holds to
// anyone, which no protocol prevents, so they don't count as the protocol
// leaking. A malicious operation that counts seals what the protocol
// sanctions.
func memberLeak(f *Result) func(*Op) bool {
	return func(o *Op) bool {
		return (o.Backdated || o.Rogue) && !f.Counts[o.ID] && f.Roles[o.Author] != None
	}
}

// demoted reports whether k's last counting role change demoted it.
func demoted(f *Result, k Key) bool {
	g := f.Grants[k]
	return len(g) > 0 && g[len(g)-1].Role == Member
}

func opDesc(o *Op) string {
	if o.Kind == Rekey {
		return "rekey"
	}
	return fmt.Sprintf("%v %v", o.Kind, o.Target)
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
			return fmt.Errorf("rogue %v by %v counts", opDesc(o), o.Author)
		}
	}
	for _, o := range f.Order {
		// A backdated op was written after its author lost its authority,
		// so it may count only at member level (a deliver by a demoted
		// admin), even if the author has been promoted again since.
		if o.Backdated && f.Counts[o.ID] && (f.Removed[o.Author] != 0 || needsAdmin(o)) {
			return fmt.Errorf("backdated %v by removed or demoted %v counts", o.Kind, o.Author)
		}
	}
	// Past (not current) epoch keys can reach a key that ends up a mirror
	// or off the roster: an honest author seals to the roster as it sees
	// it, and concurrency can change that. The design states this window;
	// the current keys are what a corrective rekey protects.
	epochs, gs := u.HoldingsExcept(memberLeak(f))
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
	le, lg := r.HoldingsExcept(memberLeak(f))
	if leak := leaked(f, le, lg); leak != "" {
		return fmt.Errorf("after recovery, %s", leak)
	}
	// What members actually hold, including keys a malicious member handed
	// them, which the leak check above leaves out.
	epochs, gs = r.Holdings()
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
				// A key a malicious operation that doesn't count made is
				// the attacker's.
				if mk := r[e]; mk != nil && (mk.Backdated || mk.Rogue) && !f.Counts[mk.ID] {
					continue
				}
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

// docPredicate is Removal step 3: the current keys reached a key the fold
// doesn't keep as a member (removed, or whose add didn't count), or the
// current epoch key reached a mirror.
func docPredicate(u Store, f *Result) bool {
	epochs, gs := u.Holdings()
	return leaked(f, epochs, gs) != ""
}

// removedPredicate is Removal step 3 as first written: the current keys were
// sealed or delivered to a member the fold removed. Demotion breaks it.
func removedPredicate(u Store, f *Result) bool {
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
	admitted.Clear()
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
// corrective-rekey condition: the current keys reached a key the fold
// doesn't keep, or the current epoch key reached a mirror.
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
		// "deliver off the roster" leaks past epoch keys, which the leak
		// check (current keys only) doesn't see: TestDeliverOffRosterLeaksHistory.
		"members add", "members remove", "members rekey", "role changes count",
		"admins set roles", "no demotion view rule", "unseen grants count",
		"removers need not see demotions", "restores need not be seen",
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

// TestRemovedReAdd replays a trace past the default depth: an admin that
// saw a key removed re-adds it after the merged fold drops the removal.
func TestRemovedReAdd(t *testing.T) {
	w := setup(t, Rules{})
	steps := []action{}
	for _, a := range []struct {
		r Key
		f func(world) bool
	}{
		{O, func(w world) bool { return Author(w[O], Rules{}, Remove, O, A, None) != nil }},
		{A, func(w world) bool { return Author(w[A], Rules{}, Add, A, N, Member) != nil }},
		{A, func(w world) bool { return Author(w[A], Rules{}, Remove, A, N, None) != nil }},
		{B, func(w world) bool {
			for id, o := range w[A] {
				w[B][id] = o
			}
			return true
		}},
		{B, rogue(B, Add, N, Member).do},
	} {
		steps = append(steps, action{do: a.f})
	}
	for i, s := range steps {
		if !s.do(w) {
			t.Fatalf("step %d didn't apply", i)
		}
	}
	if err := check(w.union(), Rules{}, docPredicate); err != nil {
		t.Fatal(err)
	}
}

// restoredScenario is an admin demoted and then promoted again, which writes
// a rekey after seeing both: the promotion restores its authority, so the
// rekey counts.
func restoredScenario(t *testing.T) error {
	w := setup(t, Rules{})
	steps := []func() *Op{
		func() *Op { return Author(w[O], Rules{}, SetRole, O, A, Member) },
		func() *Op { return Author(w[O], Rules{}, SetRole, O, A, Admin) },
	}
	for i, st := range steps {
		if st() == nil {
			return fmt.Errorf("step %d not written", i)
		}
	}
	for id, o := range w[O] {
		w[A][id] = o
	}
	rk := Author(w[A], Rules{}, Rekey, A, 0, None)
	if rk == nil {
		return fmt.Errorf("A can't rekey after its promotion")
	}
	f, err := Fold(w.union())
	if err != nil {
		return err
	}
	if !f.Counts[rk.ID] {
		return fmt.Errorf("A's rekey after its re-promotion doesn't count")
	}
	return nil
}

func TestRestoredByPromotion(t *testing.T) {
	admitted.Clear()
	if err := restoredScenario(t); err != nil {
		t.Fatal(err)
	}
	mutation = "demotions never restored"
	defer func() { mutation = "" }()
	admitted.Clear()
	if restoredScenario(t) == nil {
		t.Fatal("mutation not caught")
	}
}

// TestFourPassChain is a chain deeper than the explorer reaches, where the
// view rule takes four passes: dropping a removed admin's branch makes the
// owner's add of N count, which makes N's remove of M count, which drops
// M's delivery.
func TestFourPassChain(t *testing.T) {
	w := setup(t, Rules{})
	must := func(o *Op) {
		t.Helper()
		if o == nil {
			t.Fatal("op not written")
		}
	}
	firstRekey := Author(w[A], Rules{}, Rekey, A, 0, None)
	must(firstRekey)
	must(Author(w[A], Rules{}, Add, A, N, Member))
	must(Author(w[A], Rules{}, Remove, A, N, None))
	for range 3 {
		must(Author(w[O], Rules{}, Rekey, O, 0, None))
	}
	must(Author(w[O], Rules{}, Add, O, N, Admin))
	sawAdd := w[O].Clone()
	must(Author(w[O], Rules{}, Remove, O, A, None))

	n := sawAdd.Clone()
	must(Author(n, Rules{}, Remove, N, M, None))
	m := sawAdd.Clone()
	m[firstRekey.ID] = firstRekey
	must(Author(m, Rules{}, Deliver, M, N, None))

	u := w.union()
	for _, s := range []Store{n, m} {
		for id, o := range s {
			u[id] = o
		}
	}
	f, err := Fold(u)
	if err != nil {
		t.Fatal(err)
	}
	if f.Passes != 4 || f.Roles[N] != Admin || f.Roles[M] != None {
		t.Fatalf("passes %d, N %v, M %v; want 4, admin, none", f.Passes, f.Roles[N], f.Roles[M])
	}
	if err := check(u, Rules{}, docPredicate); err != nil {
		t.Fatal(err)
	}
}

// TestRemovedOnlyCondition shows the corrective rekey's first condition,
// keys reaching a removed member, misses a leak demotion makes possible: an
// admin that hadn't seen its demotion adds a key, the demotion's view rule
// drops the add, and the key holds the current epoch key off the roster
// while nobody removed holds it.
func TestRemovedOnlyCondition(t *testing.T) {
	_, failure := explore(t, Rules{}, removedPredicate, *depth)
	demotion := strings.Contains(failure, "role A as member") || strings.Contains(failure, "role B as member")
	if !strings.Contains(failure, "off the roster") || !demotion {
		t.Fatalf("want the demotion counterexample, got: %q", failure)
	}
	t.Logf("counterexample: %s", failure)
}

// TestDeliverOffRosterLeaksHistory pins delivery's roster check: without
// it, a deliver hands a key that was never admitted every past epoch key
// its sender holds, which no rekey can take back. The corrective rekey
// covers only the current keys.
func TestDeliverOffRosterLeaksHistory(t *testing.T) {
	try := func() (*Op, map[ID]bool) {
		w := setup(t, Rules{})
		Author(w[O], Rules{}, Rekey, O, 0, None)
		for id, o := range w[O] {
			w[M][id] = o
		}
		d := Author(w[M], Rules{}, Deliver, M, N, None)
		epochs, _ := w.union().Holdings()
		return d, epochs[N]
	}
	if d, _ := try(); d != nil {
		t.Fatal("a deliver to a key never on the roster was written")
	}
	mutation = "deliver off the roster"
	defer func() { mutation = "" }()
	d, held := try()
	if d == nil || len(held) < 2 {
		t.Fatalf("without the roster check, N should get the old and current epoch keys, got %d", len(held))
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
