package roster

import (
	"crypto/rand"
	"flag"
	"fmt"
	mrand "math/rand/v2"
	"strings"
	"testing"

	"github.com/getlantern/warren/group/keys"
	m "github.com/getlantern/warren/group/rostermodel"
)

var (
	walks = flag.Int("roster.walks", 2000, "random walks the conformance test replays")
	steps = flag.Int("roster.steps", 14, "actions per walk")
)

const (
	kO m.Key = iota + 1
	kA
	kB
	kM
	kN
)

var replicas = []m.Key{kO, kA, kB, kM}

func ident(k m.Key) *keys.Identity { return keys.IdentityFromSeed([32]byte{byte(k)}) }

// walk builds a random history with the model's own authoring functions:
// honest operations as the model's explorer writes them, backdated ones by
// removed or demoted authors, rogue ones, and syncs between replicas.
func walk(rng *mrand.Rand, n int) (map[m.Key]m.Store, []string) {
	s := m.NewGenesis(kO)
	for _, st := range []struct {
		a, t m.Key
		r    m.Role
	}{{kO, kA, m.Admin}, {kO, kB, m.Admin}, {kA, kM, m.Member}} {
		m.Author(s, m.Rules{}, m.Add, st.a, st.t, st.r)
	}
	w := map[m.Key]m.Store{}
	for _, r := range replicas {
		w[r] = s.Clone()
	}
	var trace []string
	targets := []m.Key{kO, kA, kB, kM, kN}
	kinds := []m.Kind{m.Add, m.Remove, m.Rekey, m.Deliver, m.SetRole}
	roles := []m.Role{m.Member, m.Mirror, m.Admin}
	for range n {
		r := replicas[rng.IntN(len(replicas))]
		kind, t, role := kinds[rng.IntN(len(kinds))], targets[rng.IntN(len(targets))], roles[rng.IntN(len(roles))]
		var o *m.Op
		switch rng.IntN(6) {
		case 0, 1:
			from := replicas[rng.IntN(len(replicas))]
			for id, op := range w[from] {
				w[r][id] = op
			}
			trace = append(trace, fmt.Sprintf("%d syncs from %d", r, from))
			continue
		case 2:
			o = m.AuthorBackdated(w[r], kind, r, t, role)
		case 3:
			o = m.AuthorRogue(w[r], kind, r, t, role)
		default:
			o = m.Author(w[r], m.Rules{}, kind, r, t, role)
		}
		if o != nil {
			trace = append(trace, fmt.Sprintf("%d %v %d as %v", r, o.Kind, o.Target, o.Role))
		}
	}
	return w, trace
}

var kindOf = map[m.Kind]Kind{m.Genesis: Genesis, m.Add: Add, m.Remove: Remove, m.Rekey: Rekey, m.Deliver: Deliver, m.SetRole: SetRole}
var roleOf = map[m.Role]Role{m.None: None, m.Member: Member, m.Mirror: Mirror, m.Admin: Admin, m.Owner: Owner}

// translation is a model history rewritten as real, signed operations with
// real keys sealed as the model's seals say.
type translation struct {
	r       *Roster
	real    map[m.ID]ID
	model   map[ID]m.ID
	secrets map[ID]keys.Secret
	epochs  map[ID]keys.EpochKey
}

func translate(t *testing.T, u m.Store) *translation {
	t.Helper()
	f, err := m.Fold(u)
	if err != nil {
		t.Fatal(err)
	}
	tr := &translation{real: map[m.ID]ID{}, model: map[ID]m.ID{}, secrets: map[ID]keys.Secret{}, epochs: map[ID]keys.EpochKey{}}
	for _, mo := range f.Order {
		o := &Op{Kind: kindOf[mo.Kind], Lamport: mo.Lamport, Role: roleOf[mo.Role]}
		if mo.Target != 0 {
			o.Target = ident(mo.Target).Public()
		}
		if tr.r != nil {
			o.Group = tr.r.group
		}
		for _, p := range mo.Parents {
			o.Parents = append(o.Parents, tr.real[p])
		}
		var g keys.Secret
		var e keys.EpochKey
		if o.Kind.makesKeys() {
			rand.Read(g[:])
			rand.Read(e[:])
			o.CommitSecret, o.CommitEpoch = keys.CommitSecret(g), keys.CommitEpoch(e)
		}
		o.Author = ident(mo.Author).Public()
		for _, sl := range mo.Seals {
			var es []entry
			for _, id := range sl.Gs {
				if id == 0 {
					es = append(es, entry{secret: true, key: g})
				} else {
					es = append(es, entry{made: tr.real[id], secret: true, key: tr.secrets[tr.real[id]]})
				}
			}
			for _, id := range sl.Epochs {
				if id == 0 {
					es = append(es, entry{key: e})
				} else {
					es = append(es, entry{made: tr.real[id], key: tr.epochs[tr.real[id]]})
				}
			}
			if err := seal(o, ident(sl.To).Public(), es); err != nil {
				t.Fatal(err)
			}
		}
		o.Sign(ident(mo.Author))
		// Round-trip through the wire format, as a member receiving it would.
		o, err = Decode(o.Encode())
		if err != nil {
			t.Fatalf("decoding a translated %v: %v", mo.Kind, err)
		}
		tr.real[mo.ID], tr.model[o.id] = o.id, mo.ID
		if o.Kind.makesKeys() {
			tr.secrets[o.id], tr.epochs[o.id] = g, e
		}
		if o.Kind == Genesis {
			if tr.r, err = New(o); err != nil {
				t.Fatal(err)
			}
		} else if _, err := tr.r.Add(o); err != nil {
			t.Fatalf("adding a translated %v: %v", mo.Kind, err)
		}
	}
	return tr
}

// compare checks the real fold of the translated ops in s agrees with the
// model's fold of s on everything the model decides.
func (tr *translation) compare(s m.Store) error {
	mf, err := m.Fold(s)
	if err != nil {
		return fmt.Errorf("model fold: %w", err)
	}
	ids := map[ID]bool{}
	for id := range s {
		ids[tr.real[id]] = true
	}
	rr := tr.r.sub(ids)
	rf, err := rr.Fold()
	if err != nil {
		return fmt.Errorf("real fold: %w", err)
	}
	for _, mo := range mf.Order {
		if mf.Counts[mo.ID] != rf.Counts[tr.real[mo.ID]] {
			return fmt.Errorf("%v by %d: model counts=%v, real counts=%v", mo.Kind, mo.Author, mf.Counts[mo.ID], !mf.Counts[mo.ID])
		}
	}
	if len(mf.Roles) != len(rf.Roles) {
		return fmt.Errorf("model has %d keys on the roster, real %d", len(mf.Roles), len(rf.Roles))
	}
	for k, role := range mf.Roles {
		if rf.Roles[ident(k).Public()] != roleOf[role] {
			return fmt.Errorf("key %d: model %v, real %v", k, role, rf.Roles[ident(k).Public()])
		}
	}
	for k, rid := range mf.Removed {
		if rf.Removed[ident(k).Public()] != tr.real[rid] {
			return fmt.Errorf("key %d removed by different operations", k)
		}
	}
	if len(mf.Removed) != len(rf.Removed) {
		return fmt.Errorf("model removed %d keys, real %d", len(mf.Removed), len(rf.Removed))
	}
	if tr.real[mf.Current] != rf.Current {
		return fmt.Errorf("current keys differ")
	}
	epochs, gs := s.Holdings()
	for _, k := range []m.Key{kO, kA, kB, kM, kN} {
		kr := rr.Keyring(ident(k))
		if err := sameSet(epochs[k], kr.Epochs, tr); err != nil {
			return fmt.Errorf("key %d's epoch keys: %w", k, err)
		}
		if err := sameSet(gs[k], kr.Secrets, tr); err != nil {
			return fmt.Errorf("key %d's group secrets: %w", k, err)
		}
	}
	return nil
}

func sameSet[V any](model map[m.ID]bool, real map[ID]V, tr *translation) error {
	if len(model) != len(real) {
		return fmt.Errorf("model holds %d, real %d", len(model), len(real))
	}
	for id := range model {
		if _, ok := real[tr.real[id]]; !ok {
			return fmt.Errorf("real lacks one the model holds")
		}
	}
	return nil
}

// TestConformance replays random histories written with the model's own
// authoring functions, translated into real signed operations and real
// sealed keys, and requires the real fold to agree with the model's on
// what counts, the roster, removals, the current keys and who holds which
// keys, for every replica's partial view and for all of it.
func TestConformance(t *testing.T) {
	defer func(f func(a, b *Op) int) { tiebreak = f }(tiebreak)
	var tr *translation
	tiebreak = func(a, b *Op) int { return cmpModel(tr.model[a.id], tr.model[b.id]) }
	rng := mrand.New(mrand.NewPCG(1, 2))
	for i := range *walks {
		w, trace := walk(rng, *steps)
		u := m.Store{}
		for _, s := range w {
			for id, o := range s {
				u[id] = o
			}
		}
		tr = translate(t, u)
		stores := append([]m.Store{u}, w[kO], w[kA], w[kB], w[kM])
		for j, s := range stores {
			if err := tr.compare(s); err != nil {
				t.Fatalf("walk %d, store %d: %v\n  trace: %s", i, j, err, strings.Join(trace, "; "))
			}
		}
	}
}

// scripted are interleavings the random walks rarely reach, each one the
// counterexample the model's explorer found for a rule. They run through
// the same translation and comparison.
var scripted = map[string]func(w map[m.Key]m.Store){
	"a remover must see the target demoted": func(w map[m.Key]m.Store) {
		m.Author(w[kO], m.Rules{}, m.SetRole, kO, kA, m.Member)
		m.AuthorRogue(w[kB], m.Remove, kB, kA, m.None)
	},
	"an add counts only if its author hadn't admitted the key": func(w map[m.Key]m.Store) {
		m.Author(w[kO], m.Rules{}, m.Remove, kO, kA, m.None)
		m.Author(w[kA], m.Rules{}, m.Add, kA, kN, m.Mirror)
		sync(w, kB, kA)
		m.AuthorRogue(w[kB], m.Add, kB, kN, m.Member)
	},
	"a promotion restores only operations that saw it": func(w map[m.Key]m.Store) {
		m.Author(w[kO], m.Rules{}, m.SetRole, kO, kA, m.Member)
		sync(w, kA, kO)
		m.AuthorBackdated(w[kA], m.Add, kA, kN, m.Member)
		m.Author(w[kO], m.Rules{}, m.SetRole, kO, kA, m.Admin)
	},
}

func sync(w map[m.Key]m.Store, to, from m.Key) {
	for id, o := range w[from] {
		w[to][id] = o
	}
}

func TestScripted(t *testing.T) {
	defer func(f func(a, b *Op) int) { tiebreak = f }(tiebreak)
	var tr *translation
	tiebreak = func(a, b *Op) int { return cmpModel(tr.model[a.id], tr.model[b.id]) }
	for name, run := range scripted {
		t.Run(name, func(t *testing.T) {
			w, _ := walk(mrand.New(mrand.NewPCG(0, 0)), 0)
			run(w)
			u := m.Store{}
			for _, s := range w {
				for id, o := range s {
					u[id] = o
				}
			}
			tr = translate(t, u)
			for j, s := range append([]m.Store{u}, w[kO], w[kA], w[kB], w[kM]) {
				if err := tr.compare(s); err != nil {
					t.Fatalf("store %d: %v", j, err)
				}
			}
		})
	}
}

func cmpModel(a, b m.ID) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

