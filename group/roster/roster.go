package roster

import (
	"bytes"
	"cmp"
	"container/heap"
	"errors"
	"slices"

	"github.com/getlantern/warren/group/keys"
)

var (
	// ErrWrongGroup means an operation names another group.
	ErrWrongGroup = errors.New("roster: operation of another group")
	// ErrMissingParent means an operation arrived before a parent: a roster
	// is causally closed, so the caller adds the parent first.
	ErrMissingParent = errors.New("roster: missing parent")
	// ErrLamport means an operation's Lamport clock isn't one more than its
	// parents' greatest.
	ErrLamport = errors.New("roster: Lamport clock doesn't follow its parents")
	// ErrNoFixpoint means the view rules never settle on these operations.
	ErrNoFixpoint = errors.New("roster: view rule has no fixpoint")
)

// Roster is a causally closed set of verified operations of one group.
// Members exchange operations by gossip and fold them; every member holding
// the same operations folds the same roster. A Roster caches as it folds,
// so it isn't safe for concurrent use, even of Fold.
type Roster struct {
	group ID
	ops   map[ID]*Op
	hist  map[ID]map[ID]bool
	// views caches each operation's author's view: the fold of its causal
	// history. An ID commits to that history, and every op here has been
	// verified against its ID, so the view never changes.
	views map[ID]*view
}

type view struct {
	roles   map[keys.PublicKey]Role
	removed map[keys.PublicKey]ID
	failed  bool // the history's fold had no fixpoint
}

// New starts a roster from a genesis operation.
func New(genesis *Op) (*Roster, error) {
	if genesis.Kind != Genesis || len(genesis.Parents) != 0 || genesis.Lamport != 1 {
		return nil, ErrMalformed
	}
	r := &Roster{group: genesis.id, ops: map[ID]*Op{}, hist: map[ID]map[ID]bool{}, views: map[ID]*view{}}
	r.ops[genesis.id] = genesis
	return r, nil
}

// Group returns the group's ID: its genesis's ID.
func (r *Roster) Group() ID { return r.group }

// Len returns how many operations the roster holds.
func (r *Roster) Len() int { return len(r.ops) }

// Op returns the operation with id, or nil.
func (r *Roster) Op(id ID) *Op { return r.ops[id] }

// Has reports whether the roster holds id.
func (r *Roster) Has(id ID) bool { return r.ops[id] != nil }

// Add adds a verified operation (from Decode, or signed locally). It
// reports whether the operation was new.
func (r *Roster) Add(o *Op) (bool, error) {
	if r.ops[o.id] != nil {
		return false, nil
	}
	if o.Kind == Genesis || o.Group != r.group {
		return false, ErrWrongGroup
	}
	if len(o.Parents) == 0 {
		return false, ErrMalformed
	}
	var clock uint64
	for _, p := range o.Parents {
		if r.ops[p] == nil {
			return false, ErrMissingParent
		}
		clock = max(clock, r.ops[p].Lamport)
	}
	// Exactly one more than the parents' greatest, as every honest writer
	// sets it: an author can't choose its place in the total order by its
	// clock, nor push the clock toward overflow.
	if o.Lamport != clock+1 {
		return false, ErrLamport
	}
	r.ops[o.id] = o
	return true, nil
}

// Heads returns the operations no other operation names as a parent, in
// ID order: the parents of the next operation written here.
func (r *Roster) Heads() []ID {
	named := map[ID]bool{}
	for _, o := range r.ops {
		for _, p := range o.Parents {
			named[p] = true
		}
	}
	var hs []ID
	for id := range r.ops {
		if !named[id] {
			hs = append(hs, id)
		}
	}
	slices.SortFunc(hs, func(a, b ID) int { return bytes.Compare(a[:], b[:]) })
	return hs
}

// History returns id's strict causal ancestors, or nil if the roster
// doesn't hold id.
func (r *Roster) History(id ID) map[ID]bool {
	if h := r.hist[id]; h != nil {
		return h
	}
	if r.ops[id] == nil {
		return nil
	}
	h := map[ID]bool{}
	stack := slices.Clone(r.ops[id].Parents)
	for len(stack) > 0 {
		p := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if h[p] {
			continue
		}
		h[p] = true
		stack = append(stack, r.ops[p].Parents...)
	}
	r.hist[id] = h
	return h
}

// sub is the roster of only the given operations, which must be causally
// closed, sharing r's caches: an operation's history and view are the same
// in any roster that holds it.
func (r *Roster) sub(ids map[ID]bool) *Roster {
	s := &Roster{group: r.group, ops: make(map[ID]*Op, len(ids)), hist: r.hist, views: r.views}
	for id := range ids {
		s.ops[id] = r.ops[id]
	}
	return s
}

// Result is a folded roster.
type Result struct {
	Order   []*Op // the total order
	Counts  map[ID]bool
	Roles   map[keys.PublicKey]Role
	Removed map[keys.PublicKey]ID // each removed key's counting remove
	// Grants lists, per key, the counting role operations that promoted or
	// demoted it, in total order.
	Grants  map[keys.PublicKey][]*Op
	Owner   keys.PublicKey
	Current ID // the key-making operation whose keys are current
	Passes  int
}

// tiebreak orders operations the total order can't tell apart otherwise.
// Tests replace it to match the model's.
var tiebreak = func(a, b *Op) int { return bytes.Compare(a.id[:], b.id[:]) }

type ready []*Op

func (h ready) Len() int { return len(h) }
func (h ready) Less(i, j int) bool {
	if c := cmp.Compare(h[i].Lamport, h[j].Lamport); c != 0 {
		return c < 0
	}
	return tiebreak(h[i], h[j]) < 0
}
func (h ready) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *ready) Push(x any)   { *h = append(*h, x.(*Op)) }
func (h *ready) Pop() any {
	old := *h
	o := old[len(old)-1]
	*h = old[:len(old)-1]
	return o
}

// order is the total order: a topological order of the causal graph that,
// among operations whose parents are all placed, takes the lowest Lamport
// clock and then the lowest ID first.
func (r *Roster) order() []*Op {
	waiting := map[ID]int{}
	children := map[ID][]*Op{}
	h := &ready{}
	for _, o := range r.ops {
		waiting[o.id] = len(o.Parents)
		for _, p := range o.Parents {
			children[p] = append(children[p], o)
		}
		if len(o.Parents) == 0 {
			heap.Push(h, o)
		}
	}
	order := make([]*Op, 0, len(r.ops))
	for h.Len() > 0 {
		o := heap.Pop(h).(*Op)
		order = append(order, o)
		for _, c := range children[o.id] {
			waiting[c.id]--
			if waiting[c.id] == 0 {
				heap.Push(h, c)
			}
		}
	}
	return order
}

// Fold folds the roster: operations apply in the total order, each checked
// against the roster built so far; a removed author's operations count only
// if its counting remove has them in its history; a demoted admin's
// operations that need admin authority count only if the demotion has them
// in its history, unless a later promotion they've seen restored it. Those
// view rules can drop operations earlier passes applied, so the fold
// repeats until the dropped set is stable, or cycles.
func (r *Roster) Fold() (*Result, error) {
	order := r.order()
	dropped := map[ID]bool{}
	var tried []map[ID]bool
	for pass := 1; ; pass++ {
		res := r.apply(order, dropped)
		res.Passes = pass
		next := map[ID]bool{}
		for k, rid := range res.Removed {
			for _, o := range order {
				if o.Author == k && o.id != rid && !r.History(rid)[o.id] {
					next[o.id] = true
				}
			}
		}
		for k, grants := range res.Grants {
			for i, d := range grants {
				if d.Role != Member {
					continue
				}
				for _, o := range order {
					if o.Author != k || !o.Kind.needsAdmin() || r.History(d.id)[o.id] {
						continue
					}
					restored := false
					for _, p := range grants[i+1:] {
						if p.Role == Admin && r.History(p.id)[d.id] && r.History(o.id)[p.id] {
							restored = true
						}
					}
					if !restored {
						next[o.id] = true
					}
				}
			}
		}
		if equalSets(next, dropped) {
			return res, nil
		}
		tried = append(tried, dropped)
		if slices.ContainsFunc(tried, func(t map[ID]bool) bool { return equalSets(t, next) }) {
			return nil, ErrNoFixpoint
		}
		dropped = next
	}
}

// viewOf is the roster o's author saw when it wrote o.
func (r *Roster) viewOf(o *Op) *view {
	if v := r.views[o.id]; v != nil {
		return v
	}
	v := &view{}
	if f, err := r.sub(r.History(o.id)).foldOrFail(); err != nil {
		v.failed = true
	} else {
		v.roles, v.removed = f.Roles, f.Removed
	}
	r.views[o.id] = v
	return v
}

func (r *Roster) foldOrFail() (*Result, error) {
	if len(r.ops) == 0 {
		return &Result{Roles: map[keys.PublicKey]Role{}, Removed: map[keys.PublicKey]ID{}}, nil
	}
	return r.Fold()
}

func (r *Roster) apply(order []*Op, dropped map[ID]bool) *Result {
	res := &Result{
		Order: order, Counts: map[ID]bool{}, Roles: map[keys.PublicKey]Role{},
		Removed: map[keys.PublicKey]ID{}, Grants: map[keys.PublicKey][]*Op{},
	}
	ever := map[keys.PublicKey]bool{}
	// granted is the operation that made each admin one: its counting add
	// as admin, or its latest promotion.
	granted := map[keys.PublicKey]ID{}
	sawTarget := func(o *Op) bool {
		v := r.viewOf(o)
		return v.failed || v.roles[o.Target] != None || v.removed[o.Target] != ID{}
	}
	adminInView := func(o *Op) bool {
		v := r.viewOf(o)
		return v.failed || v.roles[o.Target] == Admin
	}
	for i, o := range order {
		if dropped[o.id] {
			continue
		}
		author := res.Roles[o.Author]
		if author == Admin && o.Kind.needsAdmin() && !r.History(o.id)[granted[o.Author]] {
			author = Member // not yet an admin as far as its author knew
		}
		ok := false
		switch o.Kind {
		case Genesis:
			if i == 0 {
				res.Owner, res.Roles[o.Author], res.Current = o.Author, Owner, o.id
				ever[o.Author] = true
				ok = true
			}
		case Add:
			can := author == Owner || (author == Admin && o.Role != Admin)
			if !can || (o.Role != Member && o.Role != Mirror && o.Role != Admin) {
				break
			}
			cur := res.Roles[o.Target]
			switch {
			case cur == None && !ever[o.Target] && !sawTarget(o):
				ok = true
			case cur != None && cur != Owner && rank(o.Role) > rank(cur) && !sawTarget(o):
				// Concurrent with the add that admitted the key, not a role
				// change; both sealed their role's keys, so the higher wins.
				ok = true
			}
			if ok {
				res.Roles[o.Target] = o.Role
				ever[o.Target] = true
				if o.Role == Admin {
					granted[o.Target] = o.id
				}
			}
		case Remove:
			t := res.Roles[o.Target]
			can := author == Owner || (author == Admin && t != Admin && !adminInView(o))
			if can && t != None && t != Owner {
				delete(res.Roles, o.Target)
				res.Removed[o.Target], res.Current = o.id, o.id
				ok = true
			}
		case Rekey:
			if author == Owner || author == Admin {
				res.Current = o.id
				ok = true
			}
		case Deliver:
			ok = author != None && res.Roles[o.Target] != None
		case SetRole:
			t := res.Roles[o.Target]
			if author == Owner && ((t == Member && o.Role == Admin) || (t == Admin && o.Role == Member)) {
				res.Roles[o.Target] = o.Role
				res.Grants[o.Target] = append(res.Grants[o.Target], o)
				if o.Role == Admin {
					granted[o.Target] = o.id
				}
				ok = true
			}
		case Invite:
			ok = author == Owner || author == Admin
		}
		res.Counts[o.id] = ok
	}
	return res
}

func equalSets(a, b map[ID]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}
