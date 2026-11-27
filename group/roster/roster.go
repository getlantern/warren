package roster

import (
	"bytes"
	"cmp"
	"container/heap"
	"errors"
	"slices"
	"time"

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
	// views caches each operation's author's view: the fold of its causal
	// history. An ID commits to that history, and every op here has been
	// verified against its ID, so the view never changes.
	views map[ID]*view
	// anc caches descends within one top-level fold (whether the second op
	// is an ancestor of the first), and is dropped after it, so it never
	// outgrows a fold's own work; each fold walks the grant checks afresh,
	// O(ops) per admin.
	anc map[[2]ID]bool
}

// view is what an op's author saw of the op's target, the only thing the
// view checks ask: its role, and whether it had been removed.
type view struct {
	role    Role
	removed bool
	failed  bool // the history's fold had no fixpoint
}

// New starts a roster from a genesis operation.
func New(genesis *Op) (*Roster, error) {
	if genesis.Kind != Genesis || len(genesis.Parents) != 0 || genesis.Lamport != 1 {
		return nil, ErrMalformed
	}
	g, err := Decode(genesis.Encode())
	if err != nil {
		return nil, err
	}
	r := &Roster{group: g.id, ops: map[ID]*Op{}, views: map[ID]*view{}}
	r.ops[g.id] = g
	return r, nil
}

// Clone is a copy of the roster to fold with operations not yet trusted:
// adding to it leaves r unchanged. Operations and the views already
// computed are shared (neither ever changes once made), each in a map of
// the clone's own, so folding it reuses r's work but writes nothing r
// reads.
func (r *Roster) Clone() *Roster {
	c := &Roster{group: r.group, ops: make(map[ID]*Op, len(r.ops)), views: make(map[ID]*view, len(r.views))}
	for id, o := range r.ops {
		c.ops[id] = o
	}
	for id, v := range r.views {
		c.views[id] = v
	}
	return c
}

// Group returns the group's ID: its genesis's ID.
func (r *Roster) Group() ID { return r.group }

// Len returns how many operations the roster holds.
func (r *Roster) Len() int { return len(r.ops) }

// Op returns a copy of the operation with id, or nil.
func (r *Roster) Op(id ID) *Op {
	if o := r.ops[id]; o != nil {
		return o.clone()
	}
	return nil
}

// IDs returns the IDs of every operation the roster holds, parents before
// children: by Lamport clock, which strictly increases along every edge,
// then by ID.
func (r *Roster) IDs() []ID {
	ids := make([]ID, 0, len(r.ops))
	for id := range r.ops {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, func(a, b ID) int {
		if c := cmp.Compare(r.ops[a].Lamport, r.ops[b].Lamport); c != 0 {
			return c
		}
		return bytes.Compare(a[:], b[:])
	})
	return ids
}

// Has reports whether the roster holds id.
func (r *Roster) Has(id ID) bool { return r.ops[id] != nil }

// Add adds an operation (decoded, or signed locally). It keeps its own
// copy, re-decoded from the operation's encoding, so what it holds is
// exactly what peers would accept, and the caller's later changes to o
// can't reach it. It reports whether the operation was new.
func (r *Roster) Add(o *Op) (bool, error) {
	if h := r.ops[o.id]; h != nil && bytes.Equal(h.Encode(), o.Encode()) {
		return false, nil // already held, byte for byte: gossip's common case
	}
	o, err := Decode(o.Encode())
	if err != nil {
		return false, err
	}
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

// Closure returns the operations among ids the roster holds, with all
// their ancestors: one walk with one visited set, so ids sharing history,
// or repeating, cost no more than the roster's size.
func (r *Roster) Closure(ids []ID) map[ID]bool {
	seen := map[ID]bool{}
	var stack []ID
	push := func(id ID) {
		if !seen[id] && r.ops[id] != nil {
			seen[id] = true
			stack = append(stack, id)
		}
	}
	for _, id := range ids {
		push(id)
	}
	for len(stack) > 0 {
		id := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, p := range r.ops[id].Parents {
			push(p)
		}
	}
	return seen
}

// History returns id's strict causal ancestors, or nil if the roster
// doesn't hold id. It walks the whole history; authority checks ask the
// narrower descends.
func (r *Roster) History(id ID) map[ID]bool {
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
	return h
}

// descends reports whether a is a strict ancestor of o. Clocks strictly
// increase along every edge, so the walk stops below a's clock.
func (r *Roster) descends(o, a ID) bool {
	ao, oo := r.ops[a], r.ops[o]
	if ao == nil || oo == nil {
		return false
	}
	if r.anc == nil { // outside a fold: a cache for this query alone
		r.anc = map[[2]ID]bool{}
		defer func() { r.anc = nil }()
	}
	return r.desc(oo, ao)
}

// desc is descends over parents, memoizing every node's answer for the
// current fold, so one ancestor's queries cost O(ops) together however many
// are asked. It walks with an explicit stack, not recursion, so its depth
// doesn't grow with the chain.
func (r *Roster) desc(oo, ao *Op) bool {
	a := ao.id
	if v, ok := r.anc[[2]ID{oo.id, a}]; ok {
		return v
	}
	type frame struct {
		o *Op
		i int
	}
	stack := []frame{{o: oo}}
	found := func() bool {
		for _, f := range stack {
			r.anc[[2]ID{f.o.id, a}] = true // every op on the stack descends from a
		}
		return true
	}
	for len(stack) > 0 {
		top := &stack[len(stack)-1]
		if top.i == len(top.o.Parents) {
			r.anc[[2]ID{top.o.id, a}] = false // no parent leads to a
			stack = stack[:len(stack)-1]
			continue
		}
		p := top.o.Parents[top.i]
		top.i++
		if p == a {
			return found()
		}
		po := r.ops[p]
		if po.Lamport <= ao.Lamport {
			continue // clocks rise along edges, so a is not above p
		}
		if v, ok := r.anc[[2]ID{p, a}]; ok {
			if v {
				return found()
			}
			continue
		}
		stack = append(stack, frame{o: po})
	}
	return false
}

// sub is the roster of only the given operations, which must be causally
// closed, sharing r's view and ancestry caches: an operation's view and
// ancestors are the same in any roster that holds it.
func (r *Roster) sub(ids map[ID]bool) *Roster {
	s := &Roster{group: r.group, ops: make(map[ID]*Op, len(ids)), views: r.views, anc: r.anc}
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
	Grants map[keys.PublicKey][]*Op
	// As is each counting op's author's role when it counted, as far as the
	// author knew: an admin not yet aware of its grant counts as a member.
	As      map[ID]Role
	Owner   keys.PublicKey
	Current ID // the key-making operation whose keys are current
	Passes  int
	// Invites is each recorded invite's state, by its public key.
	Invites map[keys.PublicKey]*InviteState
}

// InviteState is an invite as the roster records it. The fold counts uses
// and doesn't drop: two admins approving one invite at once both admit
// their joiner, and the invite reads as overspent (Used > Uses). Expiry is
// checked by the approving admin's clock (Usable), as operations carry no
// time.
type InviteState struct {
	Op      ID // the invite operation
	Expires int64
	Uses    uint32
	// Used is the approvals that named it: counting adds and rejoins'
	// delivers by an owner or admin, and an authorized add concurrent with
	// the one that admitted its target, which doesn't count but was given.
	Used uint32
	// Dead is set once a counting remove comes after the invite in the
	// total order: invites issued before a removal are refused after it.
	Dead bool
}

// Usable reports whether the invite may admit another joiner at now.
func (s *InviteState) Usable(now time.Time) bool {
	return !s.Dead && s.Used < s.Uses && now.Unix() < s.Expires
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

// countInvite applies a counting operation, by an author counting in role
// author, to the invites: records an invite, spends one of an add's or
// deliver's, or kills those before a remove. Only an owner or admin, who
// approves invites, spends one: any member may deliver, and a member's
// deliver naming an invite would otherwise use it up with no one joining.
// live holds the invites recorded since the last counting remove, the only
// ones a remove has left to kill, and is returned updated.
func countInvite(res *Result, live []*InviteState, o *Op, author Role) []*InviteState {
	switch o.Kind {
	case Invite:
		if _, ok := res.Invites[o.Invite]; !ok { // the first record stands
			s := &InviteState{Op: o.id, Expires: o.Expires, Uses: o.Uses}
			res.Invites[o.Invite] = s
			live = append(live, s)
		}
	case Add, Deliver:
		if s := res.Invites[o.Invite]; s != nil && (author == Owner || author == Admin) {
			s.Used++
		}
	case Remove:
		for _, s := range live {
			s.Dead = true
		}
		live = live[:0]
	}
	return live
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
//
// The result's operations are copies, so changing them can't reach the
// roster.
func (r *Roster) Fold() (*Result, error) {
	res, err := r.fold()
	if err != nil {
		return nil, err
	}
	clones := make(map[ID]*Op, len(res.Order))
	for i, o := range res.Order {
		clones[o.id] = o.clone()
		res.Order[i] = clones[o.id]
	}
	for k, gs := range res.Grants {
		for i, g := range gs {
			gs[i] = clones[g.id]
		}
		res.Grants[k] = gs
	}
	return res, nil
}

func (r *Roster) fold() (*Result, error) {
	if r.anc == nil {
		r.anc = map[[2]ID]bool{}
		defer func() { r.anc = nil }()
	}
	order := r.order()
	byAuthor := map[keys.PublicKey][]*Op{}
	for _, o := range order {
		byAuthor[o.Author] = append(byAuthor[o.Author], o)
	}
	dropped := map[ID]bool{}
	var tried []map[ID]bool
	for pass := 1; ; pass++ {
		res := r.apply(order, dropped)
		res.Passes = pass
		next := map[ID]bool{}
		// These rules ask whether each of an author's ops is an ancestor of
		// one remove or demotion: a different ancestor per question, which
		// the descends memo can't reuse, so they walk that op's history
		// once instead.
		for k, rid := range res.Removed {
			ops := byAuthor[k]
			if len(ops) == 0 {
				continue // most removed keys never wrote anything
			}
			h := r.History(rid)
			for _, o := range ops {
				if o.id != rid && !h[o.id] {
					next[o.id] = true
				}
			}
		}
		for k, grants := range res.Grants {
			ops := byAuthor[k]
			if !slices.ContainsFunc(ops, func(o *Op) bool { return o.needsAdmin() }) {
				continue // nothing of k's needs the authority a demotion takes
			}
			for i, d := range grants {
				if d.Role != Member {
					continue
				}
				h := r.History(d.id)
				for _, o := range ops {
					if !o.needsAdmin() || h[o.id] {
						continue
					}
					restored := false
					for _, p := range grants[i+1:] {
						if p.Role == Admin && r.descends(p.id, d.id) && r.descends(o.id, p.id) {
							restored = true
							break
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
		v.role, v.removed = f.Roles[o.Target], f.Removed[o.Target] != ID{}
	}
	r.views[o.id] = v
	return v
}

func (r *Roster) foldOrFail() (*Result, error) {
	if len(r.ops) == 0 {
		return &Result{Roles: map[keys.PublicKey]Role{}, Removed: map[keys.PublicKey]ID{}}, nil
	}
	return r.fold()
}

func (r *Roster) apply(order []*Op, dropped map[ID]bool) *Result {
	res := &Result{
		Order: order, Counts: map[ID]bool{}, Roles: map[keys.PublicKey]Role{},
		Removed: map[keys.PublicKey]ID{}, Grants: map[keys.PublicKey][]*Op{}, As: map[ID]Role{},
		Invites: map[keys.PublicKey]*InviteState{},
	}
	ever := map[keys.PublicKey]bool{}
	var live []*InviteState // invites recorded since the last counting remove
	// attempts is, per key, every add that admitted it in its author's
	// view: the counting ones, and authorized concurrent duplicates. An op
	// descending from one has seen the key admitted. sees asks that,
	// memoized per op and key; ops come in topological order, so an
	// ancestor's attempts are settled before anyone asks.
	attempts := map[keys.PublicKey]map[ID]bool{}
	attempt := func(t keys.PublicKey, id ID) {
		if attempts[t] == nil {
			attempts[t] = map[ID]bool{}
		}
		attempts[t][id] = true
	}
	type seeKey struct {
		op ID
		t  keys.PublicKey
	}
	seesMemo := map[seeKey]bool{}
	var sees func(o *Op, t keys.PublicKey) bool
	sees = func(o *Op, t keys.PublicKey) bool {
		k := seeKey{o.id, t}
		if v, ok := seesMemo[k]; ok {
			return v
		}
		v := false
		for _, p := range o.Parents {
			if po := r.ops[p]; attempts[t][p] || (po != nil && sees(po, t)) {
				v = true
				break
			}
		}
		seesMemo[k] = v
		return v
	}
	// granted is the operation that made each admin one: its counting add
	// as admin, or its latest promotion.
	granted := map[keys.PublicKey]ID{}
	sawTarget := func(o *Op) bool {
		v := r.viewOf(o)
		return v.failed || v.role != None || v.removed
	}
	adminInView := func(o *Op) bool {
		v := r.viewOf(o)
		return v.failed || v.role == Admin
	}
	for i, o := range order {
		if dropped[o.id] {
			continue
		}
		author := res.Roles[o.Author]
		// An admin that hadn't seen its own grant writes as a member: for
		// authority, and for the role recorded in As, whatever the kind.
		if author == Admin && !r.descends(o.id, granted[o.Author]) {
			author = Member
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
			case cur != None && cur != Owner && !sees(o, o.Target):
				// Concurrent with every add that admitted the key, at no
				// higher a role: it doesn't count, but its approval was
				// given, so it still spends its invite (see InviteState),
				// and an op descending from it has seen the key admitted.
				// Descent is asked (sees), not the op's view, which would
				// refold its history.
				attempt(o.Target, o.id)
				if s := res.Invites[o.Invite]; s != nil {
					s.Used++
				}
			}
			if ok {
				res.Roles[o.Target] = o.Role
				ever[o.Target] = true
				attempt(o.Target, o.id)
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
		if ok {
			live = countInvite(res, live, o, author)
			res.As[o.id] = author
			if o.Kind == Genesis {
				res.As[o.id] = Owner
			}
		}
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
