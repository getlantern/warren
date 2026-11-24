// Package rostermodel is an executable model of the roster rules in
// docs/groups-design.md, used to model-check them before phase 1 builds the
// real roster. Keys are abstract: an epoch key or group secret is named by
// the operation that made it, and sealing is a set of recipients. Nothing
// here is cryptographic, and nothing outside tests should import it.
package rostermodel

import (
	"cmp"
	"container/heap"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"slices"
)

// Key is a member key.
type Key uint8

// Role is a roster role. The owner is the genesis author.
type Role uint8

const (
	None Role = iota
	Member
	Mirror
	Admin
	Owner
)

// rank orders roles by the keys they hold: a mirror holds the fewest.
func rank(r Role) int { return [...]int{0, 2, 1, 3, 4}[r] }

func (r Role) String() string {
	return [...]string{"none", "member", "mirror", "admin", "owner"}[r]
}

// Kind is an operation kind.
type Kind uint8

const (
	Genesis Kind = iota
	Add
	Remove
	Rekey
	Deliver
)

func (k Kind) String() string {
	return [...]string{"genesis", "add", "remove", "rekey", "deliver"}[k]
}

// ID names an operation; for key-making operations it also names the
// epoch key and group secret the operation made.
type ID uint64

// Seal is what one operation sealed to one key: epoch keys and group
// secrets, each named by the operation that made it.
type Seal struct {
	To     Key
	Epochs []ID
	Gs     []ID
}

// Op is a signed roster operation.
type Op struct {
	ID      ID
	Kind    Kind
	Author  Key
	Target  Key  // add, remove, deliver
	Role    Role // add
	Parents []ID
	Lamport uint64
	Seals   []Seal
	// Backdated marks an operation written by a removed author after it
	// learned of its removal; Rogue, one written by a compromised device
	// without its role's authority for it. The fold reads neither; properties do.
	Backdated, Rogue bool
}

func (o *Op) makesKeys() bool {
	return o.Kind == Genesis || o.Kind == Remove || o.Kind == Rekey
}

// seal fills in ID from the operation's content, as a hash would.
func (o *Op) seal() {
	h := sha256.New()
	var b [8]byte
	w := func(v uint64) { binary.BigEndian.PutUint64(b[:], v); h.Write(b[:]) }
	w(uint64(o.Kind))
	w(uint64(o.Author))
	w(uint64(o.Target))
	w(uint64(o.Role))
	w(o.Lamport)
	flags := uint64(0)
	if o.Backdated {
		flags |= 1
	}
	if o.Rogue {
		flags |= 2
	}
	w(flags)
	list := func(ids []ID) {
		w(uint64(len(ids)))
		for _, id := range ids {
			w(uint64(id))
		}
	}
	list(o.Parents)
	w(uint64(len(o.Seals)))
	for _, s := range o.Seals {
		w(uint64(s.To))
		list(s.Epochs)
		list(s.Gs)
	}
	o.ID = ID(binary.BigEndian.Uint64(h.Sum(nil)))
}

// Store is a causally closed set of operations.
type Store map[ID]*Op

// Clone copies the set (operations are shared and immutable).
func (s Store) Clone() Store {
	c := make(Store, len(s))
	for id, o := range s {
		c[id] = o
	}
	return c
}

// Heads returns the operations no other operation names as a parent.
func (s Store) Heads() []ID {
	named := map[ID]bool{}
	for _, o := range s {
		for _, p := range o.Parents {
			named[p] = true
		}
	}
	var hs []ID
	for id := range s {
		if !named[id] {
			hs = append(hs, id)
		}
	}
	slices.Sort(hs)
	return hs
}

// History returns id's strict causal ancestors.
func (s Store) History(id ID) map[ID]bool {
	seen := map[ID]bool{}
	stack := slices.Clone(s[id].Parents)
	for len(stack) > 0 {
		p := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[p] {
			continue
		}
		seen[p] = true
		if o := s[p]; o != nil {
			stack = append(stack, o.Parents...)
		}
	}
	return seen
}

// Holdings returns, per key, every epoch key and group secret sealed to it
// by any operation, counting or not: a seal hands over its keys whether or
// not the fold accepts the operation that carried it.
func (s Store) Holdings() (epochs, gs map[Key]map[ID]bool) {
	epochs, gs = map[Key]map[ID]bool{}, map[Key]map[ID]bool{}
	for _, o := range s {
		for _, sl := range o.Seals {
			if epochs[sl.To] == nil {
				epochs[sl.To], gs[sl.To] = map[ID]bool{}, map[ID]bool{}
			}
			for _, e := range resolve(o, sl.Epochs) {
				epochs[sl.To][e] = true
			}
			for _, g := range resolve(o, sl.Gs) {
				gs[sl.To][g] = true
			}
		}
	}
	return epochs, gs
}

// Result is a folded roster.
type Result struct {
	Order   []*Op
	Counts  map[ID]bool
	Roles   map[Key]Role
	Removed map[Key]ID // the counting remove of each removed key
	Owner   Key
	Current ID // the key-making operation whose keys are current
	Passes  int
}

// mutation, set only by tests, breaks one rule so the tests can show the
// checker notices.
var mutation string

// ErrNoFixpoint means the view rule never settled: whether an operation
// counts kept flipping between passes.
var ErrNoFixpoint = errors.New("rostermodel: view rule has no fixpoint")

// Fold folds the store: a total order (causal, then Lamport clock, then
// hash), each operation checked when applied, and a removed author's
// operations dropped unless the counting remove has them in its history.
// The view rule can drop operations that earlier passes applied, so the
// fold repeats until the dropped set is stable.
func Fold(s Store) (*Result, error) {
	order := totalOrder(s)
	hist := map[ID]map[ID]bool{}
	dropped := map[ID]bool{}
	for pass := 1; pass <= 8; pass++ {
		r := apply(order, dropped)
		r.Passes = pass
		next := map[ID]bool{}
		for k, rid := range r.Removed {
			if mutation == "no view rule" {
				break
			}
			if hist[rid] == nil {
				hist[rid] = s.History(rid)
			}
			for _, o := range order {
				if o.Author == k && o.ID != rid && !hist[rid][o.ID] {
					next[o.ID] = true
				}
			}
		}
		if equalSets(next, dropped) {
			return r, nil
		}
		dropped = next
	}
	return nil, ErrNoFixpoint
}

func apply(order []*Op, dropped map[ID]bool) *Result {
	r := &Result{Order: order, Counts: map[ID]bool{}, Roles: map[Key]Role{}, Removed: map[Key]ID{}}
	ever := map[Key]bool{}
	byID := Store{}
	for _, o := range order {
		byID[o.ID] = o
	}
	// sawTarget reports whether an add's author already had its target on
	// the roster: the fold of the add's own causal history.
	sawTarget := func(o *Op) bool {
		if mutation == "role changes count" {
			return false
		}
		view := Store{}
		for id := range byID.History(o.ID) {
			view[id] = byID[id]
		}
		f, err := Fold(view)
		return err != nil || f.Roles[o.Target] != None
	}
	for i, o := range order {
		if dropped[o.ID] {
			continue
		}
		author := r.Roles[o.Author]
		ok := false
		switch o.Kind {
		case Genesis:
			if i == 0 && len(o.Parents) == 0 {
				r.Owner, r.Roles[o.Author], r.Current = o.Author, Owner, o.ID
				ever[o.Author] = true
				ok = true
			}
		case Add:
			can := author == Owner || (author == Admin && (o.Role != Admin || mutation == "admins add admins")) ||
				((author == Member || author == Mirror) && mutation == "members add")
			if !can || (o.Role != Member && o.Role != Mirror && o.Role != Admin) {
				break
			}
			cur := r.Roles[o.Target]
			switch {
			case cur == None && !ever[o.Target]:
				ok = true
			case cur != None && cur != Owner && rank(o.Role) > rank(cur) && !sawTarget(o):
				// The author didn't have the key on its own roster, so this
				// add is concurrent with the one that admitted it, not a
				// role change. Both have sealed their role's keys, so the
				// key takes the higher role (admin over member over mirror).
				ok = true
			}
			if ok {
				r.Roles[o.Target] = o.Role
				ever[o.Target] = true
			}
		case Remove:
			t := r.Roles[o.Target]
			can := author == Owner || (author == Admin && (t != Admin || mutation == "admins remove admins")) ||
				((author == Member || author == Mirror) && mutation == "members remove")
			if can && t != None && (t != Owner || mutation == "owner removable") {
				delete(r.Roles, o.Target)
				r.Removed[o.Target], r.Current = o.ID, o.ID
				ok = true
			}
		case Rekey:
			if author == Owner || author == Admin || ((author == Member || author == Mirror) && mutation == "members rekey") {
				r.Current = o.ID
				ok = true
			}
		case Deliver:
			ok = author != None && r.Roles[o.Target] != None
		}
		r.Counts[o.ID] = ok
	}
	return r
}

type readyHeap []*Op

func (h readyHeap) Len() int { return len(h) }
func (h readyHeap) Less(i, j int) bool {
	if c := cmp.Compare(h[i].Lamport, h[j].Lamport); c != 0 {
		return c < 0
	}
	return h[i].ID < h[j].ID
}
func (h readyHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *readyHeap) Push(x any)   { *h = append(*h, x.(*Op)) }
func (h *readyHeap) Pop() any {
	old := *h
	o := old[len(old)-1]
	*h = old[:len(old)-1]
	return o
}

// totalOrder is a topological order that, among operations whose parents
// are all placed, takes the lowest (Lamport clock, hash) first. Sorting by
// Lamport clock alone would break causality whenever an author writes a
// clock lower than a parent's.
func totalOrder(s Store) []*Op {
	waiting := map[ID]int{}
	children := map[ID][]*Op{}
	h := &readyHeap{}
	for _, o := range s {
		n := 0
		for _, p := range o.Parents {
			if s[p] != nil {
				n++
				children[p] = append(children[p], o)
			}
		}
		waiting[o.ID] = n
		if n == 0 {
			heap.Push(h, o)
		}
	}
	order := make([]*Op, 0, len(s))
	for h.Len() > 0 {
		o := heap.Pop(h).(*Op)
		order = append(order, o)
		for _, c := range children[o.ID] {
			waiting[c.ID]--
			if waiting[c.ID] == 0 {
				heap.Push(h, c)
			}
		}
	}
	return order
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
