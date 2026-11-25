package rostermodel

import "slices"

// self in a seal names the sealing operation's own new key, since an
// operation's ID can't appear in its own content.
const self ID = 0

// Rules selects readings of the design where its text admits more than one,
// so the checker can compare them.
type Rules struct {
	// DeliverAfterAnyRemove makes a sender withhold from a recipient every
	// key made by, or causally after, any remove of the recipient in the
	// sender's store, counting or not: the design's first wording, which
	// starves a member whose remove didn't count. Otherwise a sender
	// withholds nothing beyond delivering only to keys on its own roster,
	// which a counting remove already takes the recipient off.
	DeliverAfterAnyRemove bool
}

func resolve(o *Op, ids []ID) []ID {
	out := make([]ID, len(ids))
	for i, id := range ids {
		if id == self {
			id = o.ID
		}
		out[i] = id
	}
	return out
}

// held returns what key k holds in s, with self resolved.
func held(s Store, k Key) (epochs, gs map[ID]bool) {
	epochs, gs = map[ID]bool{}, map[ID]bool{}
	for _, o := range s {
		for _, sl := range o.Seals {
			if sl.To != k {
				continue
			}
			for _, e := range resolve(o, sl.Epochs) {
				epochs[e] = true
			}
			for _, g := range resolve(o, sl.Gs) {
				gs[g] = true
			}
		}
	}
	return epochs, gs
}

func newOp(s Store, kind Kind, author, target Key, role Role, parents []ID, lamport uint64) *Op {
	if lamport == 0 {
		for _, p := range parents {
			lamport = max(lamport, s[p].Lamport)
		}
		lamport++
	}
	return &Op{Kind: kind, Author: author, Target: target, Role: role, Parents: parents, Lamport: lamport}
}

func finish(s Store, o *Op) *Op {
	o.seal()
	s[o.ID] = o
	return o
}

// NewGenesis starts a group owned by founder.
func NewGenesis(founder Key) Store {
	s := Store{}
	o := &Op{Kind: Genesis, Author: founder, Lamport: 1,
		Seals: []Seal{{To: founder, Epochs: []ID{self}, Gs: []ID{self}}}}
	finish(s, o)
	return s
}

// Author writes one honest operation by author into s, as the doc says to
// seal it, and returns it, or nil if the author's own fold doesn't allow it
// or there is nothing to deliver.
func Author(s Store, rules Rules, kind Kind, author, target Key, role Role) *Op {
	f, err := Fold(s)
	if err != nil {
		return nil
	}
	a := f.Roles[author]
	o := newOp(s, kind, author, target, role, s.Heads(), 0)
	epochs, gs := held(s, author)
	switch kind {
	case Add:
		can := (a == Owner || (a == Admin && role != Admin)) && (role == Member || role == Mirror || role == Admin)
		// The add carries the current group secret, so an author that
		// hasn't been given it yet waits.
		if !can || f.Roles[target] != None || f.Removed[target] != 0 || !gs[f.Current] {
			return nil
		}
		sl := Seal{To: target, Gs: []ID{f.Current}}
		if role != Mirror {
			sl.Epochs = sortedIDs(epochs)
		}
		o.Seals = []Seal{sl}
	case Remove, Rekey:
		if kind == Remove {
			t := f.Roles[target]
			can := a == Owner || (a == Admin && t != Admin)
			if !can || t == None || t == Owner {
				return nil
			}
		} else if a != Owner && a != Admin {
			return nil
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
	case SetRole:
		t := f.Roles[target]
		valid := (t == Member && role == Admin) || (t == Admin && role == Member)
		if a != Owner || !valid {
			return nil
		}
	case Deliver:
		t := f.Roles[target]
		if a == None || (t == None && mutation != "deliver off the roster") {
			return nil
		}
		tEpochs, tGs := held(s, target)
		withheld := withheldFrom(s, rules, target)
		sl := Seal{To: target}
		if gs[f.Current] && !tGs[f.Current] && !withheld[f.Current] {
			sl.Gs = []ID{f.Current}
		}
		if t != Mirror {
			for _, e := range sortedIDs(epochs) {
				if !tEpochs[e] && !withheld[e] {
					sl.Epochs = append(sl.Epochs, e)
				}
			}
		}
		if len(sl.Gs) == 0 && len(sl.Epochs) == 0 {
			return nil
		}
		o.Seals = []Seal{sl}
	default:
		return nil
	}
	return finish(s, o)
}

// withheldFrom returns the key-making operations a sender must not deliver
// to target: those made by, or causally after, a remove of target.
func withheldFrom(s Store, rules Rules, target Key) map[ID]bool {
	if !rules.DeliverAfterAnyRemove {
		return nil
	}
	var removes []ID
	for _, o := range s {
		if o.Kind == Remove && o.Target == target {
			removes = append(removes, o.ID)
		}
	}
	out := map[ID]bool{}
	for _, o := range s {
		if !o.makesKeys() {
			continue
		}
		h := s.History(o.ID)
		for _, r := range removes {
			if o.ID == r || h[r] {
				out[o.ID] = true
			}
		}
	}
	return out
}

// AuthorBackdated writes an operation by a removed or demoted author with
// parents from before it saw that, so it looks concurrent with it, and a
// low Lamport clock, so it sorts early. It seals whatever the author holds.
// It returns nil unless s holds a remove or demotion of author.
func AuthorBackdated(s Store, kind Kind, author, target Key, role Role) *Op {
	lost := func(o *Op) bool {
		return o.Target == author && (o.Kind == Remove || (o.Kind == SetRole && o.Role == Member))
	}
	pre := Store{}
	for id, o := range s {
		before := lost(o)
		for p := range s.History(id) {
			if lost(s[p]) {
				before = true
			}
		}
		if !before {
			pre[id] = o
		}
	}
	if len(pre) == len(s) {
		return nil
	}
	o := newOp(s, kind, author, target, role, pre.Heads(), 1)
	o.Backdated = true
	epochs, gs := held(pre, author)
	switch kind {
	case Add, Deliver:
		o.Seals = []Seal{{To: target, Epochs: sortedIDs(epochs), Gs: sortedIDs(gs)}}
	case Remove, Rekey:
		f, err := Fold(pre)
		if err != nil {
			return nil
		}
		for _, k := range sortedKeys(f.Roles) {
			if k != target {
				o.Seals = append(o.Seals, Seal{To: k, Epochs: []ID{self}, Gs: []ID{self}})
			}
		}
	default:
		return nil
	}
	return finish(s, o)
}

func sortedIDs(m map[ID]bool) []ID {
	out := make([]ID, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}

func sortedKeys(m map[Key]Role) []Key {
	out := make([]Key, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
