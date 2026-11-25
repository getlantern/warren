package roster

import (
	"bytes"
	"crypto/rand"
	"errors"
	"math"
	"slices"

	"github.com/getlantern/warren/group/keys"
)

// ErrNotAllowed means the author's own view of the roster doesn't allow the
// operation, or there is nothing for it to do.
var ErrNotAllowed = errors.New("roster: operation not allowed")

// Found starts a group founded by founder, its owner.
func Found(founder *keys.Identity, name string, shards uint32) (*Roster, error) {
	if len(name) > MaxName || shards == 0 || shards > MaxShards {
		return nil, ErrNotAllowed
	}
	o := &Op{Kind: Genesis, Lamport: 1, Name: name, Shards: shards}
	o.Author = founder.Public()
	if err := freshKeys(o, map[keys.PublicKey]Role{o.Author: Owner}, keys.PublicKey{}); err != nil {
		return nil, err
	}
	o.Sign(founder)
	return New(o)
}

// Writer writes honest operations into a roster as one member, sealing
// what the design says each operation seals, from the member's own view.
type Writer struct {
	R  *Roster
	Me *keys.Identity
}

func (w *Writer) base(kind Kind) *Op {
	o := &Op{Group: w.R.group, Kind: kind, Author: w.Me.Public(), Parents: w.R.Heads()}
	for _, p := range o.Parents {
		o.Lamport = max(o.Lamport, w.R.ops[p].Lamport)
	}
	o.Lamport++
	return o
}

func (w *Writer) finish(o *Op) (*Op, error) {
	o.Sign(w.Me)
	if _, err := w.R.Add(o); err != nil {
		return nil, err
	}
	return o, nil
}

func (w *Writer) fold() (*Result, *Keyring, error) {
	f, err := w.R.Fold()
	if err != nil {
		return nil, nil, err
	}
	return f, w.R.Keyring(w.Me), nil
}

// freshKeys makes the operation's new group secret and epoch key, commits
// to them, and seals them to every key in roles except except: the secret
// to all, the epoch key to all but mirrors.
func freshKeys(o *Op, roles map[keys.PublicKey]Role, except keys.PublicKey) error {
	var g keys.Secret
	var e keys.EpochKey
	if _, err := rand.Read(g[:]); err != nil {
		return err
	}
	if _, err := rand.Read(e[:]); err != nil {
		return err
	}
	o.CommitSecret, o.CommitEpoch = keys.CommitSecret(g), keys.CommitEpoch(e)
	for k, role := range roles {
		if k == except {
			continue
		}
		es := []entry{{secret: true, key: g}}
		if role != Mirror {
			es = append(es, entry{key: e})
		}
		if err := seal(o, k, es); err != nil {
			return err
		}
	}
	return nil
}

func seal(o *Op, to keys.PublicKey, es []entry) error {
	box, err := keys.Seal(to, sealContext(o), encodeEntries(es))
	if err != nil {
		return err
	}
	s := Seal{To: to, Box: box}
	for _, e := range es {
		s.Holds = append(s.Holds, KeyRef{Made: e.made, Secret: e.secret})
	}
	o.Seals = append(o.Seals, s)
	return nil
}

func sortedIDs[V any](m map[ID]V) []ID {
	ids := make([]ID, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, func(a, b ID) int { return bytes.Compare(a[:], b[:]) })
	return ids
}

// Add admits target in role, sealing it the current group secret and, for
// a member or admin, every epoch key the author holds. invite names the
// invite the add answers, if any.
func (w *Writer) Add(target keys.PublicKey, name string, role Role, invite keys.PublicKey) (*Op, error) {
	f, k, err := w.fold()
	if err != nil {
		return nil, err
	}
	a := f.Roles[w.Me.Public()]
	can := a == Owner || (a == Admin && role != Admin)
	_, haveG := k.Secrets[f.Current]
	if !can || (role != Member && role != Mirror && role != Admin) || target.Valid() != nil || len(name) > MaxName ||
		f.Roles[target] != None || f.Removed[target] != (ID{}) || !haveG {
		return nil, ErrNotAllowed
	}
	o := w.base(Add)
	o.Target, o.Role, o.Name, o.Invite = target, role, name, invite
	es := []entry{{made: f.Current, secret: true, key: k.Secrets[f.Current]}}
	if role != Mirror {
		for _, id := range sortedIDs(k.Epochs) {
			es = append(es, entry{made: id, key: k.Epochs[id]})
		}
	}
	if err := seal(o, target, es); err != nil {
		return nil, err
	}
	return w.finish(o)
}

// Remove removes target and rekeys, sealing the new keys to everyone else
// on the author's roster. logSeq and logHead are the head of target's log
// the author has seen.
func (w *Writer) Remove(target keys.PublicKey, logSeq uint64, logHead [32]byte) (*Op, error) {
	f, _, err := w.fold()
	if err != nil {
		return nil, err
	}
	a, t := f.Roles[w.Me.Public()], f.Roles[target]
	can := a == Owner || (a == Admin && t != Admin)
	if !can || t == None || t == Owner || logSeq > math.MaxInt64 {
		return nil, ErrNotAllowed
	}
	o := w.base(Remove)
	o.Target, o.LogSeq, o.LogHead = target, logSeq, logHead
	if err := freshKeys(o, f.Roles, target); err != nil {
		return nil, err
	}
	return w.finish(o)
}

// Rekey replaces the group secret and epoch key, sealing them to everyone
// on the author's roster: the corrective rekey, among others.
func (w *Writer) Rekey() (*Op, error) {
	f, _, err := w.fold()
	if err != nil {
		return nil, err
	}
	if a := f.Roles[w.Me.Public()]; a != Owner && a != Admin {
		return nil, ErrNotAllowed
	}
	o := w.base(Rekey)
	if err := freshKeys(o, f.Roles, keys.PublicKey{}); err != nil {
		return nil, err
	}
	return w.finish(o)
}

// Deliver seals target the current group secret and, unless it is a
// mirror, every epoch key the author holds that target lacks. invite names
// the invite a rejoin answers, if any.
func (w *Writer) Deliver(target keys.PublicKey, invite keys.PublicKey) (*Op, error) {
	f, k, err := w.fold()
	if err != nil {
		return nil, err
	}
	t := f.Roles[target]
	if f.Roles[w.Me.Public()] == None || t == None || target == w.Me.Public() {
		return nil, ErrNotAllowed
	}
	has := w.holdings(f, target)
	var es []entry
	if g, ok := k.Secrets[f.Current]; ok && !has[f.Current].secret {
		es = append(es, entry{made: f.Current, secret: true, key: g})
	}
	if t != Mirror {
		for _, id := range sortedIDs(k.Epochs) {
			if !has[id].epoch {
				es = append(es, entry{made: id, key: k.Epochs[id]})
			}
		}
	}
	if len(es) == 0 {
		return nil, ErrNotAllowed
	}
	o := w.base(Deliver)
	o.Target, o.Invite = target, invite
	if err := seal(o, target, es); err != nil {
		return nil, err
	}
	return w.finish(o)
}

type held struct{ secret, epoch bool }

// holdings is what target holds as far as trusted seals say, by the
// operation that made each key. A seal's key list isn't checked by anyone
// but its recipient, so a member could list keys it never sealed and stop
// others delivering them; only lists in counting operations by the owner
// or an admin (trusted with membership anyway), or by this writer, count.
func (w *Writer) holdings(f *Result, target keys.PublicKey) map[ID]held {
	h := map[ID]held{}
	for _, o := range w.R.ops {
		trusted := o.Author == w.Me.Public() ||
			(f.Counts[o.id] && (f.Roles[o.Author] == Owner || f.Roles[o.Author] == Admin))
		if !trusted {
			continue
		}
		for _, s := range o.Seals {
			if s.To != target {
				continue
			}
			for _, ref := range s.Holds {
				made := ref.Made
				if made == (ID{}) {
					made = o.id
				}
				x := h[made]
				if ref.Secret {
					x.secret = true
				} else {
					x.epoch = true
				}
				h[made] = x
			}
		}
	}
	return h
}

// SetRole promotes a member to admin or demotes an admin to member.
func (w *Writer) SetRole(target keys.PublicKey, role Role) (*Op, error) {
	f, _, err := w.fold()
	if err != nil {
		return nil, err
	}
	t := f.Roles[target]
	valid := (t == Member && role == Admin) || (t == Admin && role == Member)
	if f.Roles[w.Me.Public()] != Owner || !valid {
		return nil, ErrNotAllowed
	}
	o := w.base(SetRole)
	o.Target, o.Role = target, role
	return w.finish(o)
}

// Invite records an invite's public key and expiry.
func (w *Writer) Invite(invite keys.PublicKey, expires int64) (*Op, error) {
	f, _, err := w.fold()
	if err != nil {
		return nil, err
	}
	if a := f.Roles[w.Me.Public()]; (a != Owner && a != Admin) || invite.Valid() != nil || expires <= 0 {
		return nil, ErrNotAllowed
	}
	o := w.base(Invite)
	o.Invite, o.Expires = invite, expires
	return w.finish(o)
}
