// Package roster is a private group's membership: signed operations, folded
// into who is in the group, in what role, and which keys are current, by
// the rules docs/groups-design.md gives and group/rostermodel model-checks.
package roster

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"github.com/getlantern/warren/bencode"
	"github.com/getlantern/warren/group/keys"
)

const (
	// MaxName bounds a group's or member's display name, in bytes.
	MaxName = 256
	// MaxShards bounds the directory's shard count.
	MaxShards = 1 << 16
	// MaxOpBytes bounds an operation's encoding: room for a rekey sealed to
	// thousands of members, or an add carrying thousands of epoch keys.
	MaxOpBytes = 1 << 20
	// maxOpValues bounds its bencode values: every value takes at least
	// two bytes, so this never binds before MaxOpBytes does.
	maxOpValues = MaxOpBytes / 2
)

// ID names an operation: the SHA-256 of its signed encoding. Since the
// encoding includes the parents' IDs, an ID commits to the operation's
// whole history. A key-making operation's ID also names the group secret
// and epoch key it made.
type ID [32]byte

// Role is a key's role in the group.
type Role uint8

const (
	None Role = iota
	Member
	Mirror
	Admin
	Owner
)

func (r Role) String() string {
	if int(r) < len(roleNames) {
		return roleNames[r]
	}
	return fmt.Sprintf("role(%d)", r)
}

var roleNames = []string{"none", "member", "mirror", "admin", "owner"}

// rank orders roles by the keys they hold: a mirror holds the fewest.
func rank(r Role) int { return [...]int{0, 2, 1, 3, 4}[r] }

// Kind is an operation's kind.
type Kind uint8

const (
	Genesis Kind = iota
	Add
	Remove
	Rekey
	Deliver
	SetRole
	Invite
)

func (k Kind) String() string {
	if int(k) < len(kindNames) {
		return kindNames[k]
	}
	return fmt.Sprintf("kind(%d)", k)
}

var kindNames = []string{"genesis", "add", "remove", "rekey", "deliver", "role", "invite"}

func (k Kind) makesKeys() bool { return k == Genesis || k == Remove || k == Rekey }

// needsAdmin reports whether an operation of kind k needs admin authority.
func (k Kind) needsAdmin() bool {
	return k == Add || k == Remove || k == Rekey || k == SetRole || k == Invite
}

// Seal is a box of keys sealed to one member key. Holds lists, in the
// clear, which keys the box carries, so other members can tell what the
// recipient holds without opening it. Only the recipient can check it, so
// a sender trusts only the lists of the owner, admins and itself (see
// Writer.Deliver).
type Seal struct {
	To    keys.PublicKey
	Box   []byte
	Holds []KeyRef
}

// KeyRef names a key: the operation that made it (zero for the sealing
// operation's own new keys), and whether it is the group secret or the
// epoch key.
type KeyRef struct {
	Made   ID
	Secret bool
}

// Op is a signed roster operation. Which fields an operation carries
// depends on its kind; the rest are zero.
type Op struct {
	Group   ID // the genesis's ID; zero in the genesis itself
	Kind    Kind
	Author  keys.PublicKey
	Lamport uint64
	Parents []ID // sorted, no duplicates

	Target keys.PublicKey // add, remove, deliver, role
	Role   Role           // add, role
	Name   string         // genesis: the group's name; add: a display name
	Shards uint32         // genesis: the directory's shard count

	// LogSeq and LogHead are, in a remove, the head of the target's log the
	// remover had seen (*Logs* in the design).
	LogSeq  uint64
	LogHead [32]byte

	// Invite is, in an invite, the invite's public key; in an add or a
	// rejoin's deliver, the invite it answers, if any.
	Invite  keys.PublicKey
	Expires int64 // invite: Unix seconds

	// CommitSecret and CommitEpoch commit to the keys a key-making
	// operation makes (keys.CommitSecret, keys.CommitEpoch).
	CommitSecret [32]byte
	CommitEpoch  [32]byte

	Seals []Seal // sorted by To

	Sig []byte
	id  ID
}

// clone is a deep copy.
func (o *Op) clone() *Op {
	c := *o
	c.Parents = slices.Clone(o.Parents)
	c.Sig = slices.Clone(o.Sig)
	c.Seals = nil
	if o.Seals != nil {
		c.Seals = make([]Seal, len(o.Seals))
	}
	for i, s := range o.Seals {
		c.Seals[i] = Seal{To: s.To, Box: slices.Clone(s.Box), Holds: slices.Clone(s.Holds)}
	}
	return &c
}

// ID returns the operation's ID. It is valid once the operation is signed
// or decoded.
func (o *Op) ID() ID { return o.id }

func (o *Op) String() string { return fmt.Sprintf("%v %x by %x", o.Kind, o.id[:4], o.Author[:4]) }

var (
	// ErrMalformed means an encoding isn't a well-formed, canonical operation.
	ErrMalformed = errors.New("roster: malformed operation")
	// ErrSignature means an operation's signature doesn't verify.
	ErrSignature = errors.New("roster: bad signature")
)

func boolByte(b bool) byte {
	if b {
		return 1
	}
	return 0
}

func str(b []byte) bencode.Value                  { return bencode.Value{Kind: bencode.String, Str: b} }
func num(n int64) bencode.Value                   { return bencode.Value{Kind: bencode.Int, Int: n} }
func pair(k string, v bencode.Value) bencode.Pair { return bencode.Pair{Key: []byte(k), Value: v} }

// encode is the canonical encoding, with or without the signature.
func (o *Op) encode(withSig bool) []byte {
	d := []bencode.Pair{
		pair("a", str(o.Author[:])),
		pair("k", num(int64(o.Kind))),
		pair("l", num(int64(o.Lamport))),
	}
	if o.Kind != Genesis {
		d = append(d, pair("g", str(o.Group[:])))
	}
	if len(o.Parents) > 0 {
		ps := bencode.Value{Kind: bencode.List}
		for _, p := range o.Parents {
			ps.List = append(ps.List, str(p[:]))
		}
		d = append(d, pair("p", ps))
	}
	var zero keys.PublicKey
	if o.Target != zero {
		d = append(d, pair("t", str(o.Target[:])))
	}
	if o.Role != None {
		d = append(d, pair("r", num(int64(o.Role))))
	}
	if o.Name != "" {
		d = append(d, pair("n", str([]byte(o.Name))))
	}
	if o.Shards != 0 {
		d = append(d, pair("s", num(int64(o.Shards))))
	}
	if o.LogSeq != 0 || o.LogHead != [32]byte{} {
		d = append(d, pair("hs", num(int64(o.LogSeq))), pair("hh", str(o.LogHead[:])))
	}
	if o.Invite != zero {
		d = append(d, pair("i", str(o.Invite[:])))
	}
	if o.Expires != 0 {
		d = append(d, pair("e", num(o.Expires)))
	}
	if o.Kind.makesKeys() {
		d = append(d, pair("cg", str(o.CommitSecret[:])), pair("ce", str(o.CommitEpoch[:])))
	}
	if len(o.Seals) > 0 {
		ss := bencode.Value{Kind: bencode.List}
		for _, s := range o.Seals {
			hs := bencode.Value{Kind: bencode.List}
			for _, h := range s.Holds {
				hs.List = append(hs.List, str(append(h.Made[:], boolByte(h.Secret))))
			}
			ss.List = append(ss.List, bencode.Value{Kind: bencode.Dict, Dict: []bencode.Pair{
				pair("b", str(s.Box)), pair("h", hs), pair("to", str(s.To[:])),
			}})
		}
		d = append(d, pair("x", ss))
	}
	if withSig {
		d = append(d, pair("z", str(o.Sig)))
	}
	return bencode.Append(nil, bencode.Value{Kind: bencode.Dict, Dict: d})
}

// fieldsFitKind reports whether the operation carries only the fields its
// kind uses (the target is checked separately).
func (o *Op) fieldsFitKind() bool {
	var zero keys.PublicKey
	has := func(set bool, allowed ...Kind) bool { return !set || slices.Contains(allowed, o.Kind) }
	switch {
	case !has(o.Role != None, Add, SetRole),
		!has(o.Name != "", Genesis, Add),
		!has(o.Shards != 0, Genesis),
		!has(o.LogSeq != 0 || o.LogHead != [32]byte{}, Remove),
		!has(o.Invite != zero, Invite, Add, Deliver),
		!has(o.Expires != 0, Invite),
		!has(len(o.Seals) != 0, Genesis, Add, Remove, Rekey, Deliver):
		return false
	}
	switch o.Kind {
	case Genesis:
		return o.Shards != 0
	case Add, SetRole:
		return o.Role != None
	case Invite:
		return o.Invite != zero && o.Expires > 0
	}
	return true
}

// signed is the message an operation's signature covers.
func (o *Op) signed() []byte {
	return append([]byte("warren/group/v1 roster op "), o.encode(false)...)
}

// Sign normalizes the operation (sorting parents and seals), signs it as
// author, and sets its ID.
func (o *Op) Sign(author keys.Signer) {
	o.Author = author.Public()
	slices.SortFunc(o.Parents, func(a, b ID) int { return bytes.Compare(a[:], b[:]) })
	o.Parents = slices.Compact(o.Parents)
	slices.SortFunc(o.Seals, func(a, b Seal) int { return bytes.Compare(a.To[:], b.To[:]) })
	o.Sig = author.Sign(o.signed())
	o.id = sha256.Sum256(o.Encode())
}

// Encode returns the signed operation's encoding.
func (o *Op) Encode() []byte { return o.encode(true) }

// Decode parses and verifies an operation: well-formed, canonical (it
// re-encodes to exactly b), with usable keys, signed by its author.
func Decode(b []byte) (*Op, error) {
	if len(b) > MaxOpBytes {
		return nil, ErrMalformed
	}
	v, err := bencode.DecodeLimit(b, maxOpValues)
	if err != nil || v.Kind != bencode.Dict {
		return nil, ErrMalformed
	}
	o := &Op{}
	key32 := func(dst []byte, val bencode.Value) bool {
		if val.Kind != bencode.String || len(val.Str) != 32 {
			return false
		}
		copy(dst, val.Str)
		return true
	}
	nonneg := func(val bencode.Value) (int64, bool) {
		return val.Int, val.Kind == bencode.Int && val.Int >= 0
	}
	for _, p := range v.Dict {
		val := p.Value
		var ok bool
		switch string(p.Key) {
		case "a":
			ok = key32(o.Author[:], val)
		case "g":
			ok = key32(o.Group[:], val)
		case "k":
			n, good := nonneg(val)
			ok = good && n <= int64(Invite)
			o.Kind = Kind(n)
		case "l":
			n, good := nonneg(val)
			ok = good
			o.Lamport = uint64(n)
		case "p":
			ok = val.Kind == bencode.List
			for _, item := range val.List {
				var id ID
				ok = ok && key32(id[:], item)
				o.Parents = append(o.Parents, id)
			}
		case "t":
			ok = key32(o.Target[:], val)
		case "r":
			n, good := nonneg(val)
			ok = good && n <= int64(Owner)
			o.Role = Role(n)
		case "n":
			ok = val.Kind == bencode.String && len(val.Str) <= MaxName
			o.Name = string(val.Str)
		case "s":
			n, good := nonneg(val)
			ok = good && n <= MaxShards
			o.Shards = uint32(n)
		case "hs":
			n, good := nonneg(val)
			ok = good
			o.LogSeq = uint64(n)
		case "hh":
			ok = key32(o.LogHead[:], val)
		case "i":
			ok = key32(o.Invite[:], val)
		case "e":
			n, good := nonneg(val)
			ok = good
			o.Expires = n
		case "cg":
			ok = key32(o.CommitSecret[:], val)
		case "ce":
			ok = key32(o.CommitEpoch[:], val)
		case "x":
			ok = val.Kind == bencode.List
			for _, item := range val.List {
				var s Seal
				to, hasTo := item.Get("to")
				box, hasBox := item.Get("b")
				hs, hasHolds := item.Get("h")
				ok = ok && item.Kind == bencode.Dict && len(item.Dict) == 3 && hasTo && hasBox && hasHolds &&
					key32(s.To[:], to) && box.Kind == bencode.String && hs.Kind == bencode.List
				s.Box = bytes.Clone(box.Str)
				for _, h := range hs.List {
					ok = ok && h.Kind == bencode.String && len(h.Str) == 33 && h.Str[32] <= 1
					if ok {
						s.Holds = append(s.Holds, KeyRef{Made: ID(h.Str[:32]), Secret: h.Str[32] == 1})
					}
				}
				o.Seals = append(o.Seals, s)
			}
		case "z":
			ok = val.Kind == bencode.String
			o.Sig = bytes.Clone(val.Str)
		default:
			ok = false
		}
		if !ok {
			return nil, ErrMalformed
		}
	}
	// Re-encoding must reproduce b exactly: that rejects unsorted or
	// duplicate parents and seals, explicit zero fields, and fields a kind
	// doesn't carry, so one operation has one encoding and one ID.
	if !bytes.Equal(o.Encode(), b) {
		return nil, ErrMalformed
	}
	if !slices.IsSortedFunc(o.Parents, func(a, b ID) int { return bytes.Compare(a[:], b[:]) }) ||
		len(slices.Compact(slices.Clone(o.Parents))) != len(o.Parents) {
		return nil, ErrMalformed
	}
	for i := 1; i < len(o.Seals); i++ {
		if bytes.Compare(o.Seals[i-1].To[:], o.Seals[i].To[:]) >= 0 {
			return nil, ErrMalformed // unsorted, or two seals to one key
		}
	}
	if err := o.Author.Valid(); err != nil {
		return nil, ErrMalformed
	}
	if !o.fieldsFitKind() {
		return nil, ErrMalformed
	}
	// A kind with a target must carry a usable one, and others none: a
	// missing target must never count as a key on the roster.
	var zero keys.PublicKey
	switch o.Kind {
	case Add, Remove, Deliver, SetRole:
		if o.Target.Valid() != nil {
			return nil, ErrMalformed
		}
	default:
		if o.Target != zero {
			return nil, ErrMalformed
		}
	}
	for _, s := range o.Seals {
		if s.To.Valid() != nil {
			return nil, ErrMalformed
		}
	}
	if (o.Kind == Invite || o.Invite != zero) && o.Invite.Valid() != nil {
		return nil, ErrMalformed
	}
	if !o.Author.Verify(o.signed(), o.Sig) {
		return nil, ErrSignature
	}
	o.id = sha256.Sum256(b)
	return o, nil
}
