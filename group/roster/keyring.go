package roster

import (
	"encoding/binary"

	"github.com/getlantern/warren/group/keys"
)

// A box's plaintext is a list of entries, each a key and the operation that
// made it: the ID of the key-making operation (all zero for the sealing
// operation's own new keys), one byte saying which key, and the key.
const entrySize = 32 + 1 + 32

const (
	entryEpoch  = 0
	entrySecret = 1
)

type entry struct {
	made   ID // zero: the sealing operation itself
	secret bool
	key    [32]byte
}

func encodeEntries(es []entry) []byte {
	b := make([]byte, 0, len(es)*entrySize)
	for _, e := range es {
		b = append(b, e.made[:]...)
		if e.secret {
			b = append(b, entrySecret)
		} else {
			b = append(b, entryEpoch)
		}
		b = append(b, e.key[:]...)
	}
	return b
}

func decodeEntries(b []byte) ([]entry, bool) {
	if len(b)%entrySize != 0 {
		return nil, false
	}
	var es []entry
	for ; len(b) > 0; b = b[entrySize:] {
		var e entry
		copy(e.made[:], b[:32])
		switch b[32] {
		case entrySecret:
			e.secret = true
		case entryEpoch:
		default:
			return nil, false
		}
		copy(e.key[:], b[33:entrySize])
		es = append(es, e)
	}
	return es, true
}

// sealContext binds a box to the operation sealing it, by fields known
// before the operation is signed.
func sealContext(o *Op) string {
	b := append([]byte("roster "), o.Group[:]...)
	b = append(b, o.Author[:]...)
	b = binary.BigEndian.AppendUint64(b, o.Lamport)
	return string(append(b, byte(o.Kind)))
}

// Keyring is the keys a member holds: every group secret and epoch key
// sealed to it, each checked against the commitment of the operation that
// made it, and named by that operation's ID.
type Keyring struct {
	Secrets map[ID]keys.Secret
	Epochs  map[ID]keys.EpochKey
}

// Keyring opens every box in the roster sealed to id, counting operations
// or not: a seal hands over its keys whether or not the fold accepts the
// operation carrying it. A key that doesn't match its maker's commitment is
// ignored, whoever sealed it.
func (r *Roster) Keyring(id *keys.Identity) *Keyring {
	k := &Keyring{Secrets: map[ID]keys.Secret{}, Epochs: map[ID]keys.EpochKey{}}
	me := id.Public()
	for _, o := range r.ops {
		for _, s := range o.Seals {
			if s.To != me {
				continue
			}
			pt, err := id.Open(sealContext(o), s.Box)
			if err != nil {
				continue
			}
			es, ok := decodeEntries(pt)
			if !ok {
				continue
			}
			for _, e := range es {
				made := e.made
				if made == (ID{}) {
					made = o.id
				}
				m := r.ops[made]
				if m == nil || !m.Kind.makesKeys() {
					continue
				}
				if e.secret && keys.CommitSecret(keys.Secret(e.key)) == m.CommitSecret {
					k.Secrets[made] = keys.Secret(e.key)
				}
				if !e.secret && keys.CommitEpoch(keys.EpochKey(e.key)) == m.CommitEpoch {
					k.Epochs[made] = keys.EpochKey(e.key)
				}
			}
		}
	}
	return k
}
