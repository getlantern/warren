// Package keys holds a private group's key material and the derivations
// docs/groups-design.md specifies: the group secret and what derives from
// it, member identities and their per-period blinded rendezvous keys,
// sealing keys to a member, and commitments to new keys.
package keys

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"time"
)

// Period is how long rendezvous keys, the directory's signing key and its
// salts last before they rotate.
const Period = time.Hour

// PeriodOf returns the period t falls in.
// Times before 1970 (an unset time.Time, say) are period 0.
func PeriodOf(t time.Time) uint64 {
	return uint64(max(t.Unix(), 0)) / uint64(Period/time.Second)
}

const label = "warren/group/v1 "

// Secret is a group secret, G: 32 random bytes the founder makes, replaced
// on every rekey, and delivered only sealed to members (mirrors included).
type Secret [32]byte

// EpochKey wraps content keys. It is delivered sealed to members but not to
// mirrors.
type EpochKey [32]byte

func derive(secret []byte, info string, n int) []byte {
	k, err := hkdf.Key(sha256.New, secret, nil, label+info, n)
	if err != nil {
		panic(err) // only for n out of range
	}
	return k
}

func periodBytes(p uint64) []byte { return binary.BigEndian.AppendUint64(nil, p) }

// DirKey derives the directory's signing seeds and salts.
func (g Secret) DirKey() [32]byte { return [32]byte(derive(g[:], "directory", 32)) }

// DirSeal derives the key that encrypts directory shards.
func (g Secret) DirSeal() [32]byte { return [32]byte(derive(g[:], "directory seal", 32)) }

// Blind derives the factor that blinds member keys into period p's
// rendezvous keys.
func (g Secret) Blind(p uint64) [32]byte {
	return [32]byte(derive(g[:], "blind"+string(periodBytes(p)), 32))
}

// DirectoryKey is period p's directory signing key, which every holder of G
// can compute and which changes every period.
func (g Secret) DirectoryKey(p uint64) ed25519.PrivateKey {
	dk := g.DirKey()
	return ed25519.NewKeyFromSeed(derive(dk[:], "directory key"+string(periodBytes(p)), ed25519.SeedSize))
}

// DirectorySalt is the BEP 44 salt of shard in period p.
func (g Secret) DirectorySalt(p uint64, shard uint32) []byte {
	dk := g.DirKey()
	m := hmac.New(sha256.New, dk[:])
	m.Write([]byte(label + "directory salt"))
	m.Write(periodBytes(p))
	m.Write(binary.BigEndian.AppendUint32(nil, shard))
	return m.Sum(nil)
}

// SyncKey is the caller key for calling rendezvous, the callee's period-p
// rendezvous key (not its member key), when the callee may not know the
// caller yet: only a holder of G can compute it, and signaling offers are
// signed by it, so it proves G before any session exists.
func (g Secret) SyncKey(p uint64, rendezvous PublicKey) *Identity {
	info := "sync" + string(periodBytes(p)) + string(rendezvous[:])
	return IdentityFromSeed([32]byte(derive(g[:], info, 32)))
}

// InviteBlind derives the factor that blinds an invite key in period p,
// from the invite secret I rather than G, so an invitee can compute it.
func InviteBlind(invite [32]byte, p uint64) [32]byte {
	return [32]byte(derive(invite[:], "invite blind"+string(periodBytes(p)), 32))
}

// CommitSecret commits to a group secret, so a member given it by anyone
// can check it against the operation that made it.
func CommitSecret(g Secret) [32]byte {
	return sha256.Sum256(append([]byte(label+"commit secret "), g[:]...))
}

// CommitEpoch commits to an epoch key. It is separate from CommitSecret
// because a mirror is given G alone and must check it alone.
func CommitEpoch(e EpochKey) [32]byte {
	return sha256.Sum256(append([]byte(label+"commit epoch "), e[:]...))
}
