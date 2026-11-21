package dht

import (
	"crypto/ed25519"
	"crypto/sha1"
	"errors"

	"github.com/getlantern/warren/bencode"
	"github.com/getlantern/warren/krpc"
)

// BEP 44 error codes.
const (
	ErrCodeTooBig       = 205
	ErrCodeBadSignature = 206
	ErrCodeSaltTooBig   = 207
	ErrCodeCASMismatch  = 301
	ErrCodeSeqTooLow    = 302
)

const (
	MaxValueSize = 1000
	MaxSaltSize  = 64
)

var ErrSaltTooLarge = errors.New("dht: salt exceeds 64 bytes")

// MutableItem is a BEP 44 signed, sequence-numbered value stored under
// SHA-1(key ‖ salt).
type MutableItem struct {
	Key  [32]byte
	Salt []byte
	Seq  int64
	V    []byte // bencoded value
	Sig  [64]byte
}

// NewMutable signs v under priv.
func NewMutable(priv ed25519.PrivateKey, salt []byte, seq int64, v []byte) (MutableItem, error) {
	if len(v) > MaxValueSize {
		return MutableItem{}, ErrTooLarge
	}
	if len(salt) > MaxSaltSize {
		return MutableItem{}, ErrSaltTooLarge
	}
	m := MutableItem{Key: [32]byte(priv.Public().(ed25519.PublicKey)), Salt: salt, Seq: seq, V: v}
	m.Sig = [64]byte(ed25519.Sign(priv, signedPayload(salt, seq, v)))
	return m, nil
}

// signedPayload is the BEP 44 signature input: the bencoded "salt" (if any),
// "seq", and "v" dictionary entries, without the surrounding dictionary.
func signedPayload(salt []byte, seq int64, v []byte) []byte {
	var b []byte
	if len(salt) > 0 {
		b = bencode.AppendString(b, "salt")
		b = bencode.AppendBytes(b, salt)
	}
	b = bencode.AppendString(b, "seq")
	b = bencode.AppendInt(b, seq)
	b = bencode.AppendString(b, "v")
	return append(b, v...)
}

func (m *MutableItem) Verify() bool {
	return len(m.V) <= MaxValueSize && len(m.Salt) <= MaxSaltSize &&
		ed25519.Verify(m.Key[:], signedPayload(m.Salt, m.Seq, m.V), m.Sig[:])
}

func (m *MutableItem) Target() krpc.NodeID { return MutableTarget(m.Key, m.Salt) }

func MutableTarget(key [32]byte, salt []byte) krpc.NodeID {
	h := sha1.New()
	h.Write(key[:])
	h.Write(salt)
	return krpc.NodeID(h.Sum(nil))
}

func (m *MutableItem) args() krpc.Args {
	seq := m.Seq
	return krpc.Args{V: m.V, K: m.Key[:], Sig: m.Sig[:], Seq: &seq, Salt: m.Salt}
}

// mutableFromReturn builds an item from a get response, if it carries one.
func mutableFromReturn(r *krpc.Return, salt []byte) (*MutableItem, bool) {
	if len(r.K) != 32 || len(r.Sig) != 64 || r.Seq == nil || r.V == nil {
		return nil, false
	}
	return &MutableItem{Key: [32]byte(r.K), Salt: salt, Seq: *r.Seq, V: r.V, Sig: [64]byte(r.Sig)}, true
}
