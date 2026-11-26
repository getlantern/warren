package dht

import (
	"crypto"
	"crypto/ed25519"
	"crypto/sha1"
	"errors"
	"fmt"

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

// ErrSigner means a signer is nil, its key isn't an Ed25519 key, or it
// failed to sign.
var ErrSigner = errors.New("dht: not a usable ed25519 signer")

// SignerKey returns s's Ed25519 public key. Every key this package signs
// with is a crypto.Signer: an ed25519.PrivateKey, or anything else that
// signs Ed25519 messages whole (a blinded key, a key in hardware). Signing
// runs on the node's loop, so a signer's Sign must be quick.
func SignerKey(s crypto.Signer) (key [32]byte, err error) {
	if s == nil {
		return [32]byte{}, ErrSigner
	}
	// A typed nil (a nil ed25519.PrivateKey, an adapter around nothing)
	// passes the check above and panics in Public.
	defer func() {
		if recover() != nil {
			key, err = [32]byte{}, ErrSigner
		}
	}()
	pk, ok := s.Public().(ed25519.PublicKey)
	if !ok || len(pk) != ed25519.PublicKeySize {
		return [32]byte{}, ErrSigner
	}
	return [32]byte(pk), nil
}

// sign signs msg whole with s, as Ed25519 does.
func sign(s crypto.Signer, msg []byte) (out [64]byte, err error) {
	// The signer is the caller's code, run on the node's loop: a panic in
	// it is a refusal, not the end of every lookup.
	defer func() {
		if r := recover(); r != nil {
			out, err = [64]byte{}, fmt.Errorf("%w: it panicked: %v", ErrSigner, r)
		}
	}()
	sig, err := s.Sign(nil, msg, crypto.Hash(0))
	if err != nil {
		return [64]byte{}, fmt.Errorf("%w: %w", ErrSigner, err)
	}
	if len(sig) != ed25519.SignatureSize {
		return [64]byte{}, fmt.Errorf("%w: a %d-byte signature", ErrSigner, len(sig))
	}
	return [64]byte(sig), nil
}

// NewMutable signs v under priv.
func NewMutable(priv crypto.Signer, salt []byte, seq int64, v []byte) (MutableItem, error) {
	if len(v) > MaxValueSize {
		return MutableItem{}, ErrTooLarge
	}
	if len(salt) > MaxSaltSize {
		return MutableItem{}, ErrSaltTooLarge
	}
	key, err := SignerKey(priv)
	if err != nil {
		return MutableItem{}, err
	}
	m := MutableItem{Key: key, Salt: salt, Seq: seq, V: v}
	if m.Sig, err = sign(priv, signedPayload(salt, seq, v)); err != nil {
		return MutableItem{}, err
	}
	// A signer whose signature isn't its public key's would publish items
	// every peer rejects: catch it here, where it can be reported.
	if !m.Verify() {
		return MutableItem{}, fmt.Errorf("%w: its signature doesn't verify under its key", ErrSigner)
	}
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
