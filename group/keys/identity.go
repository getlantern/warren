package keys

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha512"
	"errors"
	"io"

	"filippo.io/edwards25519"
)

// PublicKey is an Ed25519 public key: a member key, or a blinded one.
type PublicKey [32]byte

// Signer signs as one Ed25519 public key. An Identity and the blinded keys
// derived from it are both Signers; a blinded key has no seed, so it can't
// be an ed25519.PrivateKey.
type Signer interface {
	Public() PublicKey
	Sign(msg []byte) []byte
}

// CryptoSigner adapts s to a crypto.Signer, the form warren's endpoint,
// driver, dht and hy2 take a key in, so a member can listen and connect
// under a blinded key. It signs messages whole, as Ed25519 does.
func CryptoSigner(s Signer) crypto.Signer { return cryptoSigner{s} }

type cryptoSigner struct{ s Signer }

func (c cryptoSigner) Public() crypto.PublicKey {
	pk := c.s.Public()
	return ed25519.PublicKey(pk[:])
}

func (c cryptoSigner) Sign(_ io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts != nil && opts.HashFunc() != 0 {
		return nil, errors.New("keys: Ed25519 signs messages whole, not digests")
	}
	return c.s.Sign(msg), nil
}

// Verify reports whether sig is pk's signature of msg, and pk is a usable
// key: under a small-order key anyone can forge signatures that
// ed25519.Verify accepts.
func (pk PublicKey) Verify(msg, sig []byte) bool {
	if _, err := pk.point(); err != nil {
		return false
	}
	return ed25519.Verify(pk[:], msg, sig)
}

// Valid returns ErrBadKey if pk isn't a usable key, the check to run before
// admitting a member key.
func (pk PublicKey) Valid() error {
	_, err := pk.point()
	return err
}

// ErrBadKey means a public key isn't a usable point: not on the curve,
// outside the prime-order subgroup (small order, or an honest key plus a
// small-order component), or encoded non-canonically. Each of the last two
// would let one secret appear as several keys.
var ErrBadKey = errors.New("keys: unusable public key")

func (pk PublicKey) point() (*edwards25519.Point, error) {
	p, err := new(edwards25519.Point).SetBytes(pk[:])
	if err != nil || PublicKey(p.Bytes()) != pk {
		return nil, ErrBadKey
	}
	// P is in the prime-order subgroup exactly when 8⁻¹·(8·P) = P; a
	// small-order component is lost by multiplying by the cofactor.
	eight := new(edwards25519.Point).MultByCofactor(p)
	if eight.Equal(edwards25519.NewIdentityPoint()) == 1 ||
		new(edwards25519.Point).ScalarMult(invEight, eight).Equal(p) != 1 {
		return nil, ErrBadKey
	}
	return p, nil
}

var invEight = func() *edwards25519.Scalar {
	var b [32]byte
	b[0] = 8
	s, err := new(edwards25519.Scalar).SetCanonicalBytes(b[:])
	if err != nil {
		panic(err)
	}
	return s.Invert(s)
}()

// X25519 converts pk to the X25519 key sealing to it uses. Only member keys
// are sealed to: a blinded key has no Identity to open with, so a box
// sealed to one can't be opened.
func (pk PublicKey) X25519() (*ecdh.PublicKey, error) {
	p, err := pk.point()
	if err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPublicKey(p.BytesMontgomery())
}

// blindScalar is the blinding scalar for factor and public key a. Binding
// a's own bytes into it means one factor blinds different keys by
// unrelated scalars.
func blindScalar(factor [32]byte, a PublicKey) *edwards25519.Scalar {
	h := sha512.New()
	h.Write([]byte(label + "blind scalar "))
	h.Write(factor[:])
	h.Write(a[:])
	s, err := new(edwards25519.Scalar).SetUniformBytes(h.Sum(nil))
	if err != nil {
		panic(err) // SHA-512 output is always 64 bytes
	}
	return s
}

// Blind returns pk blinded by factor: what a member computes for another
// member's rendezvous key, from the roster, without asking anyone.
func (pk PublicKey) Blind(factor [32]byte) (PublicKey, error) {
	p, err := pk.point()
	if err != nil {
		return PublicKey{}, err
	}
	return PublicKey(new(edwards25519.Point).ScalarMult(blindScalar(factor, pk), p).Bytes()), nil
}

// Rendezvous is member's rendezvous key in period p.
func Rendezvous(g Secret, p uint64, member PublicKey) (PublicKey, error) {
	return member.Blind(g.Blind(p))
}

// expanded is an Ed25519 key in expanded form: the secret scalar and the
// nonce prefix, which is all signing needs.
type expanded struct {
	scalar *edwards25519.Scalar
	prefix [32]byte
	pub    PublicKey
}

func (k *expanded) Public() PublicKey { return k.pub }

// Sign is RFC 8032 Ed25519 signing from the expanded key, so ed25519.Verify
// accepts its signatures.
func (k *expanded) Sign(msg []byte) []byte {
	h := sha512.New()
	h.Write(k.prefix[:])
	h.Write(msg)
	r, err := new(edwards25519.Scalar).SetUniformBytes(h.Sum(nil))
	if err != nil {
		panic(err)
	}
	R := new(edwards25519.Point).ScalarBaseMult(r).Bytes()
	h.Reset()
	h.Write(R)
	h.Write(k.pub[:])
	h.Write(msg)
	c, err := new(edwards25519.Scalar).SetUniformBytes(h.Sum(nil))
	if err != nil {
		panic(err)
	}
	S := new(edwards25519.Scalar).MultiplyAdd(c, k.scalar, r)
	return append(R, S.Bytes()...)
}

// Identity is a device's member key in one group, generated on join and
// never reused across groups.
type Identity struct {
	seed [32]byte
	expanded
}

// NewIdentity makes a member key from rand.
func NewIdentity(rand io.Reader) (*Identity, error) {
	var seed [32]byte
	if _, err := io.ReadFull(rand, seed[:]); err != nil {
		return nil, err
	}
	return IdentityFromSeed(seed), nil
}

// IdentityFromSeed restores a member key from its seed.
func IdentityFromSeed(seed [32]byte) *Identity {
	h := sha512.Sum512(seed[:])
	s, err := new(edwards25519.Scalar).SetBytesWithClamping(h[:32])
	if err != nil {
		panic(err)
	}
	id := &Identity{seed: seed}
	id.scalar = s
	id.prefix = [32]byte(h[32:])
	id.pub = PublicKey(new(edwards25519.Point).ScalarBaseMult(s).Bytes())
	return id
}

// Seed returns the seed, to store the identity.
func (id *Identity) Seed() [32]byte { return id.seed }

// Blind returns the signer for the identity blinded by factor, whose public
// key is id.Public().Blind(factor).
func (id *Identity) Blind(factor [32]byte) Signer {
	b := blindScalar(factor, id.pub)
	h := sha512.New()
	h.Write([]byte(label + "blind prefix "))
	h.Write(id.prefix[:])
	h.Write(factor[:])
	k := &expanded{
		scalar: new(edwards25519.Scalar).Multiply(b, id.scalar),
		prefix: [32]byte(h.Sum(nil)[:32]),
	}
	k.pub = PublicKey(new(edwards25519.Point).ScalarBaseMult(k.scalar).Bytes())
	return k
}

// Rendezvous returns the signer for the identity's rendezvous key in
// period p, which it listens under.
func (id *Identity) Rendezvous(g Secret, p uint64) Signer { return id.Blind(g.Blind(p)) }

// X25519 is the identity's X25519 key, for opening what is sealed to it.
// It is the same clamped scalar as the Ed25519 key, so it matches
// id.Public().X25519().
func (id *Identity) X25519() *ecdh.PrivateKey {
	h := sha512.Sum512(id.seed[:])
	k, err := ecdh.X25519().NewPrivateKey(h[:32])
	if err != nil {
		panic(err)
	}
	return k
}
