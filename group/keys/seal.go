package keys

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// ErrOpen means a sealed box didn't open: not sealed to this identity, for
// a different context, or tampered with.
var ErrOpen = errors.New("keys: sealed box didn't open")

// Overhead is how much longer a sealed box is than its plaintext.
const Overhead = 32 + chacha20poly1305.Overhead

func sealKey(shared, ePub, rPub []byte, context string) ([]byte, error) {
	salt := append(append([]byte{}, ePub...), rPub...)
	return hkdf.Key(sha256.New, shared, salt, label+"seal "+context, chacha20poly1305.KeySize)
}

// Seal encrypts plaintext to the member key to, for context: a label
// naming what the box is for (the operation sealing it, say), which Open
// must be given too. The box is an ephemeral X25519 key followed by an
// XChaCha20-Poly1305 ciphertext under a key used once.
func Seal(rand io.Reader, to PublicKey, context string, plaintext []byte) ([]byte, error) {
	rPub, err := to.X25519()
	if err != nil {
		return nil, err
	}
	e, err := ecdh.X25519().GenerateKey(rand)
	if err != nil {
		return nil, err
	}
	shared, err := e.ECDH(rPub)
	if err != nil {
		return nil, err
	}
	ePub := e.PublicKey().Bytes()
	k, err := sealKey(shared, ePub, rPub.Bytes(), context)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(k)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	return aead.Seal(ePub, nonce, plaintext, []byte(context)), nil
}

// Open decrypts a box Seal made to id for context.
func (id *Identity) Open(context string, box []byte) ([]byte, error) {
	if len(box) < Overhead {
		return nil, ErrOpen
	}
	ePub, err := ecdh.X25519().NewPublicKey(box[:32])
	if err != nil {
		return nil, ErrOpen
	}
	x := id.X25519()
	shared, err := x.ECDH(ePub) // fails on a low-order ephemeral key
	if err != nil {
		return nil, ErrOpen
	}
	k, err := sealKey(shared, box[:32], x.PublicKey().Bytes(), context)
	if err != nil {
		return nil, ErrOpen
	}
	aead, err := chacha20poly1305.NewX(k)
	if err != nil {
		return nil, ErrOpen
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	pt, err := aead.Open(nil, nonce, box[32:], []byte(context))
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}
