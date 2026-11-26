package hy2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"testing"
)

func TestCertificateRefusesNonEd25519(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var nilKey ed25519.PrivateKey
	for name, s := range map[string]crypto.Signer{"nil": nil, "ecdsa": ec, "typed nil": nilKey} {
		if _, err := certificate(s); !errors.Is(err, ErrNotEd25519) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// panicky panics in Sign, as a broken hardware signer might.
type panicky struct{ k ed25519.PrivateKey }

func (p panicky) Public() crypto.PublicKey { return p.k.Public() }
func (panicky) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	panic("device gone")
}

func TestCertificateSignerPanicIsError(t *testing.T) {
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := certificate(panicky{k}); err == nil || errors.Is(err, ErrNotEd25519) {
		t.Fatalf("a panicking Ed25519 signer: %v", err)
	}
}
