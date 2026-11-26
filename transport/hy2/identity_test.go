package hy2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
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
