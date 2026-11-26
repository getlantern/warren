package hy2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
)

func TestCertificateRefusesNonEd25519(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for name, s := range map[string]crypto.Signer{"nil": nil, "ecdsa": ec} {
		if _, err := certificate(s); !errors.Is(err, errNotEd25519) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
