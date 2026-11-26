package dht

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

// opaque signs with an ed25519 key it doesn't expose: a crypto.Signer that
// isn't an ed25519.PrivateKey, as a blinded or hardware key is.
type opaque struct{ k ed25519.PrivateKey }

func (o opaque) Public() crypto.PublicKey { return o.k.Public() }
func (o opaque) Sign(r io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	return o.k.Sign(r, msg, opts)
}

func TestNewMutableTakesAnySigner(t *testing.T) {
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	m, err := NewMutable(opaque{k}, []byte("salt"), 3, []byte("1:v"))
	if err != nil {
		t.Fatal(err)
	}
	if !m.Verify() || m.Key != [32]byte(k.Public().(ed25519.PublicKey)) {
		t.Fatal("an item signed by a signer that isn't a PrivateKey doesn't verify")
	}
}

func TestSignerRefusals(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for name, s := range map[string]crypto.Signer{"nil": nil, "ecdsa": ec} {
		if _, err := NewMutable(s, nil, 1, []byte("1:v")); !errors.Is(err, ErrSigner) {
			t.Fatalf("%s: %v", name, err)
		}
		n := New(Config{ID: outsiderID(rng(1)), Rand: rng(2)})
		if _, err := n.Signal(t0, s, [32]byte{1}, nil); !errors.Is(err, ErrSigner) {
			t.Fatalf("%s signal: %v", name, err)
		}
		if err := n.Listen(t0, s); !errors.Is(err, ErrSigner) {
			t.Fatalf("%s listen: %v", name, err)
		}
	}
}
