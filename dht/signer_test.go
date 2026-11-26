package dht

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
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

// failing signs with k until told to fail, as a hardware key might.
type failing struct {
	k    ed25519.PrivateKey
	fail bool
}

func (f *failing) Public() crypto.PublicKey { return f.k.Public() }
func (f *failing) Sign(r io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	if f.fail {
		return nil, errors.New("device gone")
	}
	return f.k.Sign(r, msg, opts)
}

// wrongKey names one key and signs with another.
type wrongKey struct{ pub, k ed25519.PrivateKey }

func (w wrongKey) Public() crypto.PublicKey { return w.pub.Public() }
func (w wrongKey) Sign(r io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	return w.k.Sign(r, msg, opts)
}

// TestFailedSignKeepsRecord: a signer failing on a re-sign leaves the
// record held before, signed and valid, instead of an empty one.
func TestFailedSignKeepsRecord(t *testing.T) {
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	f := &failing{k: k}
	n := New(Config{ID: outsiderID(rng(1)), Rand: rng(2)})
	if err := n.Listen(t0, f); err != nil {
		t.Fatal(err)
	}
	if len(n.lst.records) != 1 {
		t.Fatalf("%d records", len(n.lst.records))
	}
	f.fail = true
	n.resign(t0.Add(time.Second))
	for _, target := range n.lst.records {
		o := n.owned[target]
		if o == nil || o.rec.mut == nil || !o.rec.mut.Verify() {
			t.Fatal("a failed re-sign replaced the record with an invalid one")
		}
	}
	// A new epoch's record isn't made while signing fails, and is once it
	// works again.
	later := t0.Add(2 * RecordEpoch)
	n.ensureRecords(later)
	if _, ok := n.lst.records[epochOf(later)]; ok {
		t.Fatal("a record was stored for an epoch the signer couldn't sign")
	}
	f.fail = false
	n.ensureRecords(later)
	if _, ok := n.lst.records[epochOf(later)]; !ok {
		t.Fatal("no record once the signer works again")
	}
}

func TestSignerEdges(t *testing.T) {
	var nilKey ed25519.PrivateKey
	if _, err := SignerKey(nilKey); !errors.Is(err, ErrSigner) {
		t.Fatalf("a typed-nil key: %v", err)
	}
	_, a, _ := ed25519.GenerateKey(rand.Reader)
	_, b, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := NewMutable(wrongKey{pub: a, k: b}, nil, 1, []byte("1:v")); !errors.Is(err, ErrSigner) {
		t.Fatalf("a signer naming another key: %v", err)
	}
	gone := &failing{k: a, fail: true}
	if _, err := NewMutable(gone, nil, 1, []byte("1:v")); !errors.Is(err, ErrSigner) || !strings.Contains(err.Error(), "device gone") {
		t.Fatalf("a failing signer's cause: %v", err)
	}
}
