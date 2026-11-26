package dht

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/getlantern/warren/krpc"
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

// panicky panics in Sign, as a broken adapter might.
type panicky struct{ k ed25519.PrivateKey }

func (p panicky) Public() crypto.PublicKey { return p.k.Public() }
func (panicky) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	panic("broken signer")
}

func TestSignPanicIsRefusal(t *testing.T) {
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := NewMutable(panicky{k}, nil, 1, []byte("1:v")); !errors.Is(err, ErrSigner) {
		t.Fatalf("a panicking signer: %v", err)
	}
}

// TestListenRefusesUnsigningSigner: a signer that can't sign is refused,
// and the identity listened under before stays.
func TestListenRefusesUnsigningSigner(t *testing.T) {
	_, good, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	n := New(Config{ID: outsiderID(rng(1)), Rand: rng(2)})
	if err := n.Listen(t0, good); err != nil {
		t.Fatal(err)
	}
	for name, s := range map[string]crypto.Signer{
		"failing":   &failing{k: other, fail: true},
		"wrong key": wrongKey{pub: other, k: good},
		"panicking": panicky{other},
	} {
		if err := n.Listen(t0, s); !errors.Is(err, ErrSigner) {
			t.Fatalf("%s: %v", name, err)
		}
		if n.lst == nil || n.lst.pub != [32]byte(good.Public().(ed25519.PublicKey)) || len(n.lst.records) == 0 {
			t.Fatalf("%s: the identity listened under before was dropped", name)
		}
	}
}

// TestSignerFailedOnce: a run of failed signs is reported once, and again
// only after a success.
func TestSignerFailedOnce(t *testing.T) {
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	f := &failing{k: k}
	n := New(Config{ID: outsiderID(rng(1)), Rand: rng(2)})
	if err := n.Listen(t0, f); err != nil {
		t.Fatal(err)
	}
	count := func() int {
		_, evs := n.Drain()
		c := 0
		for _, e := range evs {
			if _, ok := e.(SignerFailed); ok {
				c++
			}
		}
		return c
	}
	count()
	f.fail = true
	n.resign(t0.Add(time.Second))
	n.resign(t0.Add(2 * time.Second))
	if c := count(); c != 1 {
		t.Fatalf("%d SignerFailed events for one run of failures", c)
	}
	f.fail = false
	n.resign(t0.Add(3 * time.Second))
	f.fail = true
	n.resign(t0.Add(4 * time.Second))
	if c := count(); c != 1 {
		t.Fatalf("%d SignerFailed events after a success and a new failure", c)
	}
}

// TestRebindRetriedAfterFailedSign: a NAT mapping change seen while the
// signer fails is re-signed by the next maintenance pass, once the signer
// works, and a failing signer is asked once a pass, not per holder reply.
func TestRebindRetriedAfterFailedSign(t *testing.T) {
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	f := &counting{failing: failing{k: k}}
	n := New(Config{ID: outsiderID(rng(1)), Rand: rng(2)})
	if err := n.Listen(t0, f); err != nil {
		t.Fatal(err)
	}
	var target krpc.NodeID
	for _, tg := range n.lst.records {
		target = tg
	}
	seq := n.recordSeq[target]
	old := netip.MustParseAddrPort("192.0.2.1:1000")
	moved := netip.MustParseAddrPort("192.0.2.9:2000")
	var hs []*holder
	for i := range 4 {
		h := &holder{addr: netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(i + 1)}), 6881), target: target, mapped: old}
		hs = append(hs, h)
		n.lst.holders = append(n.lst.holders, h)
	}
	f.fail, f.signs = true, 0
	for _, h := range hs {
		n.keepaliveReply(t0.Add(time.Second), h, &krpc.Msg{IP: moved})
	}
	if f.signs > len(n.lst.records) {
		t.Fatalf("%d signs for one mapping change seen by %d holders", f.signs, len(hs))
	}
	if !n.lst.resignDue {
		t.Fatal("a failed re-sign left nothing due")
	}
	f.fail = false
	n.maintain(t0.Add(2 * time.Second))
	if n.lst.resignDue || n.recordSeq[target] <= seq {
		t.Fatal("maintenance didn't re-sign after the signer recovered")
	}
}

// counting counts Sign calls.
type counting struct {
	failing
	signs int
}

func (c *counting) Sign(r io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	c.signs++
	return c.failing.Sign(r, msg, opts)
}

// TestListenSignsOnce: one Listen asks the signer once, as a hardware key
// needing a touch per signature would want.
func TestListenSignsOnce(t *testing.T) {
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	c := &counting{failing: failing{k: k}}
	n := New(Config{ID: outsiderID(rng(1)), Rand: rng(2)})
	if err := n.Listen(t0, c); err != nil {
		t.Fatal(err)
	}
	if c.signs != 1 {
		t.Fatalf("%d signatures for one Listen", c.signs)
	}
}
