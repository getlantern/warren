package dht

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/getlantern/warren/krpc"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Test vectors from BEP 44.
func TestBEP44Vectors(t *testing.T) {
	pub := [32]byte(unhex(t, "77ff84905a91936367c01360803104f92432fcd904a43511876df5cdf3e7e548"))
	v := []byte("12:Hello World!")
	for _, tc := range []struct {
		salt, sig, target string
	}{
		{"", "305ac8aeb6c9c151fa120f120ea2cfb923564e11552d06a5d856091e5e853cff1260d3f39e4999684aa92eb73ffd136e6f4f3ecbfda0ce53a1608ecd7ae21f01",
			"4a533d47ec9c7d95b1ad75f576cffc641853b750"},
		{"foobar", "6834284b6b24c3204eb2fea824d82f88883a3d95e8b4a21b8c0ded553d17d17ddf9a8a7104b1258f30bed3787e6cb896fca78c58f8e03b5f18f14951a87d9a08",
			"411eba73b6f087ca51a3795d9c8c938d365e32c1"},
	} {
		m := MutableItem{Key: pub, Salt: []byte(tc.salt), Seq: 1, V: v, Sig: [64]byte(unhex(t, tc.sig))}
		if !m.Verify() {
			t.Errorf("salt %q: spec signature does not verify", tc.salt)
		}
		if got := m.Target(); hex.EncodeToString(got[:]) != tc.target {
			t.Errorf("salt %q: target %x, want %s", tc.salt, got, tc.target)
		}
		m.Seq = 2
		if m.Verify() {
			t.Errorf("salt %q: signature verified for the wrong seq", tc.salt)
		}
	}
}

func TestSignAndVerify(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	m, err := NewMutable(priv, []byte("s"), 5, ImmutableValue([]byte("hi")))
	if err != nil || !m.Verify() {
		t.Fatalf("fresh item invalid: %v", err)
	}
	m.V = ImmutableValue([]byte("ho"))
	if m.Verify() {
		t.Fatal("tampered value verified")
	}
	if _, err := NewMutable(priv, make([]byte, 65), 1, []byte("0:")); err == nil {
		t.Fatal("oversized salt accepted")
	}
}

func mutablePut(t *testing.T, n *Node, m MutableItem, cas *int64) *krpc.Msg {
	t.Helper()
	from := addr(9)
	target := m.Target()
	tok := query(t, n, from, krpc.Msg{Q: "get", A: krpc.Args{ID: outsiderID(rng(30)), Target: &target}}).R.Token
	a := m.args()
	a.ID, a.Token, a.CAS = outsiderID(rng(30)), tok, cas
	return query(t, n, from, krpc.Msg{Q: "put", A: a})
}

func TestMutableStorageRules(t *testing.T) {
	n := New(Config{ID: outsiderID(rng(31)), Rand: rng(32)})
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	salt := []byte("inbox")
	mk := func(seq int64, s string) MutableItem {
		m, _ := NewMutable(priv, salt, seq, ImmutableValue([]byte(s)))
		return m
	}
	code := func(r *krpc.Msg) int {
		if r.E != nil {
			return r.E.Code
		}
		return 0
	}

	if c := code(mutablePut(t, n, mk(2, "two"), nil)); c != 0 {
		t.Fatalf("first put rejected: %d", c)
	}
	forged := mk(3, "three")
	forged.V = ImmutableValue([]byte("evil"))
	if c := code(mutablePut(t, n, forged, nil)); c != ErrCodeBadSignature {
		t.Errorf("forged put: code %d, want %d", c, ErrCodeBadSignature)
	}
	if c := code(mutablePut(t, n, mk(1, "one"), nil)); c != ErrCodeSeqTooLow {
		t.Errorf("older seq: code %d, want %d", c, ErrCodeSeqTooLow)
	}
	if c := code(mutablePut(t, n, mk(2, "different"), nil)); c != ErrCodeSeqTooLow {
		t.Errorf("same seq, different value: code %d, want %d", c, ErrCodeSeqTooLow)
	}
	wrong := int64(7)
	if c := code(mutablePut(t, n, mk(3, "three"), &wrong)); c != ErrCodeCASMismatch {
		t.Errorf("bad CAS: code %d, want %d", c, ErrCodeCASMismatch)
	}
	right := int64(2)
	if c := code(mutablePut(t, n, mk(3, "three"), &right)); c != 0 {
		t.Errorf("good CAS rejected: %d", c)
	}

	target := MutableTarget([32]byte(priv.Public().(ed25519.PublicKey)), salt)
	got := query(t, n, addr(9), krpc.Msg{Q: "get", A: krpc.Args{ID: outsiderID(rng(33)), Target: &target}})
	m, ok := mutableFromReturn(&got.R, salt)
	if !ok || m.Seq != 3 || !m.Verify() {
		t.Fatalf("get returned %+v", got.R)
	}
	// A reader that already has seq 3 gets only the sequence number back.
	have := int64(3)
	short := query(t, n, addr(9), krpc.Msg{Q: "get", A: krpc.Args{ID: outsiderID(rng(33)), Target: &target, Seq: &have}})
	if short.R.V != nil || short.R.Seq == nil || *short.R.Seq != 3 {
		t.Errorf("seq-limited get returned v=%q seq=%v", short.R.V, short.R.Seq)
	}
}
