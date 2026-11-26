package keys

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"filippo.io/edwards25519"
)

func id(t *testing.T, b byte) *Identity {
	t.Helper()
	return IdentityFromSeed([32]byte{b})
}

func TestIdentityMatchesStdlib(t *testing.T) {
	seed := [32]byte{1, 2, 3}
	ours := IdentityFromSeed(seed)
	std := ed25519.NewKeyFromSeed(seed[:])
	if pub := ours.Public(); !bytes.Equal(pub[:], std.Public().(ed25519.PublicKey)) {
		t.Fatal("public key differs from crypto/ed25519")
	}
	for _, msg := range [][]byte{nil, []byte("x"), bytes.Repeat([]byte("m"), 1000)} {
		got, want := ours.Sign(msg), ed25519.Sign(std, msg)
		if !bytes.Equal(got, want) {
			t.Fatalf("signature of %d bytes differs from crypto/ed25519", len(msg))
		}
		if !ours.Public().Verify(msg, got) {
			t.Fatalf("PublicKey.Verify rejects the member's own signature of %d bytes", len(msg))
		}
	}
}

func TestBlindedSignerVerifiesUnderStdlib(t *testing.T) {
	var g Secret
	g[0] = 7
	alice := id(t, 1)
	for p := uint64(0); p < 3; p++ {
		s := alice.Rendezvous(g, p)
		want, err := Rendezvous(g, p, alice.Public())
		if err != nil {
			t.Fatal(err)
		}
		if s.Public() != want {
			t.Fatalf("period %d: signer's key %x, computed from the roster %x", p, s.Public(), want)
		}
		msg := []byte("offer")
		sig := s.Sign(msg)
		if !ed25519.Verify(want[:], msg, sig) {
			t.Fatalf("period %d: crypto/ed25519 rejects the blinded signature", p)
		}
		if !want.Verify(msg, sig) {
			t.Fatalf("period %d: PublicKey.Verify rejects the blinded signature", p)
		}
		if want.Valid() != nil {
			t.Fatalf("period %d: Valid rejects an honest rendezvous key", p)
		}
		if alice.Public().Verify(msg, sig) {
			t.Fatal("a blinded signature verifies under the member key")
		}
	}
}

func TestRendezvousRotatesAndSeparates(t *testing.T) {
	var g, h Secret
	g[0], h[0] = 1, 2
	alice, bob := id(t, 1).Public(), id(t, 2).Public()
	seen := map[PublicKey]string{}
	for _, c := range []struct {
		name string
		g    Secret
		p    uint64
		m    PublicKey
	}{
		{"alice g p0", g, 0, alice}, {"alice g p1", g, 1, alice},
		{"bob g p0", g, 0, bob}, {"alice h p0", h, 0, alice},
	} {
		k, err := Rendezvous(c.g, c.p, c.m)
		if err != nil {
			t.Fatal(err)
		}
		if k == c.m {
			t.Fatalf("%s: rendezvous key is the member key", c.name)
		}
		if prev, dup := seen[k]; dup {
			t.Fatalf("%s and %s share a rendezvous key", c.name, prev)
		}
		seen[k] = c.name
	}
}

// order8 is a point of order 8; its multiples are all eight small-order
// points.
const order8 = "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"

func TestBlindRejectsSmallOrderKeys(t *testing.T) {
	b, _ := hex.DecodeString(order8)
	T, err := new(edwards25519.Point).SetBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	honest, err := new(edwards25519.Point).SetBytes(func() []byte { k := id(t, 1).Public(); return k[:] }())
	if err != nil {
		t.Fatal(err)
	}
	m := edwards25519.NewIdentityPoint()
	for i := 1; i <= 8; i++ {
		m = new(edwards25519.Point).Add(m, T) // i·T
		small := PublicKey(m.Bytes())
		if _, err := small.Blind([32]byte{1}); err != ErrBadKey {
			t.Fatalf("blinding %d·T: %v", i, err)
		}
		if _, err := small.X25519(); err != ErrBadKey {
			t.Fatalf("converting %d·T: %v", i, err)
		}
		if i == 8 {
			break // 8·T is the identity: honest + 8·T is honest itself
		}
		mixed := PublicKey(new(edwards25519.Point).Add(honest, m).Bytes())
		if _, err := mixed.Blind([32]byte{1}); err != ErrBadKey {
			t.Fatalf("blinding an honest key plus %d·T: %v", i, err)
		}
	}
	// Find an encoding that isn't a point (about half of all y values).
	var notOnCurve PublicKey
	for y := byte(2); ; y++ {
		notOnCurve[0] = y
		if _, err := new(edwards25519.Point).SetBytes(notOnCurve[:]); err != nil {
			break
		}
	}
	// y+p, for p = 2^255-19, encodes the same point as y: find a small y
	// that is a point (y < 19, so adding p's low byte 0xed doesn't carry).
	found := false
	for y := byte(2); y < 19; y++ {
		if _, err := new(edwards25519.Point).SetBytes(append([]byte{y}, make([]byte, 31)...)); err != nil {
			continue
		}
		nonCanonical := PublicKey{0xed + y}
		for i := 1; i < 31; i++ {
			nonCanonical[i] = 0xff
		}
		nonCanonical[31] = 0x7f
		if _, err := new(edwards25519.Point).SetBytes(nonCanonical[:]); err != nil {
			t.Fatalf("y=%d+p didn't decode", y)
		}
		if _, err := nonCanonical.Blind([32]byte{1}); err != ErrBadKey {
			t.Fatalf("blinding a non-canonical encoding of y=%d: %v", y, err)
		}
		found = true
		break
	}
	if !found {
		t.Fatal("no small y is a point")
	}
	if _, err := notOnCurve.Blind([32]byte{1}); err != ErrBadKey {
		t.Fatalf("blinding a non-point: %v", err)
	}
}

func TestSealOpen(t *testing.T) {
	alice, bob := id(t, 1), id(t, 2)
	box, err := Seal(alice.Public(), "op 1", []byte("G and epoch key"))
	if err != nil {
		t.Fatal(err)
	}
	if len(box) != len("G and epoch key")+Overhead {
		t.Fatalf("box is %d bytes", len(box))
	}
	pt, err := alice.Open("op 1", box)
	if err != nil || string(pt) != "G and epoch key" {
		t.Fatalf("open: %q, %v", pt, err)
	}
	if _, err := bob.Open("op 1", box); err != ErrOpen {
		t.Fatalf("another member opened it: %v", err)
	}
	if _, err := alice.Open("op 2", box); err != ErrOpen {
		t.Fatalf("opened for another context: %v", err)
	}
	for _, i := range []int{0, 31, 32, len(box) - 1} {
		bad := bytes.Clone(box)
		bad[i] ^= 1
		if _, err := alice.Open("op 1", bad); err != ErrOpen {
			t.Fatalf("opened with byte %d flipped: %v", i, err)
		}
	}
	if _, err := alice.Open("op 1", box[:Overhead-1]); err != ErrOpen {
		t.Fatalf("opened a short box: %v", err)
	}
	low := bytes.Clone(box)
	copy(low[:32], make([]byte, 32)) // the all-zero, low-order X25519 point
	if _, err := alice.Open("op 1", low); err != ErrOpen {
		t.Fatalf("opened with a low-order ephemeral key: %v", err)
	}
}

// sealedVector is a box Seal made to IdentityFromSeed({0xa1}) for context
// "vector". Seal is randomized, so this fixture pins the sealing KDF (its
// label and salt order) and the AEAD: a change that would leave existing
// boxes unreadable fails to open it.
const sealedVector = "e634a90f163a54dafe822ff859695d86b6c3c526c89ccd53651489e20254064b5745995a9656c23341c07cd2cd0acfd0bf725636a22da26fedecfff47489a9"

func TestSealedVectorOpens(t *testing.T) {
	box, _ := hex.DecodeString(sealedVector)
	pt, err := IdentityFromSeed([32]byte{0xa1}).Open("vector", box)
	if err != nil || string(pt) != "warren group v1" {
		t.Fatalf("the pinned box doesn't open: %q, %v", pt, err)
	}
}

func TestSealFreshEphemeral(t *testing.T) {
	to := id(t, 1).Public()
	a, err := Seal(to, "c", []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Seal(to, "c", []byte("x"))
	if bytes.Equal(a[:32], b[:32]) {
		t.Fatal("two seals shared an ephemeral key, so they reuse a key and nonce")
	}
}

func TestVerifyRejectsSmallOrderKeys(t *testing.T) {
	// Under the identity point A, R = r·B and S = r verify for any message,
	// since the challenge term c·A vanishes.
	identity := PublicKey(edwards25519.NewIdentityPoint().Bytes())
	sig := append(edwards25519.NewGeneratorPoint().Bytes(), append([]byte{1}, make([]byte, 31)...)...)
	if !ed25519.Verify(identity[:], []byte("anything"), sig) {
		t.Fatal("the forgery doesn't fool crypto/ed25519; the test is stale")
	}
	if identity.Verify([]byte("anything"), sig) {
		t.Fatal("Verify accepted a forged signature under a small-order key")
	}
	if identity.Valid() != ErrBadKey {
		t.Fatal("Valid accepted the identity point")
	}
}

func TestX25519Agrees(t *testing.T) {
	alice, bob := id(t, 1), id(t, 2)
	ap, err := alice.Public().X25519()
	if err != nil {
		t.Fatal(err)
	}
	bp, err := bob.Public().X25519()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(alice.X25519().PublicKey().Bytes(), ap.Bytes()) {
		t.Fatal("the identity's X25519 key doesn't match its converted public key")
	}
	s1, _ := alice.X25519().ECDH(bp)
	s2, _ := bob.X25519().ECDH(ap)
	if !bytes.Equal(s1, s2) {
		t.Fatal("ECDH disagrees")
	}
}

func TestDerivationsSeparate(t *testing.T) {
	var g Secret
	g[0] = 9
	dk, ds, b0, b1 := g.DirKey(), g.DirSeal(), g.Blind(0), g.Blind(1)
	all := map[[32]byte]string{dk: "dirKey", ds: "dirSeal"}
	for name, k := range map[string][32]byte{"blind0": b0, "blind1": b1, "invite": InviteBlind([32]byte(g), 0)} {
		if prev, dup := all[k]; dup {
			t.Fatalf("%s equals %s", name, prev)
		}
		all[k] = name
	}
	if bytes.Equal(g.DirectoryKey(0), g.DirectoryKey(1)) {
		t.Fatal("the directory key doesn't change with the period")
	}
	if bytes.Equal(g.DirectorySalt(0, 0), g.DirectorySalt(0, 1)) || bytes.Equal(g.DirectorySalt(0, 0), g.DirectorySalt(1, 0)) {
		t.Fatal("directory salts repeat across shards or periods")
	}
	callee, err := Rendezvous(g, 0, id(t, 1).Public())
	if err != nil {
		t.Fatal(err)
	}
	if g.SyncKey(0, callee).Public() == g.SyncKey(1, callee).Public() {
		t.Fatal("the sync key doesn't change with the period")
	}
	if CommitSecret(g) == CommitEpoch(EpochKey(g)) {
		t.Fatal("the secret and epoch commitments aren't domain-separated")
	}
}

func TestPeriodOf(t *testing.T) {
	t0 := time.Unix(3600*10, 0)
	if PeriodOf(t0) != 10 || PeriodOf(t0.Add(Period-time.Second)) != 10 || PeriodOf(t0.Add(Period)) != 11 {
		t.Fatal("periods aren't hour-aligned")
	}
	if PeriodOf(time.Time{}) != 0 || PeriodOf(time.Unix(-1, 0)) != 0 {
		t.Fatal("a time before 1970 isn't period 0")
	}
}

// TestVectors pins every derivation and a blinded signature, so a change to
// any of them, which would split groups across versions, fails here first.
func TestVectors(t *testing.T) {
	var g Secret
	for i := range g {
		g[i] = byte(i)
	}
	const p = 480000
	alice := IdentityFromSeed([32]byte{0xa1})
	rk, err := Rendezvous(g, p, alice.Public())
	if err != nil {
		t.Fatal(err)
	}
	h := func(b []byte) string { return hex.EncodeToString(b) }
	dk, ds, bl, ib := g.DirKey(), g.DirSeal(), g.Blind(p), InviteBlind([32]byte(g), p)
	cs, ce := CommitSecret(g), CommitEpoch(EpochKey(g))
	sk := g.SyncKey(p, rk).Public()
	got := map[string]string{
		"dirKey":        h(dk[:]),
		"dirSeal":       h(ds[:]),
		"blind":         h(bl[:]),
		"inviteBlind":   h(ib[:]),
		"directoryKey":  h(g.DirectoryKey(p).Public().(ed25519.PublicKey)),
		"directorySalt": h(g.DirectorySalt(p, 2)),
		"syncKey":       h(sk[:]),
		"commitSecret":  h(cs[:]),
		"commitEpoch":   h(ce[:]),
		"rendezvous":    h(rk[:]),
		"blindedSig":    h(alice.Rendezvous(g, p).Sign([]byte("offer"))),
	}
	if len(got) != len(vectors) {
		t.Fatalf("%d derivations computed, %d pinned", len(got), len(vectors))
	}
	for name, v := range got {
		if v != vectors[name] {
			t.Errorf("%s: got %s, want %s", name, v, vectors[name])
		}
	}
}

var vectors = map[string]string{
	"blind":         "bfe08ce5e4ae646682b168e172aab5e16b5c3a3b8e06c3a3ab098f49941256cf",
	"blindedSig":    "45130509cc9f98390a4369aae32c388005d3f0b675b342616c476565c747653d7616b6349fa58f9042db2ec1529d4ca01a77ebea0219148c117838b8db2d6402",
	"commitEpoch":   "b2acfd01c93871d0bda777ae0dbf38e8d446e43ef8d1606c747666f21f679618",
	"commitSecret":  "b43337f890d5f0432cd455847c8d74b6c161c8aa12af64943f5a300672c643d1",
	"dirKey":        "fe24261c48e9010943ccab872c994acf29b10f0d621f75d9e736d32a3832ba6d",
	"directoryKey":  "108c23109b45690ffe685641d9be326b996116e18e4419952a5d697d0d453610",
	"directorySalt": "20e9f81331a3c0f510cf237556ed8febc35e936b058855d8de37192d9e85fb27",
	"inviteBlind":   "2ea2e387e7862c70d005d3ff14189ed7fe6b27e108136efaed66501c0a2b5fb6",
	"rendezvous":    "50cbbb712d4836024b79035eae267e03a8afc0458bd9935e07f19bda7c62470d",
	"syncKey":       "62a33e1c5af2ea4eb1a7a900776614f9413f5638f5e66e0c5aed75f49fd9a0b6",
	"dirSeal":       "9dfd19a3317a929dc2bb2f763e5f14ef53ab663ecad3635134db608f4fc20fd2",
}

func TestCryptoSigner(t *testing.T) {
	id := IdentityFromSeed([32]byte{3})
	var g Secret
	g[0] = 1
	b := id.Rendezvous(g, 9)
	cs := CryptoSigner(b)
	pk := cs.Public().(ed25519.PublicKey)
	if [32]byte(pk) != [32]byte(b.Public()) {
		t.Fatal("the adapter names another key")
	}
	sig, err := cs.Sign(nil, []byte("msg"), crypto.Hash(0))
	if err != nil || !ed25519.Verify(pk, []byte("msg"), sig) {
		t.Fatalf("a blinded signature through the adapter: %v", err)
	}
	if _, err := cs.Sign(nil, make([]byte, 32), crypto.SHA256); err == nil {
		t.Fatal("signed a digest")
	}
	// A TLS certificate, as hy2 makes one, under the blinded key.
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, cs.Public(), cs)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil || c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) != nil {
		t.Fatalf("a self-signed certificate under the blinded key: %v", err)
	}
}

func TestCryptoSignerRefusesContext(t *testing.T) {
	cs := CryptoSigner(IdentityFromSeed([32]byte{4}))
	if _, err := cs.Sign(nil, []byte("m"), &ed25519.Options{Context: "warren"}); err == nil {
		t.Fatal("signed with an Ed25519ctx context as pure Ed25519")
	}
	if _, err := cs.Sign(nil, []byte("m"), &ed25519.Options{}); err != nil {
		t.Fatalf("pure Ed25519 options: %v", err)
	}
}

func TestCryptoSignerOptionEdges(t *testing.T) {
	if CryptoSigner(nil) != nil {
		t.Fatal("an adapter around no signer")
	}
	cs := CryptoSigner(IdentityFromSeed([32]byte{5}))
	if _, err := cs.Sign(nil, []byte("m"), (*ed25519.Options)(nil)); err != nil {
		t.Fatalf("a nil *ed25519.Options: %v", err)
	}
	if _, err := cs.Sign(nil, make([]byte, 64), &ed25519.Options{Hash: crypto.SHA512}); err == nil {
		t.Fatal("signed Ed25519ph")
	}
}
