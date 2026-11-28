package content

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

// seal seals data, returning the result and its ciphertext pieces.
func seal(t testing.TB, data []byte, pieceSize uint32) (*Sealed, [][]byte) {
	t.Helper()
	var pieces [][]byte
	s, err := Seal(bytes.NewReader(data), pieceSize, func(i uint32, p []byte) error {
		if int(i) != len(pieces) {
			t.Fatalf("piece %d handed over as %d", len(pieces), i)
		}
		pieces = append(pieces, p)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return s, pieces
}

func random(t testing.TB, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// TestRoundTrip: every piece of blobs of awkward sizes verifies alone
// against the ID, opens alone, and the pieces make the blob.
func TestRoundTrip(t *testing.T) {
	const ps = MinPieceSize
	for _, size := range []int{0, 1, ps - 1, ps, ps + 1, 2 * ps, 3*ps + 7, 8 * ps, 13*ps + 1} {
		data := random(t, size)
		s, pieces := seal(t, data, ps)
		n, err := Pieces(uint64(size), ps)
		if err != nil {
			t.Fatal(err)
		}
		if s.Size != uint64(size) || len(pieces) != int(n) {
			t.Fatalf("size %d: sealed size %d in %d pieces, want %d", size, s.Size, len(pieces), n)
		}
		var got []byte
		for i, p := range pieces {
			proof, err := s.Tree.Proof(uint32(i))
			if err != nil {
				t.Fatal(err)
			}
			if err := Verify(s.ID, s.Size, s.PieceSize, uint32(i), p, proof); err != nil {
				t.Fatalf("size %d, piece %d: %v", size, i, err)
			}
			pt, err := Open(s.Key, uint32(i), p)
			if err != nil {
				t.Fatalf("size %d, piece %d: %v", size, i, err)
			}
			got = append(got, pt...)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("size %d: the pieces don't make the blob", size)
		}
	}
}

// TestDefaultPieceSize: 0 means DefaultPieceSize, and bad sizes are
// refused.
func TestDefaultPieceSize(t *testing.T) {
	s, _ := seal(t, random(t, 10), 0)
	if s.PieceSize != DefaultPieceSize {
		t.Fatalf("piece size %d", s.PieceSize)
	}
	for _, ps := range []uint32{MinPieceSize / 2, MaxPieceSize * 2, MinPieceSize + 1} {
		if _, err := Seal(bytes.NewReader(nil), ps, func(uint32, []byte) error { return nil }); !errors.Is(err, ErrPieceSize) {
			t.Fatalf("piece size %d: %v", ps, err)
		}
	}
}

// TestFreshKeys: the same plaintext sealed twice gets two keys and two IDs.
func TestFreshKeys(t *testing.T) {
	data := random(t, 100)
	a, _ := seal(t, data, MinPieceSize)
	b, _ := seal(t, data, MinPieceSize)
	if a.Key == b.Key || a.ID == b.ID {
		t.Fatal("the same plaintext sealed twice shares a key or an ID")
	}
}

// TestVerifyRefuses: a piece checked as anything but itself fails.
func TestVerifyRefuses(t *testing.T) {
	const ps = MinPieceSize
	s, pieces := seal(t, random(t, 5*ps+3), ps)
	proof := func(i uint32) []Hash {
		p, err := s.Tree.Proof(i)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	tampered := append([]byte(nil), pieces[2]...)
	tampered[7] ^= 1
	other, otherPieces := seal(t, random(t, 5*ps+3), ps)
	cases := map[string]error{
		"tampered":     Verify(s.ID, s.Size, ps, 2, tampered, proof(2)),
		"wrong index":  Verify(s.ID, s.Size, ps, 3, pieces[2], proof(2)),
		"wrong proof":  Verify(s.ID, s.Size, ps, 2, pieces[2], proof(3)),
		"short proof":  Verify(s.ID, s.Size, ps, 2, pieces[2], proof(2)[1:]),
		"long proof":   Verify(s.ID, s.Size, ps, 2, pieces[2], append(proof(2), Hash{})),
		"no proof":     Verify(s.ID, s.Size, ps, 2, pieces[2], nil),
		"index past":   Verify(s.ID, s.Size, ps, 6, pieces[2], proof(2)),
		"other blob":   Verify(s.ID, s.Size, ps, 2, otherPieces[2], proof(2)),
		"other id":     Verify(other.ID, s.Size, ps, 2, pieces[2], proof(2)),
		"truncated":    Verify(s.ID, 4*ps, ps, 2, pieces[2], proof(2)),
		"extended":     Verify(s.ID, 6*ps, ps, 2, pieces[2], proof(2)),
		"size off":     Verify(s.ID, s.Size+1, ps, 2, pieces[2], proof(2)),
		"last cut":     Verify(s.ID, s.Size, ps, 5, pieces[5][:len(pieces[5])-1], proof(5)),
		"piece size":   Verify(s.ID, s.Size, 2*ps, 2, pieces[2], proof(2)),
		"bad piece sz": Verify(s.ID, s.Size, ps+1, 2, pieces[2], proof(2)),
	}
	for name, err := range cases {
		if err == nil {
			t.Errorf("%s: verified", name)
		}
	}
	if _, err := s.Tree.Proof(6); err == nil {
		t.Fatal("a proof for a piece past the end")
	}
}

// TestOpenRefuses: a piece opens only under its own key and index.
func TestOpenRefuses(t *testing.T) {
	s, pieces := seal(t, random(t, 3*MinPieceSize), MinPieceSize)
	if _, err := Open(s.Key, 1, pieces[0]); !errors.Is(err, ErrOpen) {
		t.Fatalf("under the wrong index: %v", err)
	}
	var k Key
	if _, err := Open(k, 0, pieces[0]); !errors.Is(err, ErrOpen) {
		t.Fatalf("under the wrong key: %v", err)
	}
}

// TestTreeShape: proofs are about log2(n) hashes for many leaf counts, and
// every leaf's proof rebuilds the root; the root matches a direct RFC 6962
// computation.
func TestTreeShape(t *testing.T) {
	for n := 1; n <= 40; n++ {
		leaves := make([]Hash, n)
		for i := range leaves {
			leaves[i] = LeafHash([]byte{byte(i), byte(n)})
		}
		tr := NewTree(leaves)
		if tr.Root() != mth(leaves) {
			t.Fatalf("n=%d: root differs from RFC 6962's", n)
		}
		for i := range n {
			p, err := tr.Proof(uint32(i))
			if err != nil {
				t.Fatal(err)
			}
			if len(p) > 6 {
				t.Fatalf("n=%d: a proof of %d hashes", n, len(p))
			}
			root, ok := rootFrom(uint32(i), uint32(n), leaves[i], p)
			if !ok || root != tr.Root() {
				t.Fatalf("n=%d, leaf %d: the proof doesn't rebuild the root", n, i)
			}
		}
	}
}

// mth is RFC 6962's Merkle tree hash, computed directly.
func mth(d []Hash) Hash {
	if len(d) == 1 {
		return d[0]
	}
	k := split(uint32(len(d)))
	return node(mth(d[:k]), mth(d[k:]))
}

// TestSealErrors: put's error and a reader's are returned.
func TestSealErrors(t *testing.T) {
	boom := errors.New("boom")
	if _, err := Seal(bytes.NewReader(random(t, 10)), MinPieceSize, func(uint32, []byte) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("put's error: %v", err)
	}
	if _, err := Seal(errReader{boom}, MinPieceSize, func(uint32, []byte) error { return nil }); !errors.Is(err, boom) {
		t.Fatalf("the reader's error: %v", err)
	}
}

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

// TestPieces: counts at the edges, and MaxPieces.
func TestPieces(t *testing.T) {
	for _, c := range []struct {
		size uint64
		want uint32
	}{{0, 1}, {1, 1}, {MinPieceSize, 1}, {MinPieceSize + 1, 2}, {MaxPieces * MinPieceSize, MaxPieces}} {
		if n, err := Pieces(c.size, MinPieceSize); err != nil || n != c.want {
			t.Fatalf("size %d: %d, %v", c.size, n, err)
		}
	}
	if _, err := Pieces(MaxPieces*MinPieceSize+1, MinPieceSize); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("past MaxPieces: %v", err)
	}
}

// TestAnnouncement: an announcement round-trips; impossible ones are
// refused either way, as is anything malformed.
func TestAnnouncement(t *testing.T) {
	s, _ := seal(t, random(t, 3*MinPieceSize), MinPieceSize)
	a := s.Announce([]byte(`{"title":"x"}`))
	b, err := a.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeAnnouncement(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != a.ID || got.Size != a.Size || got.PieceSize != a.PieceSize || got.Key != a.Key || !bytes.Equal(got.Meta, a.Meta) {
		t.Fatalf("round trip: %+v", got)
	}
	if _, err := (&Announcement{Size: 1, PieceSize: 3}).Encode(); !errors.Is(err, ErrAnnouncement) {
		t.Fatalf("an impossible blob: %v", err)
	}
	if _, err := (&Announcement{Size: 1, PieceSize: MinPieceSize, Meta: make([]byte, MaxMeta+1)}).Encode(); !errors.Is(err, ErrAnnouncement) {
		t.Fatalf("meta past MaxMeta: %v", err)
	}
	bad := map[string][]byte{
		"short":      b[:announceHeader-1],
		"version":    append([]byte{2}, b[1:]...),
		"piece size": func() []byte { c := append([]byte(nil), b...); c[44] = 1; return c }(),
		"too large":  func() []byte { c := append([]byte(nil), b...); c[33] = 0xff; return c }(),
		"meta over":  append(append([]byte(nil), b[:announceHeader]...), make([]byte, MaxMeta+1)...),
	}
	for name, enc := range bad {
		if _, err := DecodeAnnouncement(enc); !errors.Is(err, ErrAnnouncement) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(b) > announceHeader+MaxMeta {
		t.Fatal("an encoding over a log entry's body")
	}
}

func FuzzVerify(f *testing.F) {
	s, pieces := seal(f, random(f, 3*MinPieceSize+5), MinPieceSize)
	p, err := s.Tree.Proof(1)
	if err != nil {
		f.Fatal(err)
	}
	var flat []byte
	for _, h := range p {
		flat = append(flat, h[:]...)
	}
	f.Add(uint64(s.Size), uint32(1), pieces[1], flat)
	f.Fuzz(func(t *testing.T, size uint64, i uint32, piece, proofBytes []byte) {
		var proof []Hash
		for len(proofBytes) >= 32 {
			proof = append(proof, Hash(proofBytes[:32]))
			proofBytes = proofBytes[32:]
		}
		if Verify(s.ID, size, MinPieceSize, i, piece, proof) == nil && (size != s.Size || i >= 4 || !bytes.Equal(piece, pieces[i])) {
			t.Fatal("a piece verified as something it isn't")
		}
	})
}

func FuzzDecodeAnnouncement(f *testing.F) {
	s, _ := seal(f, random(f, 10), MinPieceSize)
	b, err := s.Announce([]byte("meta")).Encode()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	f.Fuzz(func(t *testing.T, b []byte) {
		a, err := DecodeAnnouncement(b)
		if err != nil {
			return
		}
		again, err := a.Encode()
		if err != nil || !bytes.Equal(again, b) {
			t.Fatal("a decoded announcement doesn't encode back to its bytes")
		}
	})
}

// TestIDBindsPieceSize: a one-piece blob claimed under a larger piece size
// has the same piece count and lengths, so only the ID tells them apart.
func TestIDBindsPieceSize(t *testing.T) {
	s, pieces := seal(t, random(t, 100), MinPieceSize)
	proof, err := s.Tree.Proof(0)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(s.ID, s.Size, 2*MinPieceSize, 0, pieces[0], proof); err == nil {
		t.Fatal("verified under another piece size")
	}
}

// TestDomains: a node's hash isn't the leaf hash of its children's bytes,
// so an inner node can't pass for a piece.
func TestDomains(t *testing.T) {
	l, r := LeafHash([]byte("l")), LeafHash([]byte("r"))
	if node(l, r) == LeafHash(append(l[:], r[:]...)) {
		t.Fatal("a node hashes like a leaf of its children")
	}
}

// TestMisshapenBlob: an author can name a tree over pieces of the wrong
// lengths (a short middle piece); they don't verify, so no one fetches
// or opens a blob of the wrong size.
func TestMisshapenBlob(t *testing.T) {
	const ps = MinPieceSize
	short := random(t, 100) // piece 0 of a two-piece blob should be ps+16
	full := random(t, ps+16)
	tr := NewTree([]Hash{LeafHash(short), LeafHash(full)})
	size := uint64(2 * ps)
	id := BlobID(tr.Root(), size, ps)
	proof, err := tr.Proof(0)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(id, size, ps, 0, short, proof); !errors.Is(err, ErrPiece) {
		t.Fatalf("a short middle piece: %v", err)
	}
}
