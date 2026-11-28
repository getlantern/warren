package content

import (
	"bytes"
	"errors"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// TestSealToRead: a blob sealed into a store reads back whole.
func TestSealToRead(t *testing.T) {
	store := NewMemStore()
	data := random(t, 3*MinPieceSize+11)
	s, err := SealTo(store, bytes.NewReader(data), MinPieceSize)
	if err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	if err := Read(store, s.Announce(nil), &got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), data) {
		t.Fatal("read back differs")
	}
}

// TestReadChecksFirst: a changed or missing piece fails the read before
// any plaintext is written, even a piece after good ones.
func TestReadChecksFirst(t *testing.T) {
	store := NewMemStore()
	s, err := SealTo(store, bytes.NewReader(random(t, 3*MinPieceSize)), MinPieceSize)
	if err != nil {
		t.Fatal(err)
	}
	a := s.Announce(nil)
	store.blobs[s.ID][2][5] ^= 1
	var got bytes.Buffer
	if err := Read(store, a, &got); !errors.Is(err, ErrPiece) || got.Len() != 0 {
		t.Fatalf("a changed last piece: %v, %d bytes written", err, got.Len())
	}
	store.blobs[s.ID][2][5] ^= 1
	store.blobs[s.ID] = store.blobs[s.ID][:2]
	if err := Read(store, a, &got); !errors.Is(err, ErrNotStored) || got.Len() != 0 {
		t.Fatalf("a missing piece: %v, %d bytes written", err, got.Len())
	}
	wrong := *a
	wrong.Key = Key{}
	if err := Read(store, &wrong, &got); err == nil {
		t.Fatal("read under the wrong key")
	}
}

// TestSealToAborts: a failed seal commits nothing.
func TestSealToAborts(t *testing.T) {
	store := NewMemStore()
	if _, err := SealTo(store, errReader{errors.New("boom")}, MinPieceSize); err == nil {
		t.Fatal("sealed a failing reader")
	}
	if len(store.blobs) != 0 {
		t.Fatal("a failed seal left a blob")
	}
}

// TestMemWriter: pieces go in order, and a done writer takes no more.
func TestMemWriter(t *testing.T) {
	store := NewMemStore()
	w, _ := store.Create()
	if err := w.Put(1, nil); err == nil {
		t.Fatal("a piece out of order")
	}
	if err := w.Put(0, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := w.Commit(ID{1}); err != nil {
		t.Fatal(err)
	}
	if err := w.Commit(ID{2}); err == nil {
		t.Fatal("a second commit")
	}
	if _, err := store.Get(ID{1}, 1); !errors.Is(err, ErrNotStored) {
		t.Fatalf("a piece past the end: %v", err)
	}
	if err := store.Delete(ID{1}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ID{1}, 0); !errors.Is(err, ErrNotStored) {
		t.Fatalf("a deleted blob: %v", err)
	}
}

// TestReadMisshapen: an author can name a tree over pieces of the wrong
// lengths; Read refuses it rather than writing a blob of the wrong size.
func TestReadMisshapen(t *testing.T) {
	store := NewMemStore()
	key := Key{9}
	// Two pieces, the first short: each opens, but the blob is 2*MinPieceSize.
	p0 := sealPiece(t, key, 0, random(t, 10))
	p1 := sealPiece(t, key, 1, random(t, MinPieceSize))
	size := uint64(2 * MinPieceSize)
	id := BlobID(NewTree([]Hash{LeafHash(p0), LeafHash(p1)}).Root(), size, MinPieceSize)
	store.blobs[id] = [][]byte{p0, p1}
	var got bytes.Buffer
	if err := Read(store, &Announcement{ID: id, Size: size, PieceSize: MinPieceSize, Key: key}, &got); !errors.Is(err, ErrPiece) || got.Len() != 0 {
		t.Fatalf("a misshapen blob: %v, %d bytes written", err, got.Len())
	}
}

func sealPiece(t *testing.T, key Key, i uint32, pt []byte) []byte {
	t.Helper()
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		t.Fatal(err)
	}
	return aead.Seal(nil, nonce(i), pt, ad)
}
