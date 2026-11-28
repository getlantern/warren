package content

import (
	"bytes"
	"errors"
	"io"
	"runtime"
	"strings"
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
	fresh := NewMemStore()
	s, err = SealTo(fresh, bytes.NewReader(random(t, 3*MinPieceSize)), MinPieceSize)
	if err != nil {
		t.Fatal(err)
	}
	wrong := s.Announce(nil)
	wrong.Key = Key{}
	if err := Read(fresh, wrong, &got); !errors.Is(err, ErrOpen) || got.Len() != 0 {
		t.Fatalf("under the wrong key: %v, %d bytes written", err, got.Len())
	}
}

// TestSealToAborts: a failed seal commits nothing.
func TestSealToAborts(t *testing.T) {
	store := NewMemStore()
	// A full piece put, then the reader fails.
	r := io.MultiReader(bytes.NewReader(random(t, MinPieceSize+1)), errReader{errors.New("boom")})
	if _, err := SealTo(store, r, MinPieceSize); err == nil {
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

// swapStore serves the real piece first, then a substitute for piece 1.
type swapStore struct {
	*MemStore
	sub   []byte
	calls int
}

func (s *swapStore) Get(id ID, i uint32) ([]byte, error) {
	if i == 1 {
		s.calls++
		if s.calls > 1 {
			return s.sub, nil
		}
	}
	return s.MemStore.Get(id, i)
}

// TestReadSubstitution: a piece swapped between Read's passes for another
// that's valid under the blob's key and index fails, not written.
func TestReadSubstitution(t *testing.T) {
	mem := NewMemStore()
	s, err := SealTo(mem, bytes.NewReader(random(t, 3*MinPieceSize)), MinPieceSize)
	if err != nil {
		t.Fatal(err)
	}
	store := &swapStore{MemStore: mem, sub: sealPiece(t, s.Key, 1, random(t, MinPieceSize))}
	var got bytes.Buffer
	if err := Read(store, s.Announce(nil), &got); !errors.Is(err, ErrPiece) {
		t.Fatalf("a substituted piece: %v", err)
	}
	if got.Len() > MinPieceSize {
		t.Fatal("the substitute was written")
	}
}

// TestReadBoundedByStore: an announcement claiming the largest blob costs
// little to refuse when the store has none of it.
func TestReadBoundedByStore(t *testing.T) {
	a := &Announcement{Size: MaxPieces * DefaultPieceSize, PieceSize: DefaultPieceSize}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if err := Read(NewMemStore(), a, io.Discard); !errors.Is(err, ErrNotStored) {
		t.Fatalf("an absent blob: %v", err)
	}
	runtime.ReadMemStats(&after)
	if d := after.TotalAlloc - before.TotalAlloc; d > 1<<20 {
		t.Fatalf("refusing an absent blob allocated %d bytes", d)
	}
}

// abortFails is a store whose writers fail to abort.
type abortFails struct{ *MemStore }

func (s abortFails) Create() (BlobWriter, error) {
	w, err := s.MemStore.Create()
	return failingAbort{w}, err
}

type failingAbort struct{ BlobWriter }

func (failingAbort) Abort() error { return errors.New("abort failed") }

// TestSealToAbortError: a failed seal that can't abort says so.
func TestSealToAbortError(t *testing.T) {
	boom := errors.New("boom")
	_, err := SealTo(abortFails{NewMemStore()}, errReader{boom}, MinPieceSize)
	if !errors.Is(err, boom) || err == nil || !strings.Contains(err.Error(), "abort failed") {
		t.Fatalf("an abort failure: %v", err)
	}
}
