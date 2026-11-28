package content

import (
	"errors"
	"fmt"
	"io"
	"sync"
)

// ErrNotStored means a store doesn't hold a blob, or a piece of it.
var ErrNotStored = errors.New("content: not stored")

// Store holds blobs' ciphertext pieces. A blob is written through a
// BlobWriter, since its ID is known only once it's sealed.
type Store interface {
	// Create starts writing a blob.
	Create() (BlobWriter, error)
	// Get returns piece i of blob id (ErrNotStored).
	Get(id ID, i uint32) ([]byte, error)
	// Delete drops blob id, if held.
	Delete(id ID) error
}

// BlobWriter writes one blob into a Store: its pieces in order (Seal's
// put), then Commit under its ID or Abort.
type BlobWriter interface {
	Put(i uint32, piece []byte) error
	Commit(id ID) error
	Abort() error
}

// MemStore is a Store in memory.
type MemStore struct {
	mu    sync.Mutex
	blobs map[ID][][]byte
}

// NewMemStore returns an empty MemStore.
func NewMemStore() *MemStore { return &MemStore{blobs: map[ID][][]byte{}} }

// Create starts writing a blob.
func (s *MemStore) Create() (BlobWriter, error) { return &memWriter{s: s}, nil }

// Get returns piece i of blob id.
func (s *MemStore) Get(id ID, i uint32) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.blobs[id]
	if !ok || int(i) >= len(b) {
		return nil, ErrNotStored
	}
	return append([]byte(nil), b[i]...), nil
}

// Delete drops blob id.
func (s *MemStore) Delete(id ID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.blobs, id)
	return nil
}

type memWriter struct {
	s      *MemStore
	pieces [][]byte
	done   bool
}

func (w *memWriter) Put(i uint32, piece []byte) error {
	if w.done || int(i) != len(w.pieces) {
		return errors.New("content: piece out of order")
	}
	w.pieces = append(w.pieces, piece)
	return nil
}

func (w *memWriter) Commit(id ID) error {
	if w.done {
		return errors.New("content: blob writer done")
	}
	w.done = true
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	w.s.blobs[id] = w.pieces
	return nil
}

func (w *memWriter) Abort() error {
	w.done, w.pieces = true, nil
	return nil
}

// SealTo seals a blob from r into store (Seal with pieceSize), committing
// it under its ID, or aborting it on any failure; an error aborting is
// joined to the one returned.
func SealTo(store Store, r io.Reader, pieceSize uint32) (*Sealed, error) {
	w, err := store.Create()
	if err != nil {
		return nil, err
	}
	s, err := Seal(r, pieceSize, w.Put)
	if err == nil {
		err = w.Commit(s.ID)
	}
	if err != nil {
		if aerr := w.Abort(); aerr != nil {
			err = errors.Join(err, fmt.Errorf("content: aborting the blob: %w", aerr))
		}
		return nil, err
	}
	return s, nil
}

// Read writes the blob a announces, from store's pieces, to w. It checks
// the whole blob against a's ID before writing any plaintext: every
// piece's length, and the tree they make. Then it opens the pieces in
// order, getting them again, each checked against the leaf verified for
// it: a piece changed in the store since fails rather than writing
// something else, even one valid under the blob's key. Its memory grows
// with the pieces the store has, not the size a claims.
func Read(store Store, a *Announcement, w io.Writer) error {
	n, err := Pieces(a.Size, a.PieceSize)
	if err != nil {
		return err
	}
	var leaves []Hash
	for i := range n {
		p, err := store.Get(a.ID, i)
		if err != nil {
			return err
		}
		if len(p) != PieceLen(a.Size, a.PieceSize, i) {
			return ErrPiece
		}
		leaves = append(leaves, LeafHash(p))
	}
	if BlobID(NewTree(leaves).Root(), a.Size, a.PieceSize) != a.ID {
		return ErrPiece
	}
	for i := range n {
		p, err := store.Get(a.ID, i)
		if err != nil {
			return err
		}
		if LeafHash(p) != leaves[i] {
			return ErrPiece
		}
		pt, err := Open(a.Key, i, p)
		if err != nil {
			return err
		}
		if _, err := w.Write(pt); err != nil {
			return err
		}
	}
	return nil
}
