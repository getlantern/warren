// Package content seals blobs for a group (docs/groups-design.md,
// *Content*): a blob is encrypted under a random per-blob key in
// fixed-size pieces, each decryptable alone, and named by a BLAKE3 tree
// over the ciphertext pieces, so any piece can be served and checked
// against the blob's ID without the rest. Its author announces it in its
// log with an Announcement.
package content

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/bits"

	"github.com/zeebo/blake3"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// DefaultPieceSize is the piece size Seal uses for 0.
	DefaultPieceSize = 256 << 10
	// MinPieceSize and MaxPieceSize bound a piece size, which is a power
	// of two.
	MinPieceSize = 16 << 10
	MaxPieceSize = 4 << 20
	// MaxPieces bounds a blob's pieces: 4 TiB at the default piece size.
	MaxPieces = 1 << 24
)

var (
	// ErrPieceSize means a piece size isn't a power of two within
	// MinPieceSize and MaxPieceSize.
	ErrPieceSize = errors.New("content: bad piece size")
	// ErrTooLarge means a blob would have more than MaxPieces pieces.
	ErrTooLarge = errors.New("content: blob too large")
	// ErrPiece means a piece doesn't verify against the blob's ID: wrong
	// index, length, bytes or proof.
	ErrPiece = errors.New("content: piece doesn't verify")
	// ErrOpen means a piece didn't decrypt under the key given.
	ErrOpen = errors.New("content: piece didn't decrypt")
)

// ID names a blob: a hash over its tree's root, size and piece size.
type ID [32]byte

// Key is a blob's encryption key.
type Key [32]byte

// Hash is a node of a blob's tree.
type Hash [32]byte

var (
	leafHasher = blake3.NewDeriveKey("warren group blob leaf 1")
	nodeHasher = blake3.NewDeriveKey("warren group blob node 1")
	idHasher   = blake3.NewDeriveKey("warren group blob id 1")
	// ad binds a piece's sealing to this format.
	ad = []byte("warren-blob:1")
)

func sum(proto *blake3.Hasher, parts ...[]byte) (h Hash) {
	d := proto.Clone()
	for _, p := range parts {
		_, _ = d.Write(p)
	}
	d.Sum(h[:0])
	return h
}

// LeafHash is a ciphertext piece's leaf in its blob's tree.
func LeafHash(piece []byte) Hash { return sum(leafHasher, piece) }

func node(l, r Hash) Hash { return sum(nodeHasher, l[:], r[:]) }

// BlobID names the blob whose tree has root, of size bytes in pieces of
// pieceSize: the size is bound in, so a blob can't be cut short or added
// to and keep its ID.
func BlobID(root Hash, size uint64, pieceSize uint32) ID {
	var b [12]byte
	binary.BigEndian.PutUint64(b[:8], size)
	binary.BigEndian.PutUint32(b[8:], pieceSize)
	return ID(sum(idHasher, root[:], b[:]))
}

// CheckPieceSize reports whether pieceSize is a power of two within
// MinPieceSize and MaxPieceSize (ErrPieceSize).
func CheckPieceSize(pieceSize uint32) error {
	if pieceSize < MinPieceSize || pieceSize > MaxPieceSize || pieceSize&(pieceSize-1) != 0 {
		return fmt.Errorf("%w: %d", ErrPieceSize, pieceSize)
	}
	return nil
}

// Pieces returns how many pieces a blob of size bytes has in pieces of
// pieceSize: at least one, as an empty blob is one empty piece.
func Pieces(size uint64, pieceSize uint32) (uint32, error) {
	if err := CheckPieceSize(pieceSize); err != nil {
		return 0, err
	}
	n := size / uint64(pieceSize) // rounded up below: no overflow near MaxUint64
	if size%uint64(pieceSize) != 0 || n == 0 {
		n++
	}
	if n > MaxPieces {
		return 0, ErrTooLarge
	}
	return uint32(n), nil
}

// PieceLen returns the length of piece i's ciphertext in a blob of size
// bytes in pieces of pieceSize, which must be valid for it.
func PieceLen(size uint64, pieceSize uint32, i uint32) int {
	plain := uint64(pieceSize)
	if rest := size - uint64(i)*uint64(pieceSize); rest < plain {
		plain = rest
	}
	return int(plain) + chacha20poly1305.Overhead
}

func nonce(i uint32) []byte {
	n := make([]byte, chacha20poly1305.NonceSizeX)
	binary.LittleEndian.PutUint32(n, i)
	return n
}

// Sealed is a blob Seal produced: what announcing it takes, and its tree
// for serving pieces.
type Sealed struct {
	ID        ID
	Size      uint64
	PieceSize uint32
	Key       Key
	Tree      *Tree
}

// Seal reads a blob from r to its end and encrypts it under a fresh key in
// pieces of pieceSize (DefaultPieceSize for 0), handing each ciphertext
// piece to put in order; put may keep the slice. It holds one piece and
// the tree's hashes, not the blob.
func Seal(r io.Reader, pieceSize uint32, put func(i uint32, piece []byte) error) (*Sealed, error) {
	if pieceSize == 0 {
		pieceSize = DefaultPieceSize
	}
	if err := CheckPieceSize(pieceSize); err != nil {
		return nil, err
	}
	s := &Sealed{PieceSize: pieceSize}
	if _, err := rand.Read(s.Key[:]); err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(s.Key[:])
	if err != nil {
		return nil, err
	}
	buf := make([]byte, pieceSize)
	var leaves []Hash
	for i := uint32(0); ; i++ {
		n, last, err := fill(r, buf)
		if err != nil {
			return nil, err
		}
		if n == 0 && i > 0 {
			break // the previous piece was full and ended the blob
		}
		if i >= MaxPieces {
			return nil, ErrTooLarge
		}
		piece := aead.Seal(nil, nonce(i), buf[:n], ad)
		if err := put(i, piece); err != nil {
			return nil, err
		}
		leaves = append(leaves, LeafHash(piece))
		s.Size += uint64(n)
		if last {
			break
		}
	}
	s.Tree = NewTree(leaves)
	s.ID = BlobID(s.Tree.Root(), s.Size, s.PieceSize)
	return s, nil
}

// fill reads into buf until it's full or r ends: last reports an io.EOF
// from r, and any other error is returned. Unlike io.ReadFull, a reader's
// own io.ErrUnexpectedEOF (a truncated gzip stream, say) is an error, not
// the blob's end.
func fill(r io.Reader, buf []byte) (n int, last bool, err error) {
	for n < len(buf) {
		m, err := r.Read(buf[n:])
		n += m
		if err == io.EOF {
			return n, true, nil
		}
		if err != nil {
			return n, false, err
		}
	}
	return n, false, nil
}

// Open decrypts piece i of a blob sealed under key (ErrOpen). Verify the
// piece first: Open doesn't check it belongs to a blob.
func Open(key Key, i uint32, piece []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, nonce(i), piece, ad)
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}

// Verify checks that piece is piece i of blob id, of size bytes in pieces
// of pieceSize, by its proof (Tree.Proof).
func Verify(id ID, size uint64, pieceSize uint32, i uint32, piece []byte, proof []Hash) error {
	n, err := Pieces(size, pieceSize)
	if err != nil {
		return err
	}
	if i >= n || len(piece) != PieceLen(size, pieceSize, i) {
		return ErrPiece
	}
	root, ok := rootFrom(i, n, LeafHash(piece), proof)
	if !ok || BlobID(root, size, pieceSize) != id {
		return ErrPiece
	}
	return nil
}

// rootFrom computes the root of an n-leaf tree from leaf m and its proof,
// whose last hash is the sibling nearest the root.
func rootFrom(m, n uint32, leaf Hash, proof []Hash) (Hash, bool) {
	if n == 1 {
		return leaf, len(proof) == 0
	}
	if len(proof) == 0 {
		return Hash{}, false
	}
	sib, rest := proof[len(proof)-1], proof[:len(proof)-1]
	k := split(n)
	if m < k {
		l, ok := rootFrom(m, k, leaf, rest)
		return node(l, sib), ok
	}
	r, ok := rootFrom(m-k, n-k, leaf, rest)
	return node(sib, r), ok
}

// split is the size of an n-leaf tree's left subtree: the largest power of
// two below n (RFC 6962's tree shape).
func split(n uint32) uint32 { return 1 << (bits.Len32(n-1) - 1) }

// Tree is a blob's tree over its ciphertext pieces' leaves, holding every
// complete aligned subtree's hash (about two hashes a piece), so a proof
// takes O(log² n) hashing.
type Tree struct {
	// levels[j][i] hashes leaves [i<<j, (i+1)<<j), where complete.
	levels [][]Hash
	n      uint32
}

// NewTree builds the tree over leaves (LeafHash of each ciphertext piece,
// in order); there is at least one.
func NewTree(leaves []Hash) *Tree {
	t := &Tree{levels: [][]Hash{leaves}, n: uint32(len(leaves))}
	for lv := leaves; len(lv) > 1; {
		up := make([]Hash, len(lv)/2)
		for i := range up {
			up[i] = node(lv[2*i], lv[2*i+1])
		}
		t.levels = append(t.levels, up)
		lv = up
	}
	return t
}

// Root is the tree's root.
func (t *Tree) Root() Hash { return t.hash(0, t.n) }

// hash is the tree hash of leaves [start, start+size).
func (t *Tree) hash(start, size uint32) Hash {
	if size&(size-1) == 0 && start%size == 0 {
		j := bits.TrailingZeros32(size)
		return t.levels[j][start>>j]
	}
	k := split(size)
	return node(t.hash(start, k), t.hash(start+k, size-k))
}

// Proof returns piece i's proof, for Verify.
func (t *Tree) Proof(i uint32) ([]Hash, error) {
	if i >= t.n {
		return nil, ErrPiece
	}
	var proof []Hash
	start, size, m := uint32(0), t.n, i
	var path []Hash // root first, reversed at the end
	for size > 1 {
		k := split(size)
		if m < k {
			path = append(path, t.hash(start+k, size-k))
			size = k
		} else {
			path = append(path, t.hash(start, k))
			start, size, m = start+k, size-k, m-k
		}
	}
	for j := len(path) - 1; j >= 0; j-- {
		proof = append(proof, path[j])
	}
	return proof, nil
}
