// Package swarm schedules a blob's fetch from a group's members
// (docs/groups-design.md, *Swarming*): rarest first from their bitfields,
// in order near the playhead when streaming, pipelined per peer to its
// measured throughput, and with work stealing at the end. It does no I/O:
// the caller feeds it what peers hold and send, and asks what to request.
package swarm

import (
	"errors"
	"math/bits"
)

// ErrBitfield means a bitfield's encoding is the wrong length for its
// blob, or sets bits past its last piece.
var ErrBitfield = errors.New("swarm: malformed bitfield")

// Bitfield is a set of a blob's pieces.
type Bitfield struct {
	n uint32
	b []byte
}

// NewBitfield returns an empty bitfield for a blob of n pieces.
func NewBitfield(n uint32) *Bitfield {
	return &Bitfield{n: n, b: make([]byte, (uint64(n)+7)/8)}
}

// Len is the blob's piece count.
func (f *Bitfield) Len() uint32 { return f.n }

// Set adds piece i, which must be below Len.
func (f *Bitfield) Set(i uint32) { f.b[i/8] |= 0x80 >> (i % 8) }

// Has reports whether piece i is in the set; false past Len.
func (f *Bitfield) Has(i uint32) bool { return i < f.n && f.b[i/8]&(0x80>>(i%8)) != 0 }

// Count is how many pieces are in the set.
func (f *Bitfield) Count() uint32 {
	var c int
	for _, x := range f.b {
		c += bits.OnesCount8(x)
	}
	return uint32(c)
}

// Full reports whether every piece is in the set.
func (f *Bitfield) Full() bool { return f.Count() == f.n }

// Clone is a copy of f.
func (f *Bitfield) Clone() *Bitfield {
	return &Bitfield{n: f.n, b: append([]byte(nil), f.b...)}
}

// Encode is f's encoding: piece i is bit 7-i%8 of byte i/8, as in
// BitTorrent, with the spare bits of the last byte zero.
func (f *Bitfield) Encode() []byte { return append([]byte(nil), f.b...) }

// DecodeBitfield decodes a bitfield for a blob of n pieces: exactly its
// length, with no bits past its last piece (ErrBitfield), so an encoding
// is canonical.
func DecodeBitfield(b []byte, n uint32) (*Bitfield, error) {
	if uint64(len(b)) != (uint64(n)+7)/8 {
		return nil, ErrBitfield
	}
	if spare := n % 8; spare != 0 && b[len(b)-1]&(0xff>>spare) != 0 {
		return nil, ErrBitfield
	}
	return &Bitfield{n: n, b: append([]byte(nil), b...)}, nil
}
