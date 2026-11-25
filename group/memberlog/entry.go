// Package memberlog is each group member's append-only log: entries
// numbered from 1, each naming the hash of the one before and signed by the
// member's key, so a log can't be forked or rewritten undetected, and each
// encrypted under the epoch key current when it was written
// (docs/groups-design.md, *Logs*).
package memberlog

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/getlantern/warren/bencode"
	"github.com/getlantern/warren/group/keys"
	"github.com/getlantern/warren/group/roster"
)

// ID names an entry: the SHA-256 of its signed encoding.
type ID [32]byte

// Kind is what an entry carries, inside its encryption.
type Kind uint8

const (
	// App is opaque bytes the library stores and hands to the app in order:
	// a chat message, a comment, a reaction.
	App Kind = iota + 1
	// Blob announces a blob (*Content*); the library acts on it.
	Blob
)

// MaxBody bounds an entry's plaintext body.
const MaxBody = 64 << 10

// maxEntryBytes bounds an entry's encoding: the body, its sealing, and the
// header and signature with room to spare.
const maxEntryBytes = MaxBody + 1024

var (
	// ErrMalformed means an encoding isn't a well-formed, canonical entry.
	ErrMalformed = errors.New("memberlog: malformed entry")
	// ErrSignature means an entry's signature doesn't verify.
	ErrSignature = errors.New("memberlog: bad signature")
	// ErrOpen means an entry didn't decrypt under the key given.
	ErrOpen = errors.New("memberlog: entry didn't decrypt")
)

// Entry is one signed, encrypted log entry.
type Entry struct {
	Group  roster.ID
	Author keys.PublicKey
	Seq    uint64 // from 1
	Prev   ID     // the previous entry's ID; zero for the first
	// Epoch names the roster operation that made the epoch key the entry
	// is encrypted under.
	Epoch roster.ID
	Nonce [chacha20poly1305.NonceSizeX]byte
	Box   []byte // the sealed kind and body
	Sig   []byte
	id    ID
}

// clone is a deep copy.
func (e *Entry) clone() *Entry {
	c := *e
	c.Box = bytes.Clone(e.Box)
	c.Sig = bytes.Clone(e.Sig)
	return &c
}

// ID returns the entry's ID, valid once it is signed or decoded.
func (e *Entry) ID() ID { return e.id }

func str(b []byte) bencode.Value                  { return bencode.Value{Kind: bencode.String, Str: b} }
func num(n int64) bencode.Value                   { return bencode.Value{Kind: bencode.Int, Int: n} }
func pair(k string, v bencode.Value) bencode.Pair { return bencode.Pair{Key: []byte(k), Value: v} }

func (e *Entry) encode(withSig bool) []byte {
	d := []bencode.Pair{
		pair("a", str(e.Author[:])),
		pair("b", str(e.Box)),
		pair("e", str(e.Epoch[:])),
		pair("g", str(e.Group[:])),
		pair("n", str(e.Nonce[:])),
		pair("s", num(int64(e.Seq))),
	}
	if e.Seq > 1 {
		d = append(d, pair("p", str(e.Prev[:])))
	}
	if withSig {
		d = append(d, pair("z", str(e.Sig)))
	}
	return bencode.Append(nil, bencode.Value{Kind: bencode.Dict, Dict: d})
}

// Encode returns the signed entry's encoding.
func (e *Entry) Encode() []byte { return e.encode(true) }

func (e *Entry) signed() []byte {
	return append([]byte("warren/group/v1 log entry "), e.encode(false)...)
}

// header is what the entry's sealing authenticates besides its body: every
// field but the box and signature, so a box can't be moved to another entry.
func (e *Entry) header() []byte {
	b := append([]byte("warren/group/v1 log box "), e.Group[:]...)
	b = append(b, e.Author[:]...)
	b = binary.BigEndian.AppendUint64(b, e.Seq)
	b = append(b, e.Prev[:]...)
	return append(b, e.Epoch[:]...)
}

// Write makes the next entry of author's log after prev (nil for the
// first), encrypted under the epoch key that epoch made.
func Write(author *keys.Identity, group roster.ID, prev *Entry, epoch roster.ID, key keys.EpochKey, kind Kind, body []byte) (*Entry, error) {
	if kind != App && kind != Blob {
		return nil, ErrMalformed
	}
	if len(body) > MaxBody {
		return nil, ErrMalformed
	}
	e := &Entry{Group: group, Author: author.Public(), Seq: 1, Epoch: epoch}
	if prev != nil {
		if prev.Author != e.Author || prev.Group != group {
			return nil, ErrMalformed
		}
		if prev.Seq == 0 || prev.Seq >= math.MaxInt64 {
			return nil, ErrMalformed // not an entry, or its successor couldn't be encoded
		}
		e.Seq, e.Prev = prev.Seq+1, prev.id
	}
	if _, err := rand.Read(e.Nonce[:]); err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, err
	}
	e.Box = aead.Seal(nil, e.Nonce[:], append([]byte{byte(kind)}, body...), e.header())
	e.Sig = author.Sign(e.signed())
	e.id = sha256.Sum256(e.Encode())
	return e, nil
}

// Open decrypts the entry under the epoch key its Epoch names.
func (e *Entry) Open(key keys.EpochKey) (Kind, []byte, error) {
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return 0, nil, err
	}
	pt, err := aead.Open(nil, e.Nonce[:], e.Box, e.header())
	if err != nil || len(pt) == 0 || (Kind(pt[0]) != App && Kind(pt[0]) != Blob) {
		return 0, nil, ErrOpen
	}
	return Kind(pt[0]), pt[1:], nil
}

// Decode parses and verifies an entry: canonical, with a usable author key,
// signed by its author.
func Decode(b []byte) (*Entry, error) {
	if len(b) > maxEntryBytes {
		return nil, ErrMalformed
	}
	v, err := bencode.Decode(b)
	if err != nil || v.Kind != bencode.Dict {
		return nil, ErrMalformed
	}
	e := &Entry{}
	fixed := func(dst []byte, val bencode.Value) bool {
		if val.Kind != bencode.String || len(val.Str) != len(dst) {
			return false
		}
		copy(dst, val.Str)
		return true
	}
	for _, p := range v.Dict {
		val, ok := p.Value, false
		switch string(p.Key) {
		case "a":
			ok = fixed(e.Author[:], val)
		case "b":
			ok = val.Kind == bencode.String && len(val.Str) >= 1+chacha20poly1305.Overhead &&
				len(val.Str) <= MaxBody+1+chacha20poly1305.Overhead
			e.Box = bytes.Clone(val.Str)
		case "e":
			ok = fixed(e.Epoch[:], val)
		case "g":
			ok = fixed(e.Group[:], val)
		case "n":
			ok = fixed(e.Nonce[:], val)
		case "p":
			ok = fixed(e.Prev[:], val)
		case "s":
			ok = val.Kind == bencode.Int && val.Int >= 1
			e.Seq = uint64(val.Int)
		case "z":
			ok = val.Kind == bencode.String
			e.Sig = bytes.Clone(val.Str)
		}
		if !ok {
			return nil, ErrMalformed
		}
	}
	if !bytes.Equal(e.Encode(), b) {
		return nil, ErrMalformed // non-canonical, a missing field, or a prev on entry 1
	}
	if e.Author.Valid() != nil {
		return nil, ErrMalformed
	}
	if !e.Author.Verify(e.signed(), e.Sig) {
		return nil, ErrSignature
	}
	e.id = sha256.Sum256(b)
	return e, nil
}
