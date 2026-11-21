// Package overlay separates community DHTs (for example, a Farsi DHT) that
// all speak unmodified Mainline KRPC. Membership is carried inside the node ID
// itself: BEP 42 fixes only the first 21 bits and the last byte, so a keyed tag
// in the free middle bytes lets members recognize each other from the "id" that
// every message already carries, while the ID looks like an ordinary random
// BEP 42 ID to anyone without the community key.
//
// The key ships in the app, so a censor who extracts it can check tags too.
// The tag defeats generic DHT fingerprinting and keyless active probing, not a
// censor running a per-community MAC check.
package overlay

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"net/netip"

	"github.com/getlantern/warren/krpc"
)

// Tag layout within the 20-byte ID: bytes 0–2 and 19 are BEP 42, 3–14 are
// random, and 15–18 are the tag over every other byte.
const tagOffset = 15

type Key [32]byte

// NewKey derives a community key from a public label such as "fa".
func NewKey(label string) Key {
	return Key(sha256.Sum256([]byte("warren/overlay/v1\x00" + label)))
}

// tag is SHA-256 over key ‖ id-without-tag. The input length is fixed, so
// length extension does not apply, and a stack buffer keeps it allocation-free
// on the per-packet path.
func (k *Key) tag(id *krpc.NodeID) uint32 {
	var buf [32 + tagOffset + 1]byte
	copy(buf[:], k[:])
	copy(buf[32:], id[:tagOffset])
	buf[len(buf)-1] = id[19]
	sum := sha256.Sum256(buf[:])
	return binary.BigEndian.Uint32(sum[:])
}

// NewID returns a fresh member ID that is also BEP 42 compliant for ip.
func (k *Key) NewID(ip netip.Addr) krpc.NodeID {
	var id krpc.NodeID
	rand.Read(id[:])
	return k.Tag(krpc.SecureID(ip, id))
}

// Tag rewrites id's tag bytes for this community, keeping everything else.
func (k *Key) Tag(id krpc.NodeID) krpc.NodeID {
	binary.BigEndian.PutUint32(id[tagOffset:], k.tag(&id))
	return id
}

// IsMember reports whether id carries this community's tag. A random ID
// passes with probability 2^-32.
func (k *Key) IsMember(id krpc.NodeID) bool {
	return binary.BigEndian.Uint32(id[tagOffset:]) == k.tag(&id)
}
