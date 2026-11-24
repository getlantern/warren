package dht

import (
	"testing"

	"github.com/getlantern/warren/krpc"
)

// benchNode is a full node with a routing table of a few hundred contacts,
// about what a long-running Mainline node holds.
func benchNode(b *testing.B) *Node {
	b.Helper()
	r := rng(7)
	self := outsiderID(r)
	n := New(Config{ID: self})
	// Contacts at every depth: share the first d bits with our ID and
	// differ at bit d, as a node's lookups toward itself fill its table.
	i := 0
	for d := range 24 {
		for range 12 {
			id := outsiderID(r)
			copy(id[:], self[:])
			tail := outsiderID(r)
			for bit := d; bit < 160; bit++ {
				mask := byte(0x80 >> (bit % 8))
				if bit == d {
					id[bit/8] ^= mask // differ at bit d
				} else {
					id[bit/8] = id[bit/8]&^mask | tail[bit/8]&mask
				}
			}
			n.primary.heard(id, addr(i), t0)
			i++
		}
	}
	if n.primary.len() < 100 {
		b.Fatalf("table holds only %d contacts", n.primary.len())
	}
	return n
}

func benchServe(b *testing.B, m krpc.Msg) {
	n := benchNode(b)
	from := addr(9999)
	m.T, m.Y, m.V = []byte("aa"), krpc.Query, []byte("LT\x02\x11")
	data := krpc.AppendMarshal(nil, &m)
	b.ReportAllocs()
	for b.Loop() {
		n.HandlePacket(t0, from, data)
		n.Drain()
	}
}

// Answering a find_node: decode, find the closest contacts, encode.
func BenchmarkServeFindNode(b *testing.B) {
	target := outsiderID(rng(11))
	benchServe(b, krpc.Msg{Q: "find_node", A: krpc.Args{ID: outsiderID(rng(12)), Target: &target}})
}

// Answering a get_peers, which also mints a write token.
func BenchmarkServeGetPeers(b *testing.B) {
	target := outsiderID(rng(13))
	benchServe(b, krpc.Msg{Q: "get_peers", A: krpc.Args{ID: outsiderID(rng(14)), InfoHash: &target}})
}

func BenchmarkTableClosest(b *testing.B) {
	n := benchNode(b)
	target := outsiderID(rng(15))
	b.ReportAllocs()
	for b.Loop() {
		_ = n.primary.closest(target, 8)
	}
}
