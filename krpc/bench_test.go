package krpc

import (
	"net/netip"
	"testing"
)

func benchID(seed byte) NodeID {
	var id NodeID
	for i := range id {
		id[i] = seed + byte(i)*31
	}
	return id
}

// A find_node response with 8 nodes, the commonest datagram a DHT node
// receives during a lookup.
func benchResponse() []byte {
	m := Msg{T: []byte("aa"), Y: Response, V: []byte("LT\x02\x11"),
		IP: netip.MustParseAddrPort("203.0.113.7:6881"), R: Return{ID: benchID(1), Token: []byte("tokentok")}}
	for i := range 8 {
		m.R.Nodes = append(m.R.Nodes, NodeInfo{ID: benchID(byte(10 + i)), Addr: netip.AddrPortFrom(netip.AddrFrom4([4]byte{5, byte(i), 1, 1}), 6881)})
	}
	return AppendMarshal(nil, &m)
}

func benchQuery() []byte {
	target := benchID(2)
	return AppendMarshal(nil, &Msg{T: []byte("aa"), Y: Query, Q: "get_peers", V: []byte("LT\x02\x11"), A: Args{ID: benchID(3), InfoHash: &target}})
}

func BenchmarkUnmarshalResponse8Nodes(b *testing.B) {
	data := benchResponse()
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	for b.Loop() {
		var m Msg
		if err := Unmarshal(data, &m); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUnmarshalQuery(b *testing.B) {
	data := benchQuery()
	b.ReportAllocs()
	for b.Loop() {
		var m Msg
		if err := Unmarshal(data, &m); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMarshalResponse8Nodes(b *testing.B) {
	var m Msg
	if err := Unmarshal(benchResponse(), &m); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		_ = AppendMarshal(nil, &m)
	}
}
