package krpc

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"testing"
)

// Vectors from BEP 42. Only the first 21 bits and the last byte are defined.
func TestSecureIDVectors(t *testing.T) {
	for _, tc := range []struct{ ip, id string }{
		{"124.31.75.21", "5fbfbff10c5d6a4ec8a88e4c6ab4c28b95eee401"},
		{"21.75.31.124", "5a3ce9c14e7a08645677bbd1cfe7d8f956d53256"},
		{"65.23.51.170", "a5d43220bc8f112a3d426c84764f8c2a1150e616"},
		{"84.124.73.14", "1b0321dd1bb1fe518101ceef99462b947a01ff41"},
		{"43.213.53.83", "e56f6cbf5b7c4be0237986d5243b87aa6d51305a"},
	} {
		ip := netip.MustParseAddr(tc.ip)
		raw, _ := hex.DecodeString(tc.id)
		want := NodeID(raw)
		if !IsSecureID(ip, want) {
			t.Errorf("%s: spec ID not accepted", tc.ip)
		}
		var seed NodeID
		seed[19] = want[19]
		got := SecureID(ip, seed)
		if got[0] != want[0] || got[1] != want[1] || got[2]&0xf8 != want[2]&0xf8 {
			t.Errorf("%s: SecureID prefix = %x, want %x", tc.ip, got[:3], want[:3])
		}
		bad := want
		bad[0] ^= 0x80
		if IsSecureID(ip, bad) {
			t.Errorf("%s: tampered ID accepted", tc.ip)
		}
	}
}

// Example messages from BEP 5, re-encoded byte for byte.
func TestBEP5Examples(t *testing.T) {
	for _, in := range []string{
		"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe",
		"d1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re",
		"d1:ad2:id20:abcdefghij01234567896:target20:mnopqrstuvwxyz123456e1:q9:find_node1:t2:aa1:y1:qe",
		"d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe",
		"d1:ad2:id20:abcdefghij012345678912:implied_porti1e9:info_hash20:mnopqrstuvwxyz1234564:porti6881e5:token8:aoeusnthe1:q13:announce_peer1:t2:aa1:y1:qe",
		"d1:eli201e23:A Generic Error Ocurrede1:t2:aa1:y1:ee",
	} {
		var m Msg
		if err := Unmarshal([]byte(in), &m); err != nil {
			t.Fatalf("Unmarshal(%q): %v", in, err)
		}
		if out := AppendMarshal(nil, &m); string(out) != in {
			t.Errorf("round trip:\n got %q\nwant %q", out, in)
		}
	}
}

func TestResponseWithNodesAndIP(t *testing.T) {
	seq := int64(7)
	m := Msg{
		T: []byte{0, 1}, Y: Response, V: []byte("LT\x01\x02"),
		IP: netip.MustParseAddrPort("203.0.113.9:40000"),
		R: Return{
			ID:     NodeID{1},
			Nodes:  []NodeInfo{{ID: NodeID{2}, Addr: netip.MustParseAddrPort("198.51.100.1:6881")}},
			Nodes6: []NodeInfo{{ID: NodeID{3}, Addr: netip.MustParseAddrPort("[2001:db8::1]:6881")}},
			Values: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.5:51413")},
			Token:  []byte("tok"),
			V:      []byte("5:hello"),
			Seq:    &seq,
		},
	}
	enc := AppendMarshal(nil, &m)
	var got Msg
	if err := Unmarshal(enc, &got); err != nil {
		t.Fatal(err)
	}
	if got.IP != m.IP || got.R.Nodes[0] != m.R.Nodes[0] || got.R.Nodes6[0] != m.R.Nodes6[0] ||
		got.R.Values[0] != m.R.Values[0] || !bytes.Equal(got.R.V, m.R.V) || *got.R.Seq != seq {
		t.Errorf("round trip mismatch: %+v", got)
	}
	if again := AppendMarshal(nil, &got); !bytes.Equal(again, enc) {
		t.Errorf("re-encode differs:\n%q\n%q", again, enc)
	}
}

func TestReadOnlyFlag(t *testing.T) {
	m := Msg{T: []byte("aa"), Y: Query, Q: "ping", RO: true}
	enc := AppendMarshal(nil, &m)
	if !bytes.Contains(enc, []byte("2:roi1e")) {
		t.Fatalf("missing ro: %q", enc)
	}
	var got Msg
	if err := Unmarshal(enc, &got); err != nil || !got.RO {
		t.Fatalf("ro lost: %v %+v", err, got)
	}
}

func TestRejectsMissingID(t *testing.T) {
	var m Msg
	if err := Unmarshal([]byte("d1:ad6:target20:mnopqrstuvwxyz123456e1:q9:find_node1:t2:aa1:y1:qe"), &m); err == nil {
		t.Error("query without id accepted")
	}
}

func FuzzUnmarshal(f *testing.F) {
	f.Add([]byte("d1:rd2:id20:mnopqrstuvwxyz1234565:nodes26:abcdefghij0123456789\x01\x02\x03\x04\x1a\xe1e1:t2:aa1:y1:re"))
	f.Fuzz(func(t *testing.T, b []byte) {
		var m Msg
		if Unmarshal(b, &m) != nil {
			return
		}
		var m2 Msg
		if err := Unmarshal(AppendMarshal(nil, &m), &m2); err != nil {
			t.Fatalf("re-decode: %v", err)
		}
	})
}
