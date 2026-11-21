package dht

import (
	"crypto/sha1"
	"math/rand/v2"
	"net/netip"
	"testing"
	"time"

	"github.com/getlantern/warren/krpc"
	"github.com/getlantern/warren/overlay"
)

var (
	t0  = time.Unix(1_800_000_000, 0)
	key = overlay.NewKey("fa")
)

func rng(seed uint64) *rand.Rand { return rand.New(rand.NewPCG(seed, seed)) }

func addr(i int) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{5, byte(i >> 8), byte(i), 1}), 6881)
}

func memberID(r *rand.Rand, ip netip.Addr) krpc.NodeID {
	var id krpc.NodeID
	for i := range id {
		id[i] = byte(r.Uint32())
	}
	return key.Tag(krpc.SecureID(ip, id))
}

func outsiderID(r *rand.Rand) krpc.NodeID {
	var id krpc.NodeID
	for i := range id {
		id[i] = byte(r.Uint32())
	}
	return id
}

func query(t *testing.T, n *Node, from netip.AddrPort, m krpc.Msg) *krpc.Msg {
	t.Helper()
	m.T, m.Y = []byte("aa"), krpc.Query
	n.HandlePacket(t0, from, krpc.AppendMarshal(nil, &m))
	sends, _ := n.Drain()
	for _, s := range sends {
		var r krpc.Msg
		if s.To == from && krpc.Unmarshal(s.Data, &r) == nil && r.Y != krpc.Query {
			return &r
		}
	}
	return nil
}

// Members get community referrals; everyone else gets Mainline referrals, so
// the community is never revealed to an outsider.
func TestTwoPersonalities(t *testing.T) {
	r := rng(1)
	hub := New(Config{ID: memberID(r, addr(0).Addr()), Community: &key, Rand: rng(2)})
	members, outsiders := map[krpc.NodeID]bool{}, map[krpc.NodeID]bool{}
	for i := 1; i <= 20; i++ {
		a := addr(i)
		if i%2 == 0 {
			id := memberID(r, a.Addr())
			members[id] = true
			hub.comm.heard(id, a, t0)
		} else {
			id := outsiderID(r)
			outsiders[id] = true
			hub.main.heard(id, a, t0)
		}
	}
	target := outsiderID(r)

	asMember := query(t, hub, addr(100), krpc.Msg{Q: "find_node", A: krpc.Args{ID: memberID(r, addr(100).Addr()), Target: &target}})
	asOutsider := query(t, hub, addr(101), krpc.Msg{Q: "find_node", A: krpc.Args{ID: outsiderID(r), Target: &target}})
	if asMember == nil || asOutsider == nil {
		t.Fatal("no response")
	}
	if len(asMember.R.Nodes) == 0 || len(asOutsider.R.Nodes) == 0 {
		t.Fatalf("empty referrals: member %d outsider %d", len(asMember.R.Nodes), len(asOutsider.R.Nodes))
	}
	for _, ni := range asMember.R.Nodes {
		if !members[ni.ID] {
			t.Errorf("member was referred a non-member %s", ni.ID)
		}
	}
	for _, ni := range asOutsider.R.Nodes {
		if !outsiders[ni.ID] {
			t.Errorf("outsider was referred community node %s", ni.ID)
		}
	}
	if !asOutsider.IP.IsValid() || asOutsider.IP != addr(101) {
		t.Errorf("response ip field = %v", asOutsider.IP)
	}
}

func TestReadOnlyNeverAnswers(t *testing.T) {
	n := New(Config{ID: outsiderID(rng(3)), ReadOnly: true, Rand: rng(4)})
	if r := query(t, n, addr(1), krpc.Msg{Q: "ping", A: krpc.Args{ID: outsiderID(rng(5))}}); r != nil {
		t.Fatalf("read-only node answered: %+v", r)
	}
}

func TestPutRequiresToken(t *testing.T) {
	n := New(Config{ID: outsiderID(rng(6)), Rand: rng(7)})
	from := addr(9)
	v := ImmutableValue([]byte("hello"))
	bad := query(t, n, from, krpc.Msg{Q: "put", A: krpc.Args{ID: outsiderID(rng(8)), Token: []byte("nope"), V: v}})
	if bad == nil || bad.E == nil || bad.E.Code != krpc.ErrProtocol {
		t.Fatalf("bad token: %+v", bad)
	}
	target := outsiderID(rng(9))
	got := query(t, n, from, krpc.Msg{Q: "get", A: krpc.Args{ID: outsiderID(rng(8)), Target: &target}})
	if len(got.R.Token) != 4 {
		t.Fatalf("token length %d, want 4", len(got.R.Token))
	}
	ok := query(t, n, from, krpc.Msg{Q: "put", A: krpc.Args{ID: outsiderID(rng(8)), Token: got.R.Token, V: v}})
	if ok == nil || ok.Y != krpc.Response {
		t.Fatalf("valid put rejected: %+v", ok)
	}
	stored := krpc.NodeID(sha1.Sum(v))
	back := query(t, n, from, krpc.Msg{Q: "get", A: krpc.Args{ID: outsiderID(rng(8)), Target: &stored}})
	if string(back.R.V) != string(v) {
		t.Fatalf("get returned %q", back.R.V)
	}
}

func TestUnknownMethod(t *testing.T) {
	n := New(Config{ID: outsiderID(rng(10)), Rand: rng(11)})
	r := query(t, n, addr(1), krpc.Msg{Q: "vote", A: krpc.Args{ID: outsiderID(rng(12))}})
	if r == nil || r.E == nil || r.E.Code != krpc.ErrMethodUnknown {
		t.Fatalf("got %+v", r)
	}
}

func TestPrefixDiversity(t *testing.T) {
	r := rng(13)
	self := outsiderID(r)
	tb := newTable(self, 8, false, func(krpc.NodeID, netip.Addr) bool { return true })
	// Ten nodes from one /24, all in the same (farthest) bucket.
	for i := range 10 {
		id := outsiderID(r)
		id[0] = ^self[0]
		tb.heard(id, netip.AddrPortFrom(netip.AddrFrom4([4]byte{9, 9, 9, byte(i + 1)}), 6881), t0)
	}
	if got := len(tb.buckets[0].nodes); got != maxPerIPPrefixBucket {
		t.Fatalf("bucket holds %d from one /24, want %d", got, maxPerIPPrefixBucket)
	}
	// A second identity on an occupied IP is refused.
	id := outsiderID(r)
	tb.heard(id, netip.AddrPortFrom(netip.AddrFrom4([4]byte{9, 9, 9, 1}), 7000), t0)
	if tb.get(id) != nil {
		t.Fatal("second identity admitted on the same IP")
	}
}

func TestCommunityTableRequiresBEP42(t *testing.T) {
	r := rng(14)
	n := New(Config{ID: memberID(r, addr(0).Addr()), Community: &key, Rand: rng(15)})
	a := addr(5)
	wrongIP := memberID(r, netip.MustParseAddr("8.8.8.8"))
	n.comm.heard(wrongIP, a, t0)
	if n.comm.len() != 0 {
		t.Fatal("member ID not bound to its address was admitted")
	}
	n.comm.heard(memberID(r, a.Addr()), a, t0)
	if n.comm.len() != 1 {
		t.Fatal("valid member rejected")
	}
}

// Wire habits verified against libtorrent 2.1.1 by cmd/ltfingerprint.
func TestLibtorrentWireHabits(t *testing.T) {
	n := New(Config{ID: outsiderID(rng(40)), Rand: rng(41)})
	n.Bootstrap(t0, []netip.AddrPort{addr(1), addr(2)})
	sends, _ := n.Drain()
	if len(sends) == 0 {
		t.Fatal("bootstrap sent nothing")
	}
	for _, s := range sends {
		var m krpc.Msg
		if err := krpc.Unmarshal(s.Data, &m); err != nil {
			t.Fatal(err)
		}
		if m.Q != "get_peers" {
			t.Errorf("bootstrap sent %q; libtorrent bootstraps with get_peers", m.Q)
		}
		if string(m.V) != string(DefaultVersion) || len(m.T) != 2 {
			t.Errorf("query v=%q t=%dB; want libtorrent's v and 2-byte t", m.V, len(m.T))
		}
	}
	r := query(t, n, addr(7), krpc.Msg{Q: "ping", A: krpc.Args{ID: outsiderID(rng(42))}})
	if r.R.P != int(addr(7).Port()) || !r.IP.IsValid() || string(r.V) != string(DefaultVersion) {
		t.Errorf("ping response p=%d ip=%v v=%q", r.R.P, r.IP, r.V)
	}
}
