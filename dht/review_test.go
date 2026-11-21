package dht

import (
	"crypto/ed25519"
	"net/netip"
	"testing"
	"time"

	"github.com/getlantern/warren/krpc"
)

// Mutable operations on an empty routing table finish synchronously; they
// must still be configured and report completion, not panic.
func TestMutableOpsOnEmptyTable(t *testing.T) {
	n := New(Config{ID: outsiderID(rng(70)), Rand: rng(71)})
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	op, err := n.GetMutable(t0, [32]byte(priv.Public().(ed25519.PublicKey)), nil)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := NewMutable(priv, nil, 1, ImmutableValue([]byte("x")))
	op2, err := n.PutMutable(t0, m, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, events := n.Drain()
	var gotGet, gotPut bool
	for _, e := range events {
		switch e := e.(type) {
		case GetDone:
			gotGet = gotGet || e.Op == op
		case PutDone:
			gotPut = gotPut || e.Op == op2
		}
	}
	if !gotGet || !gotPut {
		t.Fatalf("completion events: get %v put %v", gotGet, gotPut)
	}
}

// Referrals keep IPv4 and IPv6 contacts in their own fields and honor want.
func TestReferralsSplitByFamily(t *testing.T) {
	r := rng(72)
	n := New(Config{ID: outsiderID(r), Rand: rng(73)})
	for i := 1; i <= 6; i++ {
		n.main.heard(outsiderID(r), addr(i), t0)
		n.main.heard(outsiderID(r), netip.AddrPortFrom(netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, byte(i), 15: 1}), 6881), t0)
	}
	target := outsiderID(r)
	check := func(from netip.AddrPort, want []string, v4, v6 bool) {
		t.Helper()
		resp := query(t, n, from, krpc.Msg{Q: "find_node", A: krpc.Args{ID: outsiderID(r), Target: &target, Want: want}})
		for _, ni := range resp.R.Nodes {
			if !ni.Addr.Addr().Unmap().Is4() {
				t.Errorf("IPv6 contact in nodes: %v", ni.Addr)
			}
		}
		for _, ni := range resp.R.Nodes6 {
			if ni.Addr.Addr().Is4() {
				t.Errorf("IPv4 contact in nodes6: %v", ni.Addr)
			}
		}
		if (len(resp.R.Nodes) > 0) != v4 || (len(resp.R.Nodes6) > 0) != v6 {
			t.Errorf("from %v want %v: %d v4, %d v6", from, want, len(resp.R.Nodes), len(resp.R.Nodes6))
		}
	}
	check(addr(100), nil, true, false)
	check(addr(100), []string{"n4", "n6"}, true, true)
	check(netip.MustParseAddrPort("[2001:db8::99]:1"), nil, false, true)
}

// Reflections are ordered by when we first contacted each destination, the
// moment the NAT created its mapping, not by reply arrival, and a reused
// destination is recorded once.
func TestReflectionsOrderedByMappingCreation(t *testing.T) {
	n := New(Config{ID: outsiderID(rng(74)), Rand: rng(75)})
	for i := 1; i <= 3; i++ {
		n.send(t0, addr(i), "ping", krpc.Args{}, &txn{kind: txPing})
	}
	n.reflect(addr(3), netip.MustParseAddrPort("203.0.113.1:1003"), t0)
	n.reflect(addr(1), netip.MustParseAddrPort("203.0.113.1:1001"), t0)
	n.reflect(addr(1), netip.MustParseAddrPort("203.0.113.1:1001"), t0)
	refl := n.Reflections()
	if len(refl) != 2 {
		t.Fatalf("%d reflections, want 2 (one per destination)", len(refl))
	}
	if refl[0].Order != 2 || refl[1].Order != 0 {
		t.Fatalf("orders %d, %d; want creation order 2, 0", refl[0].Order, refl[1].Order)
	}
	n.reflect(addr(9), netip.MustParseAddrPort("203.0.113.1:1009"), t0)
	if got := n.Reflections()[2].Order; got != -1 {
		t.Fatalf("never-contacted destination has order %d, want -1", got)
	}
}

var _ = time.Second

// An offer can arrive through a replica we never adopted (its put ack was
// lost); the answer must still go out, fetching a write token first.
func TestAnswerThroughUnadoptedReplica(t *testing.T) {
	r := rng(80)
	n := New(Config{ID: outsiderID(r), Rand: rng(81)})
	provider := ed25519.NewKeyFromSeed(make([]byte, 32))
	if err := n.Listen(t0, provider); err != nil {
		t.Fatal(err)
	}
	n.Drain()
	var target krpc.NodeID
	for _, tg := range n.lst.records {
		target = tg
	}
	// Build an offer exactly as a caller does.
	e, _ := ecdhX25519(n.randBytes(32))
	shared, _ := e.ECDH(n.lst.x.PublicKey())
	offerKey, _, _ := signalKeys(shared, e.PublicKey().Bytes(), n.lst.x.PublicKey().Bytes())
	sealed := append(e.PublicKey().Bytes(), n.seal(offerKey, []byte("hi"))...)
	caller := ed25519.NewKeyFromSeed(append(make([]byte, 31), 1))
	m, _ := NewMutable(caller, offerSalt(n.randBytes(16), target), t0.Unix(), bencodeBytes(sealed))
	via := addr(42) // not among lst.holders
	if !n.acceptOffer(t0, via, &m) {
		t.Fatal("offer not accepted")
	}
	_, events := n.Drain()
	in, ok := events[0].(Incoming)
	if !ok {
		t.Fatalf("events %+v", events)
	}
	if err := n.Answer(t0, in.Session, []byte("ok")); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	sends, _ := n.Drain()
	var getTID []byte
	for _, s := range sends {
		var q krpc.Msg
		if krpc.Unmarshal(s.Data, &q) == nil && s.To == via && q.Q == "get" {
			getTID = q.T
		}
	}
	if getTID == nil {
		t.Fatal("no token fetch sent to the unadopted replica")
	}
	resp := krpc.Msg{T: getTID, Y: krpc.Response, R: krpc.Return{ID: outsiderID(r), Token: []byte("tokn")}}
	n.HandlePacket(t0, via, krpc.AppendMarshal(nil, &resp))
	sends, _ = n.Drain()
	for _, s := range sends {
		var q krpc.Msg
		if krpc.Unmarshal(s.Data, &q) == nil && s.To == via && q.Q == "put" && string(q.A.Token) == "tokn" {
			return
		}
	}
	t.Fatal("answer not sent after the token arrived")
}

// A second Listen replaces the first identity: its records stop being
// republished.
func TestListenReplacesIdentity(t *testing.T) {
	n := New(Config{ID: outsiderID(rng(82)), Rand: rng(83)})
	a := ed25519.NewKeyFromSeed(make([]byte, 32))
	b := ed25519.NewKeyFromSeed(append(make([]byte, 31), 9))
	n.Listen(t0, a)
	var old krpc.NodeID
	for _, tg := range n.lst.records {
		old = tg
	}
	n.Listen(t0, b)
	if _, ok := n.owned[old]; ok {
		t.Fatal("the replaced identity's record is still published")
	}
	if len(n.owned) != 1 {
		t.Fatalf("%d owned records, want 1", len(n.owned))
	}
}

// buildOffer makes a caller's offer for n's current record.
func buildOffer(t *testing.T, n *Node) *MutableItem {
	t.Helper()
	var target krpc.NodeID
	for _, tg := range n.lst.records {
		target = tg
	}
	e, _ := ecdhX25519(n.randBytes(32))
	shared, _ := e.ECDH(n.lst.x.PublicKey())
	offerKey, _, _ := signalKeys(shared, e.PublicKey().Bytes(), n.lst.x.PublicKey().Bytes())
	sealed := append(e.PublicKey().Bytes(), n.seal(offerKey, []byte("hi"))...)
	m, _ := NewMutable(ed25519.NewKeyFromSeed(append(make([]byte, 31), 1)), offerSalt(n.randBytes(16), target), t0.Unix(), bencodeBytes(sealed))
	return &m
}

// A replayed copy of an offer from another address must not divert the
// answer from the relay the offer first came through.
func TestReplayedOfferDoesNotHijackAnswer(t *testing.T) {
	n := New(Config{ID: outsiderID(rng(84)), Rand: rng(85)})
	n.Listen(t0, ed25519.NewKeyFromSeed(make([]byte, 32)))
	n.Drain()
	m := buildOffer(t, n)
	relay, attacker := addr(50), addr(66)
	n.acceptOffer(t0, relay, m)
	_, events := n.Drain()
	in := events[0].(Incoming)
	for i := range 10 {
		n.acceptOffer(t0, netip.AddrPortFrom(attacker.Addr(), uint16(1000+i)), m) // replays
	}
	if err := n.Answer(t0, in.Session, []byte("ok")); err != nil {
		t.Fatal(err)
	}
	sends, _ := n.Drain()
	toRelay, total := false, 0
	for _, s := range sends {
		total++
		if s.To == relay {
			toRelay = true
		}
	}
	if !toRelay {
		t.Fatal("answer was diverted away from the original relay")
	}
	if total > 1+maxSessionRelays {
		t.Fatalf("answer sent to %d addresses; replays must be capped at %d extra", total, maxSessionRelays)
	}
}

// Replays from unverified addresses must not use up the slots a genuine
// retry through one of our holders needs.
func TestReplaysCannotCrowdOutHolder(t *testing.T) {
	n := New(Config{ID: outsiderID(rng(86)), Rand: rng(87)})
	n.Listen(t0, ed25519.NewKeyFromSeed(make([]byte, 32)))
	n.Drain()
	holderAddr := addr(77)
	var target krpc.NodeID
	for _, tg := range n.lst.records {
		target = tg
	}
	n.lst.holders = append(n.lst.holders, &holder{addr: holderAddr, target: target, token: []byte("htok")})
	m := buildOffer(t, n)
	n.acceptOffer(t0, addr(50), m)
	_, events := n.Drain()
	in := events[0].(Incoming)
	for i := range 10 {
		n.acceptOffer(t0, netip.AddrPortFrom(addr(66).Addr(), uint16(1000+i)), m)
	}
	n.acceptOffer(t0, holderAddr, m) // the caller's genuine retry
	n.Answer(t0, in.Session, []byte("ok"))
	sends, _ := n.Drain()
	for _, s := range sends {
		var q krpc.Msg
		if s.To == holderAddr && krpc.Unmarshal(s.Data, &q) == nil && q.Q == "put" && string(q.A.Token) == "htok" {
			return
		}
	}
	t.Fatal("the holder's retry was crowded out by replays")
}
