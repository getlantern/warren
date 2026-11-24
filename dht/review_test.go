package dht

import (
	"crypto/ed25519"
	"net/netip"
	"testing"
	"time"

	"github.com/getlantern/warren/krpc"
	"github.com/getlantern/warren/overlay"
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

// Re-listening with the same key in the same second must not re-sign the
// record at the same sequence number with a new value: storage nodes reject
// that (BEP 44 error 302) and keep the stale key.
func TestRelistenAdvancesSequence(t *testing.T) {
	n := New(Config{ID: outsiderID(rng(88)), Rand: rng(89)})
	k := ed25519.NewKeyFromSeed(make([]byte, 32))
	seqOf := func() (krpc.NodeID, int64, string) {
		for _, tg := range n.lst.records {
			o := n.owned[tg]
			return tg, o.rec.mut.Seq, string(o.rec.mut.V)
		}
		t.Fatal("no record")
		return krpc.NodeID{}, 0, ""
	}
	n.Listen(t0, k)
	t1, s1, v1 := seqOf()
	n.Listen(t0, k)
	t2, s2, v2 := seqOf()
	if t1 != t2 {
		t.Fatal("same key and epoch should give the same record target")
	}
	if v1 == v2 {
		t.Fatal("expected a fresh signaling key in the second record")
	}
	if s2 <= s1 {
		t.Fatalf("re-listen reused seq %d (was %d) with a different value", s2, s1)
	}
}

// Pruning the sequence table must never forget a live record's number that
// is still ahead of the clock. The record at risk is a different one from
// the record whose signing triggers the prune: here the previous epoch's.
func TestRecordSeqPruneKeepsLiveEntries(t *testing.T) {
	n := New(Config{ID: outsiderID(rng(90)), Rand: rng(91)})
	n.Listen(t0, ed25519.NewKeyFromSeed(make([]byte, 32)))
	var epoch int64
	for e := range n.lst.records {
		epoch = e
	}
	prev := n.signRecord(t0, epoch-1)
	for range 5 {
		n.signRecord(t0, epoch-1) // several re-signs in one second: ahead of the clock
	}
	ahead := n.recordSeq[prev]
	for i := range 2 * maxRecordSeqs { // stale entries fill the table
		n.recordSeq[krpc.NodeID{byte(i), byte(i >> 8), 0xee}] = t0.Unix() - 100
	}
	n.signRecord(t0, epoch) // triggers the prune
	n.signRecord(t0, epoch-1)
	if got := n.recordSeq[prev]; got <= ahead {
		t.Fatalf("previous-epoch record re-signed at seq %d, not above its live %d", got, ahead)
	}
	if len(n.recordSeq) > maxRecordSeqs {
		t.Fatalf("table not pruned: %d entries", len(n.recordSeq))
	}
}

// With per-family nodes paired as siblings, a query that wants the other
// family is answered from the sibling's table, as libtorrent does, and the
// community and Mainline personalities stay apart.
func TestSiblingAnswersForeignFamily(t *testing.T) {
	r := rng(76)
	v4 := New(Config{ID: outsiderID(r), Rand: rng(77)})
	v6 := New(Config{ID: outsiderID(r), Rand: rng(78)})
	v4.SetSibling(v6)
	v6.SetSibling(v4)
	for i := 1; i <= 6; i++ {
		v4.main.heard(outsiderID(r), addr(i), t0)
		v6.main.heard(outsiderID(r), netip.AddrPortFrom(netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, byte(i), 15: 1}), 6881), t0)
	}
	target := outsiderID(r)
	resp := query(t, v4, addr(100), krpc.Msg{Q: "find_node", A: krpc.Args{ID: outsiderID(r), Target: &target, Want: []string{"n4", "n6"}}})
	if len(resp.R.Nodes) == 0 || len(resp.R.Nodes6) == 0 {
		t.Fatalf("v4 node answered %d v4 and %d v6 referrals, want both", len(resp.R.Nodes), len(resp.R.Nodes6))
	}
	resp = query(t, v6, netip.MustParseAddrPort("[2001:db8::99]:1"), krpc.Msg{Q: "find_node", A: krpc.Args{ID: outsiderID(r), Target: &target, Want: []string{"n4"}}})
	if len(resp.R.Nodes) == 0 || len(resp.R.Nodes6) != 0 {
		t.Fatalf("v6 node asked for n4 answered %d v4 and %d v6", len(resp.R.Nodes), len(resp.R.Nodes6))
	}
	resp = query(t, v4, addr(100), krpc.Msg{Q: "find_node", A: krpc.Args{ID: outsiderID(r), Target: &target}})
	if len(resp.R.Nodes6) != 0 {
		t.Fatal("a query without want got the sibling's family")
	}
}

// A sibling in a different community doesn't answer for this one's
// members: its contacts would lack our tag. Mainline referrals still cross.
func TestSiblingCommunityMustMatch(t *testing.T) {
	r := rng(79)
	ru := overlay.NewKey("ru")
	v4 := New(Config{ID: memberID(r, addr(1).Addr()), Community: &key, Rand: rng(80)})
	other := ru
	v6 := New(Config{ID: ru.Tag(outsiderID(r)), Community: &other, Rand: rng(81)})
	v4.SetSibling(v6)
	v6addr := func(i int) netip.AddrPort {
		return netip.AddrPortFrom(netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, byte(i), 15: 1}), 6881)
	}
	for i := 1; i <= 4; i++ {
		a := v6addr(i)
		v6.comm.heard(ru.Tag(krpc.SecureID(a.Addr(), outsiderID(r))), a, t0)
		v6.main.heard(outsiderID(r), v6addr(10+i), t0)
	}
	target := outsiderID(r)
	resp := query(t, v4, addr(100), krpc.Msg{Q: "find_node", A: krpc.Args{ID: memberID(r, addr(100).Addr()), Target: &target, Want: []string{"n6"}}})
	if len(resp.R.Nodes6) != 0 {
		t.Fatalf("a member got %d IPv6 referrals from another community's table", len(resp.R.Nodes6))
	}
	resp = query(t, v4, addr(100), krpc.Msg{Q: "find_node", A: krpc.Args{ID: outsiderID(r), Target: &target, Want: []string{"n6"}}})
	if len(resp.R.Nodes6) == 0 {
		t.Fatal("Mainline referrals stopped crossing to the sibling")
	}
}

// Rebound forgets the old network's reflections and re-signs the
// listener's records with a newer seq, so holders move their binding.
func TestReboundResignsRecords(t *testing.T) {
	n := New(Config{ID: outsiderID(rng(90)), Rand: rng(91), ReadOnly: true})
	n.main.heard(outsiderID(rng(92)), addr(1), t0)
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	if err := n.Listen(t0, priv); err != nil {
		t.Fatal(err)
	}
	n.reflections = []Reflection{{From: addr(1), Mapped: addr(2)}}
	seqs := map[krpc.NodeID]int64{}
	for _, tgt := range n.lst.records {
		seqs[tgt] = n.owned[tgt].rec.mut.Seq
	}
	n.Rebound(t0.Add(time.Second))
	if len(n.Reflections()) != 0 {
		t.Fatal("reflections from the old network survived a rebind")
	}
	for tgt, old := range seqs {
		if got := n.owned[tgt].rec.mut.Seq; got <= old {
			t.Fatalf("record re-published at seq %d, not above %d: holders keep the old binding", got, old)
		}
	}
}

// A reply to a query sent before a rebind is dropped, even when the rebind
// carries the same timestamp, while a query sent after it (same timestamp
// again) is reflected normally.
func TestPreRebindReplyNotReflected(t *testing.T) {
	n := New(Config{ID: outsiderID(rng(93)), Rand: rng(94)})
	ping := func(peer netip.AddrPort) krpc.Msg {
		n.send(t0, peer, "ping", krpc.Args{}, &txn{kind: txPing})
		sends, _ := n.Drain()
		var q krpc.Msg
		if len(sends) != 1 || krpc.Unmarshal(sends[0].Data, &q) != nil {
			t.Fatal("no ping sent")
		}
		return q
	}
	reply := func(peer netip.AddrPort, q krpc.Msg, mapped netip.AddrPort) {
		r := krpc.Msg{T: q.T, Y: krpc.Response, IP: mapped, R: krpc.Return{ID: outsiderID(rng(95))}}
		n.HandlePacket(t0, peer, krpc.AppendMarshal(nil, &r))
	}
	old := ping(addr(7))
	n.Rebound(t0) // same instant as the query
	reply(addr(7), old, addr(50))
	if len(n.Reflections()) != 0 {
		t.Fatalf("a pre-rebind reply was recorded as a reflection: %v", n.Reflections())
	}
	fresh := ping(addr(8))
	reply(addr(8), fresh, addr(51))
	if r := n.Reflections(); len(r) != 1 || r[0].Mapped != addr(51) {
		t.Fatalf("a post-rebind reply at the same instant wasn't reflected: %v", r)
	}
}

// Rebound drops write tokens bound to our old address, and a publication
// that started before it can't install its holders afterwards.
func TestReboundDropsStaleTokensAndPublications(t *testing.T) {
	n := New(Config{ID: outsiderID(rng(96)), Rand: rng(97), ReadOnly: true})
	n.main.heard(outsiderID(rng(98)), addr(1), t0)
	if err := n.Listen(t0, ed25519.NewKeyFromSeed(make([]byte, 32))); err != nil {
		t.Fatal(err)
	}
	n.lst.holders = []*holder{{addr: addr(2), token: []byte("old")}}
	n.lst.sessions[SessionID{1}] = &session{expires: t0.Add(time.Hour), tokens: map[netip.AddrPort][]byte{addr(3): []byte("old")}}
	var target krpc.NodeID
	for _, tg := range n.lst.records {
		target = tg
	}
	oldPub := &lookup{gen: n.gen, target: target, acked: []ackedReplica{{addr: addr(4), token: []byte("old")}}}
	n.Rebound(t0.Add(time.Second))
	for _, h := range n.lst.holders {
		if h.token != nil {
			t.Fatalf("holder %v kept a token bound to the old address", h.addr)
		}
	}
	if n.lst.sessions[SessionID{1}].tokens != nil {
		t.Fatal("a session kept tokens bound to the old address")
	}
	n.lst.holders = nil
	n.recordStored(t0.Add(2*time.Second), oldPub)
	if len(n.lst.holders) != 0 {
		t.Fatal("a publication from before the rebind installed its holders")
	}
}

// A finished lookup reports when its first response came, when its K
// closest responders last changed, and its total time.
func TestLookupTiming(t *testing.T) {
	r := rng(80)
	n := New(Config{ID: outsiderID(r), Rand: rng(81)})
	ids := make([]krpc.NodeID, 3)
	for i := range ids {
		ids[i] = outsiderID(r)
		n.primary.heard(ids[i], addr(i+1), t0)
	}
	op, err := n.FindNode(t0, outsiderID(r))
	if err != nil {
		t.Fatal(err)
	}
	sends, _ := n.Drain()
	tids := map[netip.AddrPort][]byte{}
	for _, s := range sends {
		var m krpc.Msg
		if krpc.Unmarshal(s.Data, &m) == nil && m.Y == krpc.Query {
			tids[s.To] = m.T
		}
	}
	var done *LookupDone
	for i, after := range []time.Duration{100 * time.Millisecond, 250 * time.Millisecond, 400 * time.Millisecond} {
		from := addr(i + 1)
		if tids[from] == nil {
			t.Fatalf("no query to %v", from)
		}
		resp := krpc.AppendMarshal(nil, &krpc.Msg{T: tids[from], Y: krpc.Response, R: krpc.Return{ID: ids[i]}})
		n.HandlePacket(t0.Add(after), from, resp)
		_, events := n.Drain()
		for _, e := range events {
			if d, ok := e.(LookupDone); ok && d.Op == op {
				done = &d
			}
		}
	}
	if done == nil {
		t.Fatal("the lookup never finished")
	}
	want := Timing{First: 100 * time.Millisecond, Settled: 400 * time.Millisecond, Total: 400 * time.Millisecond}
	if done.Timing != want || done.Failures != 0 {
		t.Fatalf("timing %+v failures %d, want %+v and none", done.Timing, done.Failures, want)
	}
}

// A reply from beyond the K closest responders leaves Settled alone; only a
// change to the K closest moves it.
func TestSettledIgnoresDistantReplies(t *testing.T) {
	r := rng(82)
	n := New(Config{ID: outsiderID(r), Rand: rng(83), K: 2})
	target := outsiderID(r)
	near := func(byteIdx int) krpc.NodeID { // differs from target first at byteIdx
		id := target
		id[byteIdx] ^= 0x80
		return id
	}
	nearest, middle, far := near(19), near(10), near(0)
	n.primary.heard(middle, addr(1), t0)
	n.primary.heard(far, addr(2), t0)
	op, err := n.FindNode(t0, target)
	if err != nil {
		t.Fatal(err)
	}
	var done *LookupDone
	tids := map[netip.AddrPort][]byte{}
	drain := func() {
		sends, events := n.Drain()
		for _, s := range sends {
			var m krpc.Msg
			if krpc.Unmarshal(s.Data, &m) == nil && m.Y == krpc.Query {
				tids[s.To] = m.T
			}
		}
		for _, e := range events {
			if d, ok := e.(LookupDone); ok && d.Op == op {
				done = &d
			}
		}
	}
	reply := func(after time.Duration, from netip.AddrPort, id krpc.NodeID, nodes ...krpc.NodeInfo) {
		t.Helper()
		if tids[from] == nil {
			t.Fatalf("no query to %v", from)
		}
		n.HandlePacket(t0.Add(after), from, krpc.AppendMarshal(nil, &krpc.Msg{T: tids[from], Y: krpc.Response, R: krpc.Return{ID: id, Nodes: nodes}}))
		drain()
	}
	drain()
	// The middle node answers and refers a nearer one; the nearer one
	// answers; the far node, by then outside the K=2 closest responders,
	// answers last.
	reply(100*time.Millisecond, addr(1), middle, krpc.NodeInfo{ID: nearest, Addr: addr(3)})
	reply(150*time.Millisecond, addr(3), nearest)
	reply(200*time.Millisecond, addr(2), far)
	if done == nil {
		t.Fatal("the lookup never finished")
	}
	if done.Timing.Settled != 150*time.Millisecond || done.Timing.Total != 200*time.Millisecond {
		t.Fatalf("settled %v total %v, want 150ms and 200ms: a reply outside K moved Settled", done.Timing.Settled, done.Timing.Total)
	}
}
