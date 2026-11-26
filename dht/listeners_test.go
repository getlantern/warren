package dht

import (
	"crypto/ed25519"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/getlantern/warren/krpc"
)

// offerTo builds an offer to l's current record exactly as a caller does.
func offerTo(n *Node, l *listener, caller ed25519.PrivateKey, payload string) *MutableItem {
	var target krpc.NodeID
	for _, tg := range l.records {
		target = tg
	}
	e, _ := ecdhX25519(n.randBytes(32))
	shared, _ := e.ECDH(l.x.PublicKey())
	offerKey, _, _ := signalKeys(shared, e.PublicKey().Bytes(), l.x.PublicKey().Bytes())
	sealed := append(e.PublicKey().Bytes(), n.seal(offerKey, []byte(payload))...)
	m, _ := NewMutable(caller, offerSalt(n.randBytes(16), target), t0.Unix(), bencodeBytes(sealed))
	return &m
}

func seededKey(b byte) ed25519.PrivateKey {
	seed := make([]byte, 32)
	seed[0] = b
	return ed25519.NewKeyFromSeed(seed)
}

func pubOf(k ed25519.PrivateKey) [32]byte { return [32]byte(k.Public().(ed25519.PublicKey)) }

// TestOffersSayWhichListener: two listeners each get their own offers,
// each Incoming naming the key it called, and each answers.
func TestOffersSayWhichListener(t *testing.T) {
	n := New(Config{ID: outsiderID(rng(1)), Rand: rng(2)})
	a, b := seededKey(1), seededKey(2)
	for _, k := range []ed25519.PrivateKey{a, b} {
		if err := n.AddListener(t0, k); err != nil {
			t.Fatal(err)
		}
	}
	if len(n.Listeners()) != 2 {
		t.Fatalf("%d listeners", len(n.Listeners()))
	}
	n.Drain()
	caller := seededKey(9)
	for i, l := range n.lsts {
		if !n.acceptOffer(t0, addr(40+i), offerTo(n, l, caller, "hi")) {
			t.Fatalf("listener %d refused its offer", i)
		}
	}
	_, evs := n.Drain()
	var got [][32]byte
	for _, e := range evs {
		if in, ok := e.(Incoming); ok {
			got = append(got, in.Listener)
			if err := n.Answer(t0, in.Session, []byte("ok")); err != nil {
				t.Fatalf("answer through %x: %v", in.Listener[:4], err)
			}
		}
	}
	if len(got) != 2 || got[0] != pubOf(a) || got[1] != pubOf(b) {
		t.Fatalf("offers named %x", got)
	}
}

// TestRemoveListenerLeavesOthers: removing one key stops its offers and
// records, and the other carries on.
func TestRemoveListenerLeavesOthers(t *testing.T) {
	n := New(Config{ID: outsiderID(rng(1)), Rand: rng(2)})
	a, b := seededKey(1), seededKey(2)
	n.AddListener(t0, a)
	n.AddListener(t0, b)
	gone := n.lsts[0]
	n.RemoveListener(pubOf(a))
	if ls := n.Listeners(); len(ls) != 1 || ls[0].Key != pubOf(b) {
		t.Fatalf("listeners after removing one: %v", ls)
	}
	for _, tg := range gone.records {
		if n.owned[tg] != nil {
			t.Fatal("a removed listener's record is still published")
		}
	}
	if n.acceptOffer(t0, addr(40), offerTo(n, gone, seededKey(9), "hi")) {
		t.Fatal("an offer to a removed key was taken")
	}
	if !n.acceptOffer(t0, addr(41), offerTo(n, n.lsts[0], seededKey(9), "hi")) {
		t.Fatal("the remaining key refused its offer")
	}
}

// TestListenReplacesAddListenerAdds: Listen replaces every key, as it
// always has; AddListener under a key already listened under replaces only
// that one.
func TestListenReplacesAddListenerAdds(t *testing.T) {
	n := New(Config{ID: outsiderID(rng(1)), Rand: rng(2)})
	a, b, c := seededKey(1), seededKey(2), seededKey(3)
	n.AddListener(t0, a)
	n.AddListener(t0, b)
	oldX := n.lsts[0].x
	if err := n.AddListener(t0, a); err != nil {
		t.Fatal(err)
	}
	ls := n.Listeners()
	if len(ls) != 2 || ls[0].Key != pubOf(b) || ls[1].Key != pubOf(a) || ls[1].SignalKey == oldX {
		t.Fatal("re-adding a key didn't replace just that one")
	}
	if err := n.Listen(t0, c); err != nil {
		t.Fatal(err)
	}
	if ls := n.Listeners(); len(ls) != 1 || ls[0].Key != pubOf(c) {
		t.Fatal("Listen didn't replace every key")
	}
}

func TestMaxListeners(t *testing.T) {
	n := New(Config{ID: outsiderID(rng(1)), Rand: rng(2)})
	for i := range MaxListeners {
		if err := n.AddListener(t0, seededKey(byte(i+1))); err != nil {
			t.Fatalf("listener %d: %v", i, err)
		}
	}
	if err := n.AddListener(t0, seededKey(200)); !errors.Is(err, ErrTooManyListeners) {
		t.Fatalf("one past the cap: %v", err)
	}
	if err := n.AddListener(t0, seededKey(1)); err != nil {
		t.Fatalf("replacing a key at the cap: %v", err)
	}
}

// TestReboundResignsEveryListener: a network change re-signs every
// listener's records, so all their holders rebind.
func TestReboundResignsEveryListener(t *testing.T) {
	n := New(Config{ID: outsiderID(rng(1)), Rand: rng(2)})
	n.AddListener(t0, seededKey(1))
	n.AddListener(t0, seededKey(2))
	before := map[krpc.NodeID]int64{}
	for _, l := range n.lsts {
		for _, tg := range l.records {
			before[tg] = n.recordSeq[tg]
		}
	}
	n.Rebound(t0.Add(time.Second))
	for tg, seq := range before {
		if n.recordSeq[tg] <= seq {
			t.Fatal("a listener's record wasn't re-signed after a rebind")
		}
	}
}

// TestSessionsBoundedAcrossListeners: the cap on offers in progress is one
// for the node, not one per listener.
func TestSessionsBoundedAcrossListeners(t *testing.T) {
	n := New(Config{ID: outsiderID(rng(1)), Rand: rng(2)})
	n.AddListener(t0, seededKey(1))
	n.AddListener(t0, seededKey(2))
	n.Drain()
	for i := range maxSessions {
		n.acceptOffer(t0, addr(40), offerTo(n, n.lsts[i%2], seededKey(byte(10+i%200)), "hi"))
	}
	n.acceptOffer(t0, addr(41), offerTo(n, n.lsts[0], seededKey(250), "hi"))
	n.acceptOffer(t0, addr(41), offerTo(n, n.lsts[1], seededKey(251), "hi"))
	if c := n.sessionCount(); c > maxSessions {
		t.Fatalf("%d sessions across listeners, cap %d", c, maxSessions)
	}
}

// TestMappingChangeResignsEveryListener: a holder reporting our address
// moved re-signs every listener's records, not just the one it holds for.
func TestMappingChangeResignsEveryListener(t *testing.T) {
	n := New(Config{ID: outsiderID(rng(1)), Rand: rng(2)})
	n.AddListener(t0, seededKey(1))
	n.AddListener(t0, seededKey(2))
	before := map[krpc.NodeID]int64{}
	for _, l := range n.lsts {
		for _, tg := range l.records {
			before[tg] = n.recordSeq[tg]
		}
	}
	var target krpc.NodeID
	for _, tg := range n.lsts[0].records {
		target = tg
	}
	h := &holder{addr: addr(60), target: target, mapped: netip.MustParseAddrPort("192.0.2.1:1000")}
	n.lsts[0].holders = append(n.lsts[0].holders, h)
	n.keepaliveReply(t0.Add(time.Second), h, &krpc.Msg{IP: netip.MustParseAddrPort("192.0.2.9:2000")})
	for tg, seq := range before {
		if n.recordSeq[tg] <= seq {
			t.Fatal("a listener's record wasn't re-signed when our address moved")
		}
	}
}

// TestSessionIDUniqueAcrossListeners: an offer to another of our keys
// reusing a live session's ID is refused, so Answer reaches the caller
// that made the session.
func TestSessionIDUniqueAcrossListeners(t *testing.T) {
	n := New(Config{ID: outsiderID(rng(1)), Rand: rng(2)})
	n.AddListener(t0, seededKey(1))
	n.AddListener(t0, seededKey(2))
	n.Drain()
	first := offerTo(n, n.lsts[0], seededKey(9), "genuine")
	if !n.acceptOffer(t0, addr(40), first) {
		t.Fatal("offer refused")
	}
	// Another offer, to the second key, under the first one's session ID.
	reuse := offerTo(n, n.lsts[1], seededKey(10), "reused id")
	var target krpc.NodeID
	for _, tg := range n.lsts[1].records {
		target = tg
	}
	salt := offerSalt(first.Salt[:16], target)
	m, _ := NewMutable(seededKey(10), salt, t0.Unix(), reuse.V)
	n.acceptOffer(t0, addr(41), &m)
	_, evs := n.Drain()
	incoming := 0
	for _, e := range evs {
		if _, ok := e.(Incoming); ok {
			incoming++
		}
	}
	if incoming != 1 || len(n.lsts[1].sessions) != 0 {
		t.Fatalf("%d offers delivered; the reused session ID was taken", incoming)
	}
}

// TestMappingChangeResignsOncePerRound: many holders across listeners all
// reporting one address change re-sign each record once, not once per
// holder.
func TestMappingChangeResignsOncePerRound(t *testing.T) {
	n := New(Config{ID: outsiderID(rng(1)), Rand: rng(2)})
	var cs []*counting
	for i := range 3 {
		c := &counting{failing: failing{k: seededKey(byte(i + 1))}}
		cs = append(cs, c)
		n.AddListener(t0, c)
	}
	moved := netip.MustParseAddrPort("192.0.2.9:2000")
	var hs []*holder
	for i, l := range n.lsts {
		var target krpc.NodeID
		for _, tg := range l.records {
			target = tg
		}
		for j := range 4 {
			h := &holder{addr: addr(60 + 4*i + j), target: target, mapped: netip.MustParseAddrPort("192.0.2.1:1000")}
			l.holders = append(l.holders, h)
			hs = append(hs, h)
		}
	}
	for _, c := range cs {
		c.signs = 0
	}
	for _, h := range hs {
		n.keepaliveReply(t0.Add(time.Second), h, &krpc.Msg{IP: moved})
	}
	for i, c := range cs {
		if c.signs > len(n.lsts[i].records) {
			t.Fatalf("listener %d signed %d times for one address change", i, c.signs)
		}
	}
}

func TestSignerFailedNamesListener(t *testing.T) {
	n := New(Config{ID: outsiderID(rng(1)), Rand: rng(2)})
	ok := seededKey(1)
	f := &failing{k: seededKey(2)}
	n.AddListener(t0, ok)
	n.AddListener(t0, f)
	n.Drain()
	f.fail = true
	n.resign(t0.Add(time.Second), n.lsts[1])
	_, evs := n.Drain()
	for _, e := range evs {
		if sf, isSF := e.(SignerFailed); isSF {
			if sf.Listener != pubOf(f.k) {
				t.Fatalf("SignerFailed named %x", sf.Listener[:4])
			}
			return
		}
	}
	t.Fatal("no SignerFailed")
}
