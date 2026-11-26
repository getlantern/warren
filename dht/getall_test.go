package dht

import (
	"crypto/ed25519"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/getlantern/warren/krpc"
)

// getWithReplies runs a mutable get for key and salt against len(replies)
// contacts, the i-th answering with replies[i] (nil: an empty answer), and
// returns its completion.
func getWithReplies(t *testing.T, key [32]byte, salt []byte, replies []*MutableItem) GetDone {
	t.Helper()
	r := rng(90)
	n := New(Config{ID: outsiderID(r), Rand: rng(91)})
	ids := make([]krpc.NodeID, len(replies))
	for i := range ids {
		ids[i] = outsiderID(r)
		n.primary.heard(ids[i], addr(i+1), t0)
	}
	op, err := n.GetMutable(t0, key, salt)
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
	for i, it := range replies {
		ret := krpc.Return{ID: ids[i], Token: []byte("tok")}
		if it != nil {
			seq := it.Seq
			ret.V, ret.K, ret.Sig, ret.Seq = it.V, it.Key[:], it.Sig[:], &seq
		}
		n.HandlePacket(t0.Add(time.Duration(i+1)*time.Millisecond), addr(i+1),
			krpc.AppendMarshal(nil, &krpc.Msg{T: tids[addr(i+1)], Y: krpc.Response, R: ret}))
	}
	n.Tick(t0.Add(30 * time.Second))
	_, events := n.Drain()
	for _, e := range events {
		if d, ok := e.(GetDone); ok && d.Op == op {
			return d
		}
	}
	t.Fatal("the get never completed")
	return GetDone{}
}

// TestGetKeepsEveryDistinctItem: replicas holding different values, at one
// sequence number or several, are all returned, duplicates once, newest
// first; Item is still the newest.
func TestGetKeepsEveryDistinctItem(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	key := [32]byte(priv.Public().(ed25519.PublicKey))
	salt := []byte("shard")
	mk := func(seq int64, v string) *MutableItem {
		m, err := NewMutable(priv, salt, seq, ImmutableValue([]byte(v)))
		if err != nil {
			t.Fatal(err)
		}
		return &m
	}
	a, b, old := mk(2, "alice wrote"), mk(2, "bob wrote"), mk(1, "earlier")
	g := getWithReplies(t, key, salt, []*MutableItem{old, a, b}) // oldest first: the result is sorted anyway
	if len(g.Items) != 3 {
		t.Fatalf("%d items, want the 3 distinct ones", len(g.Items))
	}
	if g.Items[0].Seq != 2 || g.Items[1].Seq != 2 || g.Items[2].Seq != 1 {
		t.Fatalf("not newest first: %d %d %d", g.Items[0].Seq, g.Items[1].Seq, g.Items[2].Seq)
	}
	if g.Item == nil || g.Item.Seq != 2 {
		t.Fatal("Item isn't the newest")
	}
}

// TestGetDropsForeignItems: an item signed by another key, or not
// verifying, isn't returned.
func TestGetDropsForeignItems(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	other := ed25519.NewKeyFromSeed(append(make([]byte, 31), 1))
	key := [32]byte(priv.Public().(ed25519.PublicKey))
	salt := []byte("shard")
	good, _ := NewMutable(priv, salt, 1, ImmutableValue([]byte("good")))
	foreign, _ := NewMutable(other, salt, 2, ImmutableValue([]byte("foreign")))
	forged := good
	forged.V = ImmutableValue([]byte("forged"))
	g := getWithReplies(t, key, salt, []*MutableItem{&good, &foreign, &forged})
	if len(g.Items) != 1 || g.Items[0].Sig != good.Sig {
		t.Fatalf("%d items; want only the one signed by the key", len(g.Items))
	}
}

// TestGetItemsDedupedAndCapped: an item seen twice is kept once, and
// more distinct items than MaxGetItems can't grow the result past it.
func TestGetItemsDedupedAndCapped(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	salt := []byte("shard")
	l := &lookup{}
	first, _ := NewMutable(priv, salt, 1, ImmutableValue([]byte{0}))
	l.keep(&first)
	dup := first
	l.keep(&dup)
	if len(l.items) != 1 {
		t.Fatalf("%d items after one seen twice", len(l.items))
	}
	for i := range MaxGetItems + 8 {
		m, _ := NewMutable(priv, salt, int64(i+2), ImmutableValue([]byte{byte(i + 1)}))
		l.keep(&m)
	}
	if len(l.items) != MaxGetItems {
		t.Fatalf("%d items, cap %d", len(l.items), MaxGetItems)
	}
}

// TestGetSameValueTwiceOnce: two replicas returning one item count once.
func TestGetSameValueTwiceOnce(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	key := [32]byte(priv.Public().(ed25519.PublicKey))
	salt := []byte("shard")
	a, _ := NewMutable(priv, salt, 3, ImmutableValue([]byte("same")))
	b, _ := NewMutable(priv, salt, 3, ImmutableValue([]byte("other")))
	g := getWithReplies(t, key, salt, []*MutableItem{&a, &a, &b})
	if len(g.Items) != 2 {
		t.Fatalf("%d items, want 2", len(g.Items))
	}
}

// TestGetKeepsNewestUnderReplays: replayed old items filling the cap first
// don't push out a newer one arriving after them.
func TestGetKeepsNewestUnderReplays(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	salt := []byte("shard")
	l := &lookup{}
	for i := range MaxGetItems {
		m, _ := NewMutable(priv, salt, int64(i+1), ImmutableValue([]byte{byte(i)}))
		l.keep(&m)
	}
	current, _ := NewMutable(priv, salt, 1000, ImmutableValue([]byte("current")))
	l.keep(&current)
	if !slices.ContainsFunc(l.items, func(x *MutableItem) bool { return x.Sig == current.Sig }) {
		t.Fatal("a newer item was dropped behind replays filling the cap")
	}
	stale, _ := NewMutable(priv, salt, 0, ImmutableValue([]byte("stale")))
	l.keep(&stale)
	if slices.ContainsFunc(l.items, func(x *MutableItem) bool { return x.Sig == stale.Sig }) || len(l.items) != MaxGetItems {
		t.Fatal("an item older than every kept one displaced one")
	}
}
