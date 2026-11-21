package sim

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/getlantern/warren/dht"
)

func getMutable(t *testing.T, w *world, reader *Node, key [32]byte, salt []byte) *dht.MutableItem {
	t.Helper()
	var got *dht.GetDone
	var op dht.OpID
	w.s.OnEvent = func(n *Node, e dht.Event) {
		if g, ok := e.(dht.GetDone); ok && n == reader && g.Op == op {
			got = &g
		}
	}
	w.s.Do(reader, func(now time.Time) {
		var err error
		if op, err = reader.DHT.GetMutable(now, key, salt); err != nil {
			t.Fatal(err)
		}
	})
	w.s.RunUntil(w.s.Now.Add(45 * time.Second))
	if got == nil {
		t.Fatal("mutable get never completed")
	}
	return got.Item
}

func TestMutableLatestWins(t *testing.T) {
	w := build(5, scenarios[0], sizes{ir: 80, abroad: 30, readers: 20})
	w.join(30 * time.Minute)
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	key := [32]byte(priv.Public().(ed25519.PublicKey))
	salt := []byte("provider")
	pub := w.routersIR[3]
	for seq := int64(1); seq <= 3; seq++ {
		m, _ := dht.NewMutable(priv, salt, seq, dht.ImmutableValue([]byte{byte('a' + seq)}))
		w.s.Do(pub, func(now time.Time) { pub.DHT.PublishMutable(now, m) })
		w.s.RunUntil(w.s.Now.Add(2 * time.Minute))
	}
	for _, r := range []*Node{w.readersIR[0], w.routersIR[40], w.routersAb[10]} {
		it := getMutable(t, w, r, key, salt)
		if it == nil || it.Seq != 3 || !it.Verify() {
			t.Fatalf("reader %s got %+v, want seq 3", r.Addr, it)
		}
	}
}

// A provider record published from abroad must stay readable inside the
// country through a long shutdown.
func TestMutableSurvivesShutdown(t *testing.T) {
	w := build(6, scenarios[3], sizes{ir: 60, abroad: 180, readers: 40})
	w.join(45 * time.Minute)
	priv := ed25519.NewKeyFromSeed([]byte("0123456789abcdef0123456789abcdef"))
	key := [32]byte(priv.Public().(ed25519.PublicKey))
	m, _ := dht.NewMutable(priv, nil, 1, dht.ImmutableValue([]byte("coordinators: ...")))
	pub := w.routersAb[20]
	w.s.Do(pub, func(now time.Time) { pub.DHT.PublishMutable(now, m) })
	w.s.RunUntil(w.s.Now.Add(10 * time.Minute))

	w.s.Border = true
	w.s.RunUntil(w.s.Now.Add(3 * time.Hour))
	isolated := 0
	for _, n := range w.routersIR {
		if n.DHT.Isolated() {
			isolated++
		}
	}
	if isolated < len(w.routersIR)*9/10 {
		t.Errorf("only %d/%d domestic routers detected isolation", isolated, len(w.routersIR))
	}
	for _, r := range w.readersIR[:5] {
		if it := getMutable(t, w, r, key, nil); it == nil || it.Seq != 1 {
			t.Fatalf("reader %s lost the record after 3h of shutdown: %+v", r.Addr, it)
		}
	}
}
