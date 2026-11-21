package driver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/netip"
	"testing"
	"time"

	"github.com/getlantern/warren/dht"
	"github.com/getlantern/warren/krpc"
	"github.com/getlantern/warren/overlay"
)

var farsi = overlay.NewKey("fa")

func memberConfig(ro bool) dht.Config {
	var id krpc.NodeID
	rand.Read(id[:])
	return dht.Config{
		ID:           farsi.Tag(krpc.SecureID(netip.MustParseAddr("127.0.0.1"), id)),
		Community:    &farsi,
		ReadOnly:     ro,
		Unrestricted: true, // every node shares 127.0.0.1
		QueryTimeout: time.Second,
	}
}

func network(t *testing.T, size int) []*Node {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var nodes []*Node
	for i := range size {
		n, err := Listen("127.0.0.1:0", memberConfig(false))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { n.Close() })
		if i > 0 {
			if _, err := n.Bootstrap(ctx, []netip.AddrPort{nodes[0].Addr()}); err != nil {
				t.Fatal(err)
			}
		}
		nodes = append(nodes, n)
	}
	// A second pass lets early joiners learn about later ones.
	for _, n := range nodes {
		n.Bootstrap(ctx, []netip.AddrPort{nodes[len(nodes)-1].Addr()})
	}
	return nodes
}

func TestLoopbackNetwork(t *testing.T) {
	nodes := network(t, 16)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	phone, err := Listen("127.0.0.1:0", memberConfig(true))
	if err != nil {
		t.Fatal(err)
	}
	defer phone.Close()
	if res, err := phone.Bootstrap(ctx, []netip.AddrPort{nodes[5].Addr()}); err != nil || len(res.Closest) == 0 {
		t.Fatalf("phone bootstrap: %v %+v", err, res)
	}

	v := dht.ImmutableValue([]byte("hello over real UDP"))
	target, put, err := nodes[3].Put(ctx, v)
	if err != nil || put.Stored < 3 {
		t.Fatalf("put: %v, stored on %d", err, put.Stored)
	}
	if got, err := phone.Get(ctx, target); err != nil || string(got) != string(v) {
		t.Fatalf("phone get: %v %q", err, got)
	}

	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	key := [32]byte(priv.Public().(ed25519.PublicKey))
	for seq := int64(1); seq <= 2; seq++ {
		m, _ := dht.NewMutable(priv, []byte("inbox"), seq, dht.ImmutableValue([]byte{byte('0' + seq)}))
		if res, err := nodes[7].PutMutable(ctx, m, nil); err != nil || res.Stored == 0 {
			t.Fatalf("mutable put seq %d: %v %+v", seq, err, res)
		}
	}
	if it, err := nodes[11].GetMutable(ctx, key, []byte("inbox")); err != nil || it == nil || it.Seq != 2 {
		t.Fatalf("mutable get: %v %+v", err, it)
	}

	// The phone must not appear in any routing table (BEP 43).
	for _, n := range nodes {
		n.Inspect(ctx, func(d *dht.Node) {
			if d.Knows(phone.Addr()) {
				t.Errorf("%s holds the read-only phone in its table", n.Addr())
			}
		})
	}
}

// A node restarted from its snapshot rejoins with no bootstrap server, as a
// phone must during a shutdown when every foreign seed is unreachable.
func TestRestartFromSnapshot(t *testing.T) {
	nodes := network(t, 12)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	target, _, err := nodes[2].Put(ctx, dht.ImmutableValue([]byte("survives restarts")))
	if err != nil {
		t.Fatal(err)
	}

	snap, err := nodes[9].Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	nodes[9].Close()
	id, contacts, err := dht.ParseSnapshot(snap)
	if err != nil || len(contacts) < 5 {
		t.Fatalf("snapshot: %v, %d contacts", err, len(contacts))
	}

	cfg := memberConfig(false)
	cfg.ID = id
	again, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if res, err := again.Rejoin(ctx, contacts); err != nil || len(res.Closest) == 0 {
		t.Fatalf("rejoin: %v %+v", err, res)
	}
	if got, err := again.Get(ctx, target); err != nil || got == nil {
		t.Fatalf("get after restart: %v %q", err, got)
	}
}

func TestCloseUnblocksCallers(t *testing.T) {
	n, err := Listen("127.0.0.1:0", memberConfig(false))
	if err != nil {
		t.Fatal(err)
	}
	// A lookup toward an address that never answers is still pending when
	// the node closes.
	errc := make(chan error, 1)
	go func() {
		_, err := n.Bootstrap(context.Background(), []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:9")})
		errc <- err
	}()
	time.Sleep(50 * time.Millisecond)
	n.Close()
	select {
	case err := <-errc:
		if err != ErrClosed {
			t.Fatalf("err = %v, want ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("caller still blocked after Close")
	}
}

// Two read-only phones signal each other over real UDP through holders.
func TestSignalOverUDP(t *testing.T) {
	nodes := network(t, 12)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	phone := func() *Node {
		n, err := Listen("127.0.0.1:0", memberConfig(true))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { n.Close() })
		if _, err := n.Bootstrap(ctx, []netip.AddrPort{nodes[4].Addr()}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	provider, caller := phone(), phone()
	pk := ed25519.NewKeyFromSeed([]byte("provider-seed-provider-seed-0123"))
	if err := provider.Listen(ctx, pk); err != nil {
		t.Fatal(err)
	}
	go func() {
		for e := range provider.Events() {
			if in, ok := e.(dht.Incoming); ok {
				provider.Answer(ctx, in.Session, append([]byte("re: "), in.Payload...))
			}
		}
	}()
	// Let the record reach its holders.
	deadline := time.Now().Add(5 * time.Second)
	for {
		var holders int
		provider.Inspect(ctx, func(d *dht.Node) { holders = len(d.Holders()) })
		if holders > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("record never reached holders")
		}
		time.Sleep(20 * time.Millisecond)
	}
	start := time.Now()
	got, err := caller.Signal(ctx, ed25519.NewKeyFromSeed(make([]byte, 32)), [32]byte(pk.Public().(ed25519.PublicKey)), []byte("hello"))
	if err != nil || string(got) != "re: hello" {
		t.Fatalf("signal: %v %q", err, got)
	}
	t.Logf("signaled over real UDP in %v", time.Since(start))
}
