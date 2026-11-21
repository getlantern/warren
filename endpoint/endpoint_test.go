package endpoint

import (
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/getlantern/warren/dht"
	"github.com/getlantern/warren/driver"
	"github.com/getlantern/warren/krpc"
	"github.com/getlantern/warren/overlay"
)

var farsi = overlay.NewKey("fa")

func member(ro bool) dht.Config {
	var id krpc.NodeID
	crand.Read(id[:])
	return dht.Config{
		ID:           farsi.Tag(krpc.SecureID(netip.MustParseAddr("127.0.0.1"), id)),
		Community:    &farsi,
		ReadOnly:     ro,
		Unrestricted: true,
		QueryTimeout: time.Second,
	}
}

func key(seed string) ed25519.PrivateKey {
	s := sha256.Sum256([]byte(seed))
	return ed25519.NewKeyFromSeed(s[:])
}

func pub(k ed25519.PrivateKey) [32]byte { return [32]byte(k.Public().(ed25519.PublicKey)) }

// network starts DHT routers on loopback and returns a seed address.
func network(t *testing.T, size int) netip.AddrPort {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var nodes []*driver.Node
	for i := range size {
		n, err := driver.Listen("127.0.0.1:0", member(false))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { n.Close() })
		if i > 0 {
			n.Bootstrap(ctx, []netip.AddrPort{nodes[0].Addr()})
		}
		nodes = append(nodes, n)
	}
	for _, n := range nodes {
		n.Bootstrap(ctx, []netip.AddrPort{nodes[len(nodes)-1].Addr()})
	}
	return nodes[0].Addr()
}

func phone(t *testing.T, seed netip.AddrPort) *Endpoint {
	t.Helper()
	e, err := New(Config{DHT: member(true), DHTAddr: "127.0.0.1:0", DataIP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := e.DHT().Bootstrap(ctx, []netip.AddrPort{seed}); err != nil {
		t.Fatal(err)
	}
	return e
}

func listenAndWait(t *testing.T, e *Endpoint, k ed25519.PrivateKey) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := e.Listen(ctx, k); err != nil {
		t.Fatal(err)
	}
	for {
		var holders int
		e.DHT().Inspect(ctx, func(d *dht.Node) { holders = len(d.Holders()) })
		if holders > 0 {
			return
		}
		if ctx.Err() != nil {
			t.Fatal("record never reached holders")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func roundTrip(t *testing.T, from, to *Conn, msg string) {
	t.Helper()
	if err := from.Send([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	to.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 128)
	n, src, err := to.ReadFromUDPAddrPort(buf)
	if err != nil || string(buf[:n]) != msg || src != to.Remote {
		t.Fatalf("read: %v %q from %s (want %s)", err, buf[:n], src, to.Remote)
	}
}

func TestConnectByPublicKey(t *testing.T) {
	seed := network(t, 10)
	provider, caller := phone(t, seed), phone(t, seed)
	pk, ck := key("provider"), key("caller")
	listenAndWait(t, provider, pk)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	accepted := make(chan *Conn, 1)
	go func() {
		c, err := provider.Accept(ctx)
		if err != nil {
			t.Error(err)
		}
		accepted <- c
	}()
	start := time.Now()
	out, err := caller.Connect(ctx, ck, pub(pk))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	in := <-accepted
	if in == nil {
		t.Fatal("nothing accepted")
	}
	defer in.Close()
	t.Logf("connected by public key in %v", time.Since(start))

	if out.PeerKey != pub(pk) || in.PeerKey != pub(ck) {
		t.Errorf("peer keys: caller sees %x, provider sees %x", out.PeerKey[:4], in.PeerKey[:4])
	}
	if string(out.Secret) != string(in.Secret) || len(out.Secret) != 32 {
		t.Error("ends do not share the session secret")
	}
	roundTrip(t, out, in, "hello provider")
	roundTrip(t, in, out, "hello caller")
}

func TestConcurrentCallers(t *testing.T) {
	seed := network(t, 10)
	provider := phone(t, seed)
	pk := key("busy provider")
	listenAndWait(t, provider, pk)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const callers = 3
	got := make(chan [32]byte, callers)
	go func() {
		for range callers {
			c, err := provider.Accept(ctx)
			if err != nil {
				return
			}
			got <- c.PeerKey
			c.Close()
		}
	}()
	var wg sync.WaitGroup
	for i := range callers {
		c := phone(t, seed)
		wg.Go(func() {
			conn, err := c.Connect(ctx, key(fmt.Sprint("caller ", i)), pub(pk))
			if err != nil {
				t.Errorf("caller %d: %v", i, err)
				return
			}
			conn.Close()
		})
	}
	wg.Wait()
	seen := map[[32]byte]bool{}
	for range callers {
		select {
		case k := <-got:
			seen[k] = true
		case <-ctx.Done():
			t.Fatalf("accepted %d of %d", len(seen), callers)
		}
	}
	if len(seen) != callers {
		t.Fatalf("accepted %d distinct callers, want %d", len(seen), callers)
	}
}

func TestConnectUnknownKey(t *testing.T) {
	seed := network(t, 8)
	caller := phone(t, seed)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := caller.Connect(ctx, key("caller"), pub(key("nobody")))
	if err != dht.ErrNoRecord {
		t.Fatalf("err = %v, want ErrNoRecord", err)
	}
}

func TestAuthorizeRejects(t *testing.T) {
	seed := network(t, 10)
	pk, allowed, denied := key("picky"), key("friend"), key("stranger")
	provider, err := New(Config{
		DHT: member(true), DHTAddr: "127.0.0.1:0", DataIP: net.IPv4(127, 0, 0, 1),
		Authorize: func(c [32]byte) bool { return c == pub(allowed) },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	provider.DHT().Bootstrap(ctx, []netip.AddrPort{seed})
	listenAndWait(t, provider, pk)
	go func() {
		for {
			c, err := provider.Accept(ctx)
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	caller := phone(t, seed)
	// A rejected caller gets silence rather than a refusal, so a probe learns
	// nothing beyond the public record; it fails when its own deadline ends.
	deny, cancelDeny := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelDeny()
	if _, err := caller.Connect(deny, denied, pub(pk)); err == nil {
		t.Fatal("unauthorized caller connected")
	}
	allow, cancelAllow := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelAllow()
	if c, err := caller.Connect(allow, allowed, pub(pk)); err != nil {
		t.Fatalf("authorized caller: %v", err)
	} else {
		c.Close()
	}
}
