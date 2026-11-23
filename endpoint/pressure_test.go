package endpoint

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/getlantern/warren/dht"
)

// A memory monitor sheds connections oldest first, then all of them, and
// the DHT keeps running.
func TestShedOldestThenAll(t *testing.T) {
	seed := network(t, 8)
	provider, caller := phone(t, seed), phone(t, seed)
	pk := key("shed-provider")
	listenAndWait(t, provider, pk)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	go func() {
		for {
			c, err := provider.Accept(ctx)
			if err != nil {
				return
			}
			go func() {
				b := make([]byte, 64)
				for {
					if _, err := c.Recv(b); err != nil {
						return
					}
				}
			}()
		}
	}()
	var outs []*Conn
	for _, name := range []string{"shed-a", "shed-b", "shed-c"} {
		out, err := caller.Connect(ctx, key(name), pub(pk))
		if err != nil {
			t.Fatal(err)
		}
		defer out.Close()
		outs = append(outs, out)
		time.Sleep(10 * time.Millisecond) // distinct creation times
	}
	if n := caller.Connections(); n != 3 {
		t.Fatalf("%d connections, want 3", n)
	}
	if n := caller.CloseOldest(1); n != 1 {
		t.Fatalf("closed %d, want 1", n)
	}
	if outs[0].Send([]byte("x")) == nil || outs[1].Send([]byte("x")) != nil || outs[2].Send([]byte("x")) != nil {
		t.Fatal("CloseOldest didn't close exactly the oldest connection")
	}
	if n := caller.CloseAll(); n != 2 || caller.Connections() != 0 {
		t.Fatalf("CloseAll closed %d, %d left", n, caller.Connections())
	}
	for deadline := time.Now().Add(5 * time.Second); provider.Connections() != 3; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("provider has %d connections, want 3", provider.Connections())
		}
	}
	if n := provider.CloseAll(); n != 3 || provider.Connections() != 0 {
		t.Fatalf("provider CloseAll closed %d, %d left", n, provider.Connections())
	}
	// Still listening: the provider's record is still held. (A fourth
	// connection from loopback within the minute would hit the inbound
	// limiter's per-network budget.)
	var holders int
	provider.DHT().Inspect(ctx, func(d *dht.Node) { holders = len(d.Holders()) })
	if holders == 0 {
		t.Fatal("CloseAll stopped the provider listening")
	}
}

// While refusing, an endpoint makes no new connections and a refusing
// provider turns callers away at once; live sessions keep migrating.
func TestRefusingNewConnections(t *testing.T) {
	caller, provider, out, ctx := echoedWith(t, "refuse")
	caller.SetRefusing(true)
	if _, err := caller.Connect(ctx, key("refuse-2"), out.PeerKey); !errors.Is(err, ErrRefusing) {
		t.Fatalf("Connect while refusing: %v", err)
	}
	caller.SetRefusing(false)
	provider.SetRefusing(true)
	start := time.Now()
	if _, err := caller.Connect(ctx, key("refuse-3"), out.PeerKey); err == nil {
		t.Fatal("a refusing provider accepted a new connection")
	}
	if d := time.Since(start); d > 4*time.Second {
		t.Fatalf("a refusing provider took %v to turn the caller away", d)
	}
	if err := out.Migrate(ctx); err != nil {
		t.Fatalf("a live session couldn't migrate while the provider refuses: %v", err)
	}
	ping(t, out)
}
