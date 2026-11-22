package endpoint

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// A provider that moves networks stays reachable by public key after
// Rebind: a fresh Connect succeeds against its new address.
func TestConnectAfterProviderRebind(t *testing.T) {
	seed := network(t, 10)
	provider, caller := phone(t, seed), phone(t, seed)
	pk := key("moving-provider")
	listenAndWait(t, provider, pk)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	connect := func() {
		t.Helper()
		accepted := make(chan *Conn, 1)
		go func() {
			c, _ := provider.Accept(ctx)
			accepted <- c
		}()
		out, err := caller.Connect(ctx, key("caller-of-moving"), pub(pk))
		if err != nil {
			t.Fatal(err)
		}
		defer out.Close()
		in := <-accepted
		if in == nil {
			t.Fatal("nothing accepted")
		}
		defer in.Close()
		roundTrip(t, out, in, "hello")
	}
	connect()
	before := provider.DHT().Addr()
	if err := provider.Rebind(ctx); err != nil {
		t.Fatal(err)
	}
	if provider.DHT().Addr() == before {
		t.Fatal("rebind kept the DHT address")
	}
	connect()
}

// WatchNetwork rebinds when the default route's local address changes, and
// not otherwise.
func TestWatchNetworkRebindsOnChange(t *testing.T) {
	seed := network(t, 4)
	e := phone(t, seed)
	var route atomic.Value
	route.Store([2]netip.Addr{netip.MustParseAddr("192.168.1.5")})
	e.routes = func() [2]netip.Addr { return route.Load().([2]netip.Addr) }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.WatchNetwork(ctx, 10*time.Millisecond)
	before := e.DHT().Addr()
	time.Sleep(100 * time.Millisecond)
	if e.DHT().Addr() != before {
		t.Fatal("rebound with no network change")
	}
	route.Store([2]netip.Addr{netip.MustParseAddr("10.20.0.7")}) // moved to cellular
	for deadline := time.Now().Add(2 * time.Second); e.DHT().Addr() == before; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("a network change didn't trigger a rebind")
		}
	}
}
