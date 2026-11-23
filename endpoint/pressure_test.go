package endpoint

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
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

func punchedLoopback(t *testing.T) punched {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	return punched{sock: c, remote: netip.MustParseAddrPort("127.0.0.1:9")}
}

// A punch that finishes after refusing began adds no connection, so a
// CloseAll after SetRefusing(true) leaves none behind.
func TestRefusingDropsLateConnections(t *testing.T) {
	e := &Endpoint{}
	e.SetRefusing(true)
	pd := punchedLoopback(t)
	defer pd.sock.Close()
	if c := e.newConn(pd, [32]byte{1}, []byte("secret-secret-secret"), nil); c != nil || e.Connections() != 0 {
		t.Fatal("a connection punched while refusing was registered")
	}
	e.SetRefusing(false)
	if c := e.newConn(pd, [32]byte{1}, []byte("secret-secret-secret"), nil); c == nil || e.Connections() != 1 {
		t.Fatal("a connection wasn't registered once refusing ended")
	}
}

// Accept never returns a connection shed while it waited, and a shed one
// doesn't hold its queue slot against a fresh one.
func TestAcceptSkipsShedConnections(t *testing.T) {
	e := &Endpoint{accept: make(chan *Conn, 1), done: make(chan struct{})}
	conn := func(b byte) *Conn {
		c := e.newConn(punchedLoopback(t), [32]byte{b}, []byte("secret-secret-secret"), nil)
		t.Cleanup(func() { c.Close() })
		return c
	}
	shed, fresh := conn(1), conn(2)
	e.enqueue(shed)
	e.CloseOldest(1)
	e.enqueue(fresh) // the queue is full of a closed connection
	if fresh.p.isClosed() {
		t.Fatal("a shed connection's queue slot cost a fresh connection")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if got, err := e.Accept(ctx); err != nil || got != fresh {
		t.Fatalf("Accept returned %p, %v; want the fresh connection", got, err)
	}
	e.enqueue(conn(3))
	e.CloseAll()
	short, cancel2 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel2()
	if got, err := e.Accept(short); err == nil {
		t.Fatalf("Accept returned shed connection %p", got)
	}
}

// Another inbound worker queueing while enqueue holds a live connection out
// of the queue (to drop closed ones) can't take its slot and get it closed.
func TestConcurrentEnqueueKeepsLiveConnections(t *testing.T) {
	e := &Endpoint{accept: make(chan *Conn, 3), done: make(chan struct{})}
	conn := func(b byte) *Conn {
		c := e.newConn(punchedLoopback(t), [32]byte{b}, []byte("secret-secret-secret"), nil)
		t.Cleanup(func() { c.Close() })
		return c
	}
	live, shed1, shed2 := conn(1), conn(2), conn(3)
	e.enqueue(live)
	e.enqueue(shed1)
	e.enqueue(shed2)
	shed1.Close()
	shed2.Close()
	a, b := conn(4), conn(5)
	var wg sync.WaitGroup
	e.testHookRequeue = func() {
		e.testHookRequeue = nil
		wg.Go(func() { e.enqueue(b) }) // races into the slot live left
		time.Sleep(50 * time.Millisecond)
	}
	e.enqueue(a)
	wg.Wait()
	for _, c := range []*Conn{live, a, b} {
		if c.p.isClosed() {
			t.Fatal("a live connection that fit the queue was closed")
		}
	}
}
