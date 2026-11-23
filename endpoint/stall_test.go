package endpoint

import (
	"context"
	"testing"
	"time"
)

// echoed connects caller to an echoing provider.
func echoed(t *testing.T, name string) (*Endpoint, *Conn, context.Context) {
	t.Helper()
	seed := network(t, 8)
	provider, caller := phone(t, seed), phone(t, seed)
	caller.stallTimeout.Store(int64(300 * time.Millisecond))
	pk := key(name + "-provider")
	listenAndWait(t, provider, pk)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	go func() {
		c, _ := provider.Accept(ctx)
		if c == nil {
			return
		}
		defer c.Close()
		b := make([]byte, 1500)
		for {
			n, err := c.Recv(b)
			if err != nil {
				return
			}
			_ = c.Send(b[:n])
		}
	}()
	out, err := caller.Connect(ctx, key(name+"-caller"), pub(pk))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { out.Close() })
	return caller, out, ctx
}

func ping(t *testing.T, c *Conn) {
	t.Helper()
	b := make([]byte, 64)
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if err := c.Send([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, err := c.Recv(b)
		if err == nil && string(b[:n]) == "ping" {
			_ = c.SetReadDeadline(time.Time{})
			return
		}
	}
	t.Fatal("no echo")
}

// A path that dies without an error (the provider moved, a NAT dropped
// its mapping) is noticed from the provider's silence, and the caller
// migrates on its own.
func TestStalledSessionMigrates(t *testing.T) {
	_, out, _ := echoed(t, "stall")
	ping(t, out)
	before := out.LocalAddr().String()
	sock, _, _ := out.p.current()
	out.p.testDrop.Store(sock) // the path goes dark
	if err := out.Send([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(10 * time.Second); out.LocalAddr().String() == before; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the stalled connection never migrated")
		}
	}
	ping(t, out)
}

// A peer that answers keeps the connection where it is, and so does an
// idle one: silence counts only after we sent something.
func TestAnsweredConnectionStays(t *testing.T) {
	_, out, _ := echoed(t, "healthy")
	for end := time.Now().Add(2500 * time.Millisecond); time.Now().Before(end); time.Sleep(100 * time.Millisecond) {
		ping(t, out)
	}
	time.Sleep(1500 * time.Millisecond) // idle across watcher ticks
	if n := out.moveReqs.Load(); n != 0 {
		t.Fatalf("a connection with an answering peer migrated %d times", n)
	}
}

// Failed stall migrations back off, doubling, so a peer that is gone isn't
// signaled every second.
func TestStallMigrationsBackOff(t *testing.T) {
	c := &Conn{e: &Endpoint{}, p: &path{}} // not outbound: Migrate fails at once
	c.p.waiting.Store(time.Now().Add(-time.Hour).UnixNano())
	settle := func() {
		for c.stallBusy.Load() {
			time.Sleep(time.Millisecond)
		}
	}
	timeout := 100 * time.Millisecond
	c.checkStall(time.Now(), timeout)
	settle()
	if c.stallBackoff != timeout {
		t.Fatalf("first backoff %v, want %v", c.stallBackoff, timeout)
	}
	c.checkStall(time.Now(), timeout) // still backing off
	settle()
	if c.stallBackoff != timeout {
		t.Fatalf("an attempt ran during the backoff: backoff %v", c.stallBackoff)
	}
	c.checkStall(time.Unix(0, c.stallNext.Load()).Add(time.Millisecond), timeout)
	settle()
	if c.stallBackoff != 2*timeout {
		t.Fatalf("second backoff %v, want %v", c.stallBackoff, 2*timeout)
	}
	c.stallBackoff = maxStallBackoff
	c.checkStall(time.Unix(0, c.stallNext.Load()).Add(time.Millisecond), timeout)
	settle()
	if c.stallBackoff != maxStallBackoff {
		t.Fatalf("backoff %v past the cap", c.stallBackoff)
	}
}

// The watcher runs only while outbound connections exist.
func TestStallWatcherStopsWithoutConnections(t *testing.T) {
	caller, out, _ := echoed(t, "watcher")
	watching := func() bool {
		caller.mu.Lock()
		defer caller.mu.Unlock()
		return caller.stallWatching
	}
	if !watching() {
		t.Fatal("no watcher with an outbound connection")
	}
	out.Close()
	for deadline := time.Now().Add(5 * time.Second); watching(); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the watcher kept running with no outbound connections")
		}
	}
}
