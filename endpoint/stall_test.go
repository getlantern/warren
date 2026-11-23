package endpoint

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/getlantern/warren/transport/hy2"
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
	// Keep sending, as QUIC retransmits what goes unanswered.
	for deadline := time.Now().Add(10 * time.Second); out.LocalAddr().String() == before; time.Sleep(100 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the stalled connection never migrated")
		}
		if err := out.Send([]byte("ping")); err != nil {
			t.Fatal(err)
		}
	}
	ping(t, out)
}

// A peer that answers keeps the connection where it is, and so does an
// idle one: silence counts only after we sent something.
func TestAnsweredConnectionStays(t *testing.T) {
	_, out, _ := echoed(t, "healthy")
	before := out.LocalAddr().String()
	for end := time.Now().Add(2500 * time.Millisecond); time.Now().Before(end); time.Sleep(100 * time.Millisecond) {
		ping(t, out)
	}
	time.Sleep(1500 * time.Millisecond) // idle across watcher ticks
	if out.LocalAddr().String() != before {
		t.Fatal("a connection with an answering peer migrated")
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

// A datagram sent just after one arrived is likely a bare acknowledgment,
// which the peer never answers, so it doesn't start the wait; one sent
// later does.
func TestAckDoesntStartWait(t *testing.T) {
	p := &path{}
	p.lastRecv.Store(time.Now().UnixNano())
	p.sent()
	if p.waiting.Load() != 0 {
		t.Fatal("an acknowledgment of what just arrived started the wait")
	}
	p.lastRecv.Store(time.Now().Add(-2 * ackGrace).UnixNano())
	p.sent()
	if p.waiting.Load() == 0 {
		t.Fatal("a datagram sent well after the last arrival didn't start the wait")
	}
}

// A send error treated as loss still awaits an answer, so a path whose
// route is gone is judged stalled.
func TestSuppressedSendErrorStartsWait(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	p := newPath(c, netip.MustParseAddrPort("[2001:db8::1]:9"))
	defer p.close()
	if _, err := p.write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if p.waiting.Load() == 0 {
		t.Fatal("a send that failed as loss didn't start the wait")
	}
}

// A failed stall move leaves no request outstanding, so WatchNetwork's
// retries don't bypass the stall backoff.
func TestFailedStallMoveLeavesNoRequest(t *testing.T) {
	c := &Conn{e: &Endpoint{closed: true}, p: &path{}, outbound: true}
	w := time.Now().Add(-time.Hour).UnixNano()
	c.p.waiting.Store(w)
	if err := c.migrate(context.Background(), moveStall, stallMark{0, w}); err == nil {
		t.Fatal("setup: the stall move should fail on a closed endpoint")
	}
	if c.moveReqs.Load() != 0 || c.unmoved() {
		t.Fatal("a failed stall move left a request for WatchNetwork to retry")
	}
}

// A stall move queued behind another migration does nothing once the wait
// it judged is over: that migration replaced the path, the peer answered,
// or it answered and a fresh wait (not yet past the timeout) began.
func TestQueuedStallMoveSkipsReplacedPath(t *testing.T) {
	for _, tc := range []struct {
		name    string
		recover func(p *path)
	}{
		{"replaced", func(p *path) { p.mu.Lock(); p.gen++; p.mu.Unlock() }},
		{"answered", func(p *path) { p.waiting.Store(0) }},
		{"fresh wait", func(p *path) { p.waiting.Store(time.Now().UnixNano()) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A closed endpoint makes a move that runs fail, so a nil error
			// means it was skipped.
			c := &Conn{e: &Endpoint{closed: true}, p: &path{}, outbound: true}
			w := time.Now().Add(-time.Hour).UnixNano()
			c.p.waiting.Store(w)
			c.slotOnce.Do(func() { c.migrateSlot = make(chan struct{}, 1) })
			c.migrateSlot <- struct{}{} // another migration in flight
			done := make(chan error, 1)
			go func() { done <- c.migrate(context.Background(), moveStall, stallMark{0, w}) }()
			time.Sleep(50 * time.Millisecond)
			tc.recover(c.p)
			<-c.migrateSlot
			if err := <-done; err != nil {
				t.Fatalf("the queued stall move ran anyway: %v", err)
			}
		})
	}
}

// A healthy hysteria2 session left idle past a keepalive doesn't migrate:
// the bare acknowledgments QUIC sends get no answer, and must not look
// like a stall.
func TestIdleHysteria2DoesntStall(t *testing.T) {
	if testing.Short() {
		t.Skip("idles past a 10-second keepalive")
	}
	seed := network(t, 8)
	provider, caller := phone(t, seed), phone(t, seed)
	caller.stallTimeout.Store(int64(3 * time.Second))
	pk, ck := key("idle-provider"), key("idle-caller")
	listenAndWait(t, provider, pk)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	accepted := make(chan *Conn, 1)
	go func() {
		c, _ := provider.Accept(ctx)
		accepted <- c
	}()
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
	srv, err := hy2.Serve(ctx, in, pk, hy2.FromSecret(in.Secret, hy2.ObfsUTP), func(c net.Conn, _ string) { io.Copy(c, c) })
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	cl, err := hy2.Dial(ctx, out, out.Remote, out.PeerKey, hy2.FromSecret(out.Secret, hy2.ObfsUTP))
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	stream, err := cl.DialConn(ctx, "echo:1")
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	echo := func() {
		msg := []byte("still here")
		if _, err := stream.Write(msg); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(msg))
		_ = stream.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(stream, got); err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("echo: %v", err)
		}
	}
	echo()
	before := out.LocalAddr().String()
	time.Sleep(14 * time.Second) // past hysteria2's 10-second keepalive
	if out.LocalAddr().String() != before {
		t.Fatal("an idle, healthy session migrated")
	}
	echo()
}

// A path swap keeps when the peer was last heard from: an acknowledgment of
// what arrived on the old path, sent on the new one, mustn't start a wait.
func TestSwapKeepsAckGrace(t *testing.T) {
	var socks [2]*net.UDPConn
	for i := range socks {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		socks[i] = c
	}
	peer := netip.MustParseAddrPort("127.0.0.1:9")
	p := newPath(socks[0], peer)
	defer p.close()
	p.lastRecv.Store(time.Now().UnixNano())
	p.waiting.Store(time.Now().Add(-time.Hour).UnixNano())
	if !p.swap(1, socks[1], peer) {
		t.Fatal("setup: swap refused")
	}
	if p.waiting.Load() != 0 {
		t.Fatal("a swap kept the old path's wait")
	}
	p.sent()
	if p.waiting.Load() != 0 {
		t.Fatal("an acknowledgment just after a swap started a wait")
	}
}

// A datagram read from a socket swapped out since doesn't clear a wait
// begun on the new path.
func TestOldPathReadKeepsNewWait(t *testing.T) {
	p := &path{gen: 1}
	w := time.Now().UnixNano()
	p.waiting.Store(w)
	p.heard(0)
	if p.waiting.Load() != w {
		t.Fatal("a read from the old path cleared the new path's wait")
	}
	p.heard(1)
	if p.waiting.Load() != 0 {
		t.Fatal("an answer on the current path didn't clear the wait")
	}
}
