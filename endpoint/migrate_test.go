package endpoint

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/getlantern/warren/punch"
	"github.com/getlantern/warren/transport/hy2"
)

// A hysteria2 stream keeps working while its connection migrates to a new
// punched path, whether the caller asks (Migrate) or the network changes
// under it (Rebind): both ends move onto fresh sockets, and QUIC above
// never notices.
func TestSessionSurvivesMigration(t *testing.T) {
	seed := network(t, 10)
	provider, caller := phone(t, seed), phone(t, seed)
	pk := key("migrating-provider")
	listenAndWait(t, provider, pk)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	accepted := make(chan *Conn, 1)
	go func() {
		c, _ := provider.Accept(ctx)
		accepted <- c
	}()
	out, err := caller.Connect(ctx, key("migrating-caller"), pub(pk))
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
	echo := func(msg string) {
		t.Helper()
		b := bytes.Repeat([]byte(msg), 500)
		if _, err := stream.Write(b); err != nil {
			t.Fatalf("write %q: %v", msg, err)
		}
		got := make([]byte, len(b))
		stream.SetReadDeadline(time.Now().Add(15 * time.Second))
		if _, err := io.ReadFull(stream, got); err != nil || !bytes.Equal(got, b) {
			t.Fatalf("echo %q: %v", msg, err)
		}
	}
	echo("before ")

	outAddr, inAddr := out.LocalAddr().String(), in.LocalAddr().String()
	if err := out.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// Migrate returns once the caller has moved; the provider swaps in its
	// own worker, possibly a moment later.
	for deadline := time.Now().Add(5 * time.Second); in.LocalAddr().String() == inAddr && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if out.LocalAddr().String() == outAddr || in.LocalAddr().String() == inAddr {
		t.Fatalf("both ends should be on new sockets: caller %v→%v, provider %v→%v", outAddr, out.LocalAddr(), inAddr, in.LocalAddr())
	}
	echo("after migrate ")

	outAddr = out.LocalAddr().String()
	if err := caller.Rebind(ctx); err != nil {
		t.Fatalf("rebind: %v", err)
	}
	if out.LocalAddr().String() == outAddr {
		t.Fatal("Rebind didn't migrate the outbound connection")
	}
	echo("after rebind ")
}

// A resume offer moves only a live inbound connection of the same caller;
// one naming no such connection fails fast instead of punching.
func TestResumeNeedsTheSameCaller(t *testing.T) {
	seed := network(t, 8)
	provider, caller := phone(t, seed), phone(t, seed)
	pk := key("resume-provider")
	listenAndWait(t, provider, pk)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	accepted := make(chan *Conn, 1)
	go func() {
		c, _ := provider.Accept(ctx)
		accepted <- c
	}()
	out, err := caller.Connect(ctx, key("resume-caller"), pub(pk))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	in := <-accepted
	defer in.Close()
	if provider.resumable(in.resume, pub(key("someone-else"))) != nil {
		t.Fatal("another caller could resume this connection")
	}
	if provider.resumable(in.resume, pub(key("resume-caller"))) != in {
		t.Fatal("the connection's own caller couldn't resume it")
	}
	in.Close() // the provider's side is gone: a resume names nothing
	start := time.Now()
	if err := out.Migrate(ctx); err == nil {
		t.Fatal("migrating to a closed connection succeeded")
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("a resume naming no connection took %v to fail", took)
	}
	if err := in.Migrate(ctx); err != ErrNotCaller {
		t.Fatalf("an inbound connection migrated itself: %v", err)
	}
}

// A repeat of a live connection's secret from the same caller can't take
// over its registry slot, and inbound and outbound slots never mix.
func TestRegistrySlotsCantBeTakenOver(t *testing.T) {
	e := &Endpoint{}
	a, b := &net.UDPConn{}, &net.UDPConn{}
	secret := []byte("0123456789abcdef0123456789abcdef")
	caller := [32]byte{1}
	first := e.newConn(punched{sock: a}, caller, secret, nil)
	e.newConn(punched{sock: b}, caller, secret, nil) // same caller, same secret
	if e.resumable(first.resume, caller) != first {
		t.Fatal("a repeated secret took over a live connection's slot")
	}
	out := e.newConn(punched{sock: b}, caller, secret, key("me")) // an outbound one, same key and secret
	if e.resumable(first.resume, caller) != first || e.outConns[out.key()] != out {
		t.Fatal("inbound and outbound slots mixed")
	}
}

// A write that chose the old socket just before a swap closed it follows
// the path to the new socket instead of failing (QUIC treats a write error
// as fatal).
func TestWriteFollowsSwap(t *testing.T) {
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	listen := func() *net.UDPConn {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	remote := peer.LocalAddr().(*net.UDPAddr).AddrPort()
	p := newPath(listen(), remote)
	defer p.close()
	next := listen()
	once := false
	p.testHookWrite = func() {
		if !once {
			once = true
			p.swap(1, next, remote) // closes the socket the write already chose
		}
	}
	if _, err := p.write([]byte("x")); err != nil {
		t.Fatalf("a write racing a swap failed: %v", err)
	}
	buf := make([]byte, 8)
	peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, from, err := peer.ReadFromUDPAddrPort(buf); err != nil || from.Port() != next.LocalAddr().(*net.UDPAddr).AddrPort().Port() {
		t.Fatalf("the datagram didn't go out the new socket: %v from %v", err, from)
	}
}

// A slow resume can't overwrite a newer one: the path takes only a newer
// migration's socket.
func TestOlderMigrationCantOverwriteNewer(t *testing.T) {
	listen := func() *net.UDPConn {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	remote := netip.MustParseAddrPort("127.0.0.1:9")
	p := newPath(listen(), remote)
	defer p.close()
	b, a := listen(), listen()
	if !p.swap(2, b, remote) {
		t.Fatal("migration 2 refused")
	}
	if p.swap(1, a, remote) {
		t.Fatal("migration 1, finishing late, overwrote migration 2")
	}
	a.Close()
	if sock, _, _ := p.current(); sock != b {
		t.Fatal("the path left migration 2's socket")
	}
}

// A migratable connection keeps QUIC from path MTU discovery: a size found
// on one network would be dropped on a smaller-MTU network after a move.
func TestConnReportsNoDontFragment(t *testing.T) {
	if (&Conn{}).DontFragment() {
		t.Fatal("a migratable connection invites path MTU discovery")
	}
}

// Rebind migrates outbound connections even when a DHT family failed to
// rebind, and leaves the work pending for WatchNetwork.
func TestRebindMigratesDespiteDHTError(t *testing.T) {
	seed := network(t, 8)
	provider, caller := phone(t, seed), phone(t, seed)
	pk := key("partial-provider")
	listenAndWait(t, provider, pk)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	accepted := make(chan *Conn, 1)
	go func() {
		c, _ := provider.Accept(ctx)
		accepted <- c
	}()
	out, err := caller.Connect(ctx, key("partial-caller"), pub(pk))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	if in := <-accepted; in != nil {
		defer in.Close()
	}
	caller.rebindDHT = func(context.Context) error { return errors.New("udp6: no network yet") }
	before := out.LocalAddr().String()
	if err := caller.Rebind(ctx); err == nil {
		t.Fatal("a DHT rebind error wasn't reported")
	}
	if out.LocalAddr().String() == before {
		t.Fatal("a DHT rebind error stopped the connection from migrating")
	}
	if !caller.migratePending.Load() {
		t.Fatal("the failed rebind wasn't left pending for WatchNetwork")
	}
}

// Resumes have their own per-connection budget, so moving several sessions
// to one provider isn't refused by the new-connection limiter, while one
// connection can't be resumed without bound.
func TestResumeBudget(t *testing.T) {
	c := &Conn{}
	now := time.Unix(1_800_000_000, 0)
	for i := range maxResumesPerMinute {
		if !c.allowResume(now) {
			t.Fatalf("resume %d refused within the budget", i)
		}
	}
	if c.allowResume(now) {
		t.Fatal("a resume past the budget was allowed")
	}
	if !c.allowResume(now.Add(time.Minute)) {
		t.Fatal("the budget didn't refill after a minute")
	}
}

// Several live sessions to one provider all migrate together: the
// new-connection limiter (a few punches a minute per caller) doesn't apply
// to resumes.
func TestManySessionsMigrateTogether(t *testing.T) {
	seed := network(t, 8)
	provider, caller := phone(t, seed), phone(t, seed)
	pk := key("busy-provider")
	listenAndWait(t, provider, pk)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	go func() {
		for {
			c, err := provider.Accept(ctx)
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	var outs []*Conn
	for range 3 { // the new-connection limiter allows 3 a minute per caller
		out, err := caller.Connect(ctx, key("busy-caller"), pub(pk))
		if err != nil {
			t.Fatal(err)
		}
		defer out.Close()
		outs = append(outs, out)
	}
	if err := caller.Rebind(ctx); err != nil {
		t.Fatalf("migrating %d sessions to one provider: %v", len(outs), err)
	}
}

// A retry after a partial failure re-migrates only the connections that
// didn't move.
func TestRetryLeavesMovedConnectionsAlone(t *testing.T) {
	seed := network(t, 8)
	provider, caller := phone(t, seed), phone(t, seed)
	pk := key("retry-provider")
	listenAndWait(t, provider, pk)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	go func() {
		c, _ := provider.Accept(ctx)
		if c != nil {
			defer c.Close()
			<-ctx.Done()
		}
	}()
	out, err := caller.Connect(ctx, key("retry-caller"), pub(pk))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	if err := caller.migrateAll(ctx, false); err != nil {
		t.Fatal(err)
	}
	moved := out.LocalAddr().String()
	if err := caller.migrateAll(ctx, true); err != nil {
		t.Fatal(err)
	}
	if out.LocalAddr().String() != moved {
		t.Fatal("a retry re-migrated a connection that had already moved")
	}
	// One a failed rebind left unmoved, then recovered by an explicit
	// Migrate, is left alone by retries too.
	out.moveReqs.Add(1) // a request a failed rebind left outstanding
	if err := out.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if out.unmoved() {
		t.Fatal("a successful Migrate left the connection marked unmoved")
	}
}

// Two network changes in quick succession don't collide: the second rebind
// waits for the first and migrates again, so neither fails with a
// migration in progress and nothing is left falsely settled.
func TestConcurrentRebindsSerialize(t *testing.T) {
	seed := network(t, 8)
	provider, caller := phone(t, seed), phone(t, seed)
	pk := key("twice-provider")
	listenAndWait(t, provider, pk)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	go func() {
		c, _ := provider.Accept(ctx)
		if c != nil {
			defer c.Close()
			<-ctx.Done()
		}
	}()
	out, err := caller.Connect(ctx, key("twice-caller"), pub(pk))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	errs := make(chan error, 2)
	for range 2 {
		go func() { errs <- caller.Rebind(ctx) }()
	}
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatalf("overlapping rebinds collided: %v", err)
		}
	}
	if caller.migratePending.Load() || out.unmoved() {
		t.Fatal("overlapping rebinds left the connection marked unmoved")
	}
}

// A rebind waiting behind another gives up when its context ends, and
// leaves the work pending for the watcher.
func TestQueuedRebindCancels(t *testing.T) {
	e := &Endpoint{}
	if err := e.lockRebind(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer e.unlockRebind()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := e.Rebind(ctx); err == nil {
		t.Fatal("a queued rebind succeeded while another held the slot")
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("a canceled queued rebind waited %v", took)
	}
	if e.rebindDone.Load() >= e.rebindReqs.Load() {
		t.Fatal("a canceled rebind didn't leave its request outstanding")
	}
}

// A request outstanding because its caller gave up is served by the
// watcher's next check, with no route change needed.
func TestWatcherServesOutstandingRebind(t *testing.T) {
	seed := network(t, 4)
	e := phone(t, seed)
	e.routes = func() [2]netip.Addr { return [2]netip.Addr{netip.MustParseAddr("192.168.1.5")} }
	e.rebindReqs.Add(1) // a Rebind that gave up waiting
	before := e.DHT().Addr()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.WatchNetwork(ctx, 10*time.Millisecond)
	for deadline := time.Now().Add(3 * time.Second); e.DHT().Addr() == before; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the watcher never served the outstanding rebind")
		}
	}
	for deadline := time.Now().Add(3 * time.Second); e.rebindDone.Load() < e.rebindReqs.Load(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the request stayed outstanding after the watcher's rebind")
		}
	}
}

// A send that fails mid-handover (network unreachable, no route yet) is
// packet loss to QUIC, not an error that would end the session; a closed
// path still reports its error.
func TestHandoverSendErrorsAreLoss(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	// An IPv6 destination from an IPv4 socket fails like an unreachable
	// network would.
	p := newPath(c, netip.MustParseAddrPort("[2001:db8::1]:9"))
	if n, err := p.write([]byte("x")); err != nil || n != 1 {
		t.Fatalf("a send error mid-handover reached the protocol: %d, %v", n, err)
	}
	p.close()
	if _, err := p.write([]byte("x")); err == nil {
		t.Fatal("a write on a closed path reported success")
	}
}

// A rebind canceled before its DHT rebind ran stays outstanding, so the
// watcher reruns it.
func TestCanceledRebindStaysOutstanding(t *testing.T) {
	e := &Endpoint{rebindDHT: func(ctx context.Context) error { return context.Canceled }}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e.rebindDHT = func(context.Context) error { return ctx.Err() }
	_ = e.Rebind(context.Background())
	if e.rebindDone.Load() >= e.rebindReqs.Load() {
		t.Fatal("a rebind canceled before its DHT rebind was acknowledged")
	}
}

// A migration that arrives while an older one is in flight waits and then
// runs, rather than being refused: the newer network change always runs
// last, and the connection ends up moved and unmarked.
func TestNewerMigrationWaitsForOlder(t *testing.T) {
	seed := network(t, 8)
	provider, caller := phone(t, seed), phone(t, seed)
	pk := key("serial-provider")
	listenAndWait(t, provider, pk)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	go func() {
		c, _ := provider.Accept(ctx)
		if c != nil {
			defer c.Close()
			<-ctx.Done()
		}
	}()
	out, err := caller.Connect(ctx, key("serial-caller"), pub(pk))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	errs := make(chan error, 2)
	for range 2 {
		go func() { errs <- out.Migrate(ctx) }()
	}
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatalf("a concurrent migration was refused or failed: %v", err)
		}
	}
	if out.unmoved() || out.migrations != 2 {
		t.Fatalf("after two migrations: unmoved=%v, migrations=%d", out.unmoved(), out.migrations)
	}
}

// A newer migration request that gave up waiting behind an older one stays
// outstanding when the older one then succeeds, so retries still move the
// connection.
func TestOlderMigrationCantSettleNewerRequest(t *testing.T) {
	c := &Conn{outbound: true}
	c.moveReqs.Add(1)            // the older migration's request
	serving := c.moveReqs.Load() // what it saw when it took the slot
	c.moveReqs.Add(1)            // a newer request, which gave up waiting
	c.moveDone.Store(serving)    // the older migration succeeds
	if !c.unmoved() {
		t.Fatal("an older migration's success settled a newer request")
	}
}

// A resume naming no live connection is answered at once even when every
// punch slot is busy.
func TestUnknownResumeAnsweredWithoutSlot(t *testing.T) {
	seed := network(t, 8)
	provider, caller := phone(t, seed), phone(t, seed)
	pk := key("full-provider")
	listenAndWait(t, provider, pk)
	for len(provider.slots) < cap(provider.slots) {
		provider.slots <- struct{}{} // every slot busy
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	secret := make([]byte, 32)
	crand.Read(secret)
	offer := punch.Offer{Secret: secret, Resume: resumeOffer([16]byte{1}, 1)}
	start := time.Now()
	payload, err := caller.DHT().Signal(ctx, key("full-caller"), pub(pk), offer.Marshal())
	if err != nil {
		t.Fatalf("no answer to an unknown resume with slots full: %v", err)
	}
	if answer, err := punch.UnmarshalOffer(payload); err != nil || len(answer.Candidates) != 0 {
		t.Fatalf("answer %+v, %v; want an empty offer", answer, err)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("the empty answer took %v", took)
	}
}
