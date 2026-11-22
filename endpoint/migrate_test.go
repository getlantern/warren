package endpoint

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

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
