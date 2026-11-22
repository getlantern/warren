package endpoint

import (
	"bytes"
	"context"
	"io"
	"net"
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
	if provider.resumable(in.resume[:], pub(key("someone-else"))) != nil {
		t.Fatal("another caller could resume this connection")
	}
	if provider.resumable(in.resume[:], pub(key("resume-caller"))) != in {
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
	if e.resumable(first.resume[:], caller) != first {
		t.Fatal("a repeated secret took over a live connection's slot")
	}
	out := e.newConn(punched{sock: b}, caller, secret, key("me")) // an outbound one, same key and secret
	if e.resumable(first.resume[:], caller) != first || e.outConns[out.key()] != out {
		t.Fatal("inbound and outbound slots mixed")
	}
}
