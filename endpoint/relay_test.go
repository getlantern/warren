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

// hardPhone keeps its addresses from peers. On loopback a direct punch would
// succeed, so a relayed result proves RelayOnly is honored end to end.
func hardPhone(t *testing.T, seed netip.AddrPort) *Endpoint {
	t.Helper()
	e, err := New(Config{DHT: member(true), DHTAddr: "127.0.0.1:0", DataIP: net.IPv4(127, 0, 0, 1), RelayOnly: true})
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

// Two phones with no direct strategy connect through a router relay, then
// run hysteria2 over uTP shaping through it.
func TestRelayedConnectAndHysteria2(t *testing.T) {
	seed := network(t, 10)
	provider, caller := hardPhone(t, seed), hardPhone(t, seed)
	pk, ck := key("relayed provider"), key("relayed caller")
	listenAndWait(t, provider, pk)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	accepted := make(chan *Conn, 1)
	go func() {
		c, _ := provider.Accept(ctx)
		accepted <- c
	}()
	start := time.Now()
	out, err := caller.Connect(ctx, ck, pub(pk))
	if err != nil {
		t.Fatal(err)
	}
	in := <-accepted
	if in == nil || !out.Relayed || !in.Relayed {
		t.Fatalf("want relayed connections on both ends: caller %v, provider %v", out.Relayed, in != nil && in.Relayed)
	}
	if out.Remote != in.Remote {
		t.Errorf("ends use different relays: %s vs %s", out.Remote, in.Remote)
	}
	t.Logf("relayed connection via %s in %v", out.Remote, time.Since(start))

	srv, err := hy2.Serve(ctx, in.UDPConn, pk, hy2.FromSecret(in.Secret, hy2.ObfsUTP), func(c net.Conn, _ string) { io.Copy(c, c) })
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	cl, err := hy2.Dial(ctx, out.UDPConn, out.Remote, out.PeerKey, hy2.FromSecret(out.Secret, hy2.ObfsUTP))
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	stream, err := cl.DialConn(ctx, "echo:1")
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	msg := bytes.Repeat([]byte("through a volunteer relay "), 4000)
	go stream.Write(msg)
	got := make([]byte, len(msg))
	stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(stream, got); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("hysteria2 through the relay: %v", err)
	}
}
