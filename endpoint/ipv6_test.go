package endpoint

import (
	"bytes"
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/getlantern/warren/dht"
	"github.com/getlantern/warren/driver"
	"github.com/getlantern/warren/krpc"
	"github.com/getlantern/warren/punch"
	"github.com/getlantern/warren/transport/hy2"
)

func member6(ro bool) dht.Config {
	c := member(ro)
	var id krpc.NodeID
	crand.Read(id[:])
	c.ID = farsi.Tag(krpc.SecureID(netip.MustParseAddr("::1"), id))
	return c
}

// dualNetwork starts dual-stack DHT routers on loopback and returns seed
// addresses of both families.
func dualNetwork(t *testing.T, size int) []netip.AddrPort {
	t.Helper()
	probe, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skip("no IPv6 loopback:", err)
	}
	probe.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var nodes []*driver.Node
	for i := range size {
		n, err := driver.ListenDual("127.0.0.1:0", "[::1]:0", member(false), member6(false))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { n.Close() })
		if i > 0 {
			n.Bootstrap(ctx, nodes[0].Addrs())
		}
		nodes = append(nodes, n)
	}
	for _, n := range nodes {
		n.Bootstrap(ctx, nodes[len(nodes)-1].Addrs())
	}
	return nodes[0].Addrs()
}

func dualPhone(t *testing.T, seeds []netip.AddrPort, dual bool) *Endpoint {
	t.Helper()
	cfg := Config{DHT: member(true), DHTAddr: "127.0.0.1:0", DataIP: net.IPv4(127, 0, 0, 1)}
	if dual {
		cfg.DHTAddr6, cfg.DHT6, cfg.DataIP6 = "[::1]:0", member6(true), net.IPv6loopback
	}
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := e.DHT().Bootstrap(ctx, seeds); err != nil {
		t.Fatal(err)
	}
	return e
}

func connectPair(t *testing.T, provider, caller *Endpoint, pkSeed string) (out, in *Conn) {
	t.Helper()
	pk, ck := key(pkSeed), key("caller-"+pkSeed)
	listenAndWait(t, provider, pk)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
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
	t.Cleanup(func() { out.Close() })
	in = <-accepted
	if in == nil {
		t.Fatal("nothing accepted")
	}
	t.Cleanup(func() { in.Close() })
	return out, in
}

// Two dual-stack endpoints connect over IPv6, which gets a head start; a
// dual-stack caller reaching an IPv4-only provider falls back to IPv4.
func TestDualStackConnectPrefersIPv6(t *testing.T) {
	seeds := dualNetwork(t, 10)

	out, in := connectPair(t, dualPhone(t, seeds, true), dualPhone(t, seeds, true), "dual")
	if out.Remote.Addr().Is4() || in.Remote.Addr().Is4() {
		t.Fatalf("dual-stack peers connected over %v / %v, want IPv6", out.Remote, in.Remote)
	}
	roundTrip(t, out, in, "over v6")
	roundTrip(t, in, out, "and back")
	hysteria2Echo(t, out, in, key("dual"))

	out, in = connectPair(t, dualPhone(t, seeds, false), dualPhone(t, seeds, true), "v4only")
	if !out.Remote.Addr().Is4() || !in.Remote.Addr().Is4() {
		t.Fatalf("with an IPv4-only provider, connected over %v / %v, want IPv4", out.Remote, in.Remote)
	}
	roundTrip(t, out, in, "over v4")
}

// hysteria2Echo runs hysteria2 shaped as uTP over a punched path and
// echoes a stream through it.
func hysteria2Echo(t *testing.T, out, in *Conn, pk ed25519.PrivateKey) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	srv, err := hy2.Serve(ctx, in.UDPConn, pk, hy2.FromSecret(in.Secret, hy2.ObfsUTP), func(c net.Conn, _ string) {
		io.Copy(c, c)
	})
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
	msg := bytes.Repeat([]byte("over a punched IPv6 path "), 2000)
	go stream.Write(msg)
	got := make([]byte, len(msg))
	stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(stream, got); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("echo over hysteria2: %v", err)
	}
}

// A relay-only endpoint never prepares an IPv6 leg: it would punch
// directly and reveal our address.
func TestRelayOnlyNeverUsesIPv6(t *testing.T) {
	seeds := dualNetwork(t, 6)
	e, err := New(Config{DHT: member(true), DHTAddr: "127.0.0.1:0", DataIP: net.IPv4(127, 0, 0, 1),
		DHTAddr6: "[::1]:0", DHT6: member6(true), DataIP6: net.IPv6loopback, RelayOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := e.DHT().Bootstrap(ctx, seeds); err != nil {
		t.Fatal(err)
	}
	legs, err := e.legs(ctx, punch.Config{Initiator: true, Secret: make([]byte, 32)}, true)
	if err != nil {
		t.Fatal(err)
	}
	defer abortAll(legs)
	for _, l := range legs {
		if l.v6 {
			t.Fatal("a relay-only endpoint prepared an IPv6 leg")
		}
	}
	for _, c := range offerOf(legs).Candidates {
		if !c.Addr().Is4() {
			t.Fatalf("a relay-only offer carries IPv6 candidate %v", c)
		}
	}
}
