package endpoint

import (
	"bytes"
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
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

	provider := dualPhone(t, seeds, true)
	out, in := connectPair(t, provider, dualPhone(t, seeds, true), "dual")
	if out.Remote.Addr().Is4() || in.Remote.Addr().Is4() {
		t.Fatalf("dual-stack peers connected over %v / %v, want IPv6", out.Remote, in.Remote)
	}
	roundTrip(t, out, in, "over v6")
	roundTrip(t, in, out, "and back")
	hysteria2Echo(t, out, in, key("dual"))
	// The caller signaled through both families' DHTs; the provider punched
	// and charged its limiter once.
	time.Sleep(300 * time.Millisecond) // let the second copy arrive
	if n := provider.limiter.chargesFor(pub(key("caller-dual"))); n != 1 {
		t.Fatalf("one dual-stack connect was charged %d times", n)
	}

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
	legs, err := e.legs(ctx, punch.Config{Initiator: true, Secret: make([]byte, 32)}, true, true, new(atomic.Int32))
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

// An offer is accepted once per caller and secret while a copy could still
// arrive, other callers are unaffected, and a flood evicts the oldest entry
// rather than refusing new offers.
func TestFirstOfferDedupes(t *testing.T) {
	e := &Endpoint{cfg: Config{GatherWait: time.Second, PunchDeadline: 6 * time.Second}}
	now := time.Unix(1_800_000_000, 0)
	secret := []byte("0123456789abcdef0123456789abcdef")
	alice, bob := [32]byte{1}, [32]byte{2}
	if !e.firstOffer(alice, secret, now) || e.firstOffer(alice, secret, now.Add(time.Second)) {
		t.Fatal("a repeated offer was accepted twice")
	}
	if !e.firstOffer(bob, secret, now.Add(time.Second)) {
		t.Fatal("another caller's offer was blocked by the first caller's entry")
	}
	if !e.firstOffer(alice, secret, now.Add(time.Minute)) {
		t.Fatal("an offer was remembered long after any copy could arrive")
	}
	for i := range 2 * maxRecentOffers {
		e.firstOffer([32]byte{3, byte(i), byte(i >> 8)}, secret, now.Add(time.Minute))
	}
	if len(e.offers) > maxRecentOffers {
		t.Fatalf("offer memory grew to %d", len(e.offers))
	}
	if !e.firstOffer([32]byte{4}, secret, now.Add(time.Minute)) {
		t.Fatal("a full table refused a new offer instead of evicting the oldest")
	}
}

// A relay-only endpoint that can't bind IPv4 fails at startup: it could
// never connect.
func TestRelayOnlyNeedsIPv4(t *testing.T) {
	_, err := New(Config{DHT: member(true), DHTAddr: "256.0.0.1:0", DHTAddr6: "[::1]:0", DHT6: member6(true), RelayOnly: true})
	if err == nil {
		t.Fatal("a relay-only endpoint started with no IPv4 socket")
	}
}

// The limiter is charged only for candidates a leg will actually probe: an
// IPv6-only listener isn't charged for a caller's IPv4 addresses.
func TestProbeableFiltersByFamily(t *testing.T) {
	cands := []netip.AddrPort{netip.MustParseAddrPort("2.10.0.1:4000"), netip.MustParseAddrPort("[2001:db8::1]:4000")}
	if got := probeable(cands, false, true); len(got) != 1 || got[0].Addr().Is4() {
		t.Fatalf("IPv6-only listener charged %v", got)
	}
	if got := probeable(cands, true, false); len(got) != 1 || !got[0].Addr().Is4() {
		t.Fatalf("IPv4-only listener charged %v", got)
	}
	if got := probeable(cands, true, true); len(got) != 2 {
		t.Fatalf("dual-stack listener charged %v", got)
	}
}

// A dual-stack endpoint whose IPv6 DHT node has no contacts (an IPv6 stack
// but no IPv6 peers) skips the IPv6 leg instead of waiting out a gather
// with nothing to reflect off.
func TestEmptyIPv6TableSkipsLeg(t *testing.T) {
	var seeds4 []netip.AddrPort
	for _, s := range dualNetwork(t, 6) {
		if s.Addr().Is4() {
			seeds4 = append(seeds4, s)
		}
	}
	e := dualPhone(t, seeds4, true)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	legs, err := e.legs(ctx, punch.Config{Initiator: true, Secret: make([]byte, 32)}, true, true, new(atomic.Int32))
	if err != nil {
		t.Fatal(err)
	}
	defer abortAll(legs)
	if took := time.Since(start); took > e.cfg.GatherWait/2 {
		t.Fatalf("preparing legs took %v with an empty IPv6 table", took)
	}
	for _, l := range legs {
		if l.v6 {
			t.Fatal("prepared an IPv6 leg with no IPv6 contacts")
		}
	}
}

// A provider runs an IPv4 leg only when the caller offered IPv4 candidates
// or relays, and an IPv6 leg only for IPv6 candidates it may punch.
func TestWantFamilies(t *testing.T) {
	v4c, v6c := netip.MustParseAddrPort("2.10.0.1:4000"), netip.MustParseAddrPort("[2001:db8::1]:4000")
	relay := netip.MustParseAddrPort("2.176.0.9:6881")
	for _, tc := range []struct {
		name         string
		o            punch.Offer
		relayOnly    bool
		want4, want6 bool
	}{
		{"IPv6-only caller", punch.Offer{Candidates: []netip.AddrPort{v6c}}, false, false, true},
		{"IPv4-only caller", punch.Offer{Candidates: []netip.AddrPort{v4c}}, false, true, false},
		{"dual caller", punch.Offer{Candidates: []netip.AddrPort{v4c, v6c}}, false, true, true},
		{"relay-only caller", punch.Offer{Relays: []netip.AddrPort{relay}}, false, true, false},
		{"relay-only listener", punch.Offer{Candidates: []netip.AddrPort{v6c}}, true, true, false},
	} {
		if v4, v6 := wantFamilies(tc.o, true, true, tc.relayOnly); v4 != tc.want4 || v6 != tc.want6 {
			t.Errorf("%s: legs v4=%v v6=%v, want v4=%v v6=%v", tc.name, v4, v6, tc.want4, tc.want6)
		}
	}
}
