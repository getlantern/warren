package endpoint

import (
	"bytes"
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
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
	// and charged its limiter once. Wait until the second copy has arrived.
	for deadline := time.Now().Add(5 * time.Second); provider.dupes.Load() == 0; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the offer's second copy never reached the provider")
		}
	}
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
// arrive, its copies share the first copy's answer, other callers are
// unaffected, and a flood evicts the oldest entry rather than refusing new
// offers.
func TestFirstOfferDedupes(t *testing.T) {
	e := &Endpoint{cfg: Config{GatherWait: time.Second, PunchDeadline: 6 * time.Second}}
	now := time.Unix(1_800_000_000, 0)
	secret := []byte("0123456789abcdef0123456789abcdef")
	alice, bob := [32]byte{1}, [32]byte{2}
	first := func(c [32]byte, at time.Time) bool { _, ok := e.firstOffer(c, secret, at); return ok }
	entry, ok := e.firstOffer(alice, secret, now)
	if !ok {
		t.Fatal("a new offer was treated as a copy")
	}
	copyEntry, ok := e.firstOffer(alice, secret, now.Add(time.Second))
	if ok || copyEntry != entry {
		t.Fatal("a repeated offer was accepted twice, or didn't share the first copy's entry")
	}
	// A copy arriving before the answer is queued, not left waiting; the
	// first copy answers it on publishing. Further copies get nothing.
	if _, now := copyEntry.copyOf(dht.SessionID{1}); now {
		t.Fatal("a copy was answered before there was an answer")
	}
	if _, now := copyEntry.copyOf(dht.SessionID{2}); now {
		t.Fatal("a third copy was answered")
	}
	queued := entry.publish([]byte("answer"))
	if len(queued) != 1 || queued[0] != (dht.SessionID{1}) {
		t.Fatalf("publishing returned queued copies %v, want just the first copy", queued)
	}
	if entry.publish(nil) != nil || string(entry.answer) != "answer" {
		t.Fatal("a later publish changed the answer")
	}
	late, ok := e.firstOffer(alice, secret, now.Add(2*time.Second))
	if ok {
		t.Fatal("a late copy was treated as new")
	}
	if _, now := late.copyOf(dht.SessionID{3}); now {
		t.Fatal("a copy beyond the cap was answered after publishing")
	}
	fresh := &offerEntry{done: make(chan struct{})}
	fresh.publish([]byte("ready"))
	if a, now := fresh.copyOf(dht.SessionID{4}); !now || string(a) != "ready" {
		t.Fatal("a copy arriving after the answer wasn't answered at once")
	}
	if !first(bob, now.Add(time.Second)) {
		t.Fatal("another caller's offer was blocked by the first caller's entry")
	}
	if !first(alice, now.Add(time.Minute)) {
		t.Fatal("an offer was remembered long after any copy could arrive")
	}
	for i := range 2 * maxRecentOffers {
		first([32]byte{3, byte(i), byte(i >> 8)}, now.Add(time.Minute))
	}
	if len(e.offers) > maxRecentOffers {
		t.Fatalf("offer memory grew to %d", len(e.offers))
	}
	if !first([32]byte{4}, now.Add(time.Minute)) {
		t.Fatal("a full table refused a new offer instead of evicting the oldest")
	}
}

// A relay-only endpoint that can't bind IPv4 fails at startup: it could
// never connect.
func TestRelayOnlyNeedsIPv4(t *testing.T) {
	probe, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skip("no IPv6 loopback:", err)
	}
	probe.Close()
	_, err = New(Config{DHT: member(true), DHTAddr: "256.0.0.1:0", DHTAddr6: "[::1]:0", DHT6: member6(true), RelayOnly: true})
	if err == nil || !strings.Contains(err.Error(), "relay-only needs an IPv4 socket") {
		t.Fatalf("relay-only with only IPv6 bound: %v, want the IPv4 prerequisite error", err)
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
	if has4, has6 := e.families(); !has4 || !has6 {
		t.Fatalf("the endpoint bound v4=%v v6=%v; the test needs an IPv6 node with an empty table", has4, has6)
	}
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

// A provider that can run no leg for an offer answers at once with an empty
// offer, so the caller fails fast instead of waiting out signaling.
func TestNoCommonFamilyFailsFast(t *testing.T) {
	seed := network(t, 8)
	provider, caller := phone(t, seed), phone(t, seed) // both IPv4-only
	pk := key("v6only-provider")
	listenAndWait(t, provider, pk)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// Offer only an IPv6 candidate, as an IPv6-only caller would.
	secret := make([]byte, 32)
	crand.Read(secret)
	offer := punch.Offer{Secret: secret, Candidates: []netip.AddrPort{netip.MustParseAddrPort("[2001:db8::1]:4000")}}
	start := time.Now()
	payload, err := caller.DHT().Signal(ctx, key("v6only-caller"), pub(pk), offer.Marshal())
	if err != nil {
		t.Fatalf("no answer: %v", err)
	}
	answer, err := punch.UnmarshalOffer(payload)
	if err != nil || len(answer.Candidates) != 0 {
		t.Fatalf("answer %+v, %v; want an empty offer", answer, err)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("the empty answer took %v", took)
	}
}

// A leg that already nominated keeps the shared claim when it fails: the
// responder may have connected on its path, so the other family mustn't
// nominate too. One that never committed gives the claim up.
func TestCommittedLegKeepsClaim(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	open := punch.Profile{Mapping: punch.MappingIndependent}
	owner := new(atomic.Int32)
	mk := func(id int32) *leg {
		s := punch.New(punch.Config{Initiator: true, Secret: secret, Local: open, Claim: claimer(owner, id), Rand: rand.New(rand.NewPCG(1, uint64(id)))})
		return &leg{sess: s, id: id, claim: owner}
	}

	idle := mk(1)
	if !claimer(owner, 1)() {
		t.Fatal("first claim refused")
	}
	idle.release()
	if owner.Load() != 0 {
		t.Fatal("an uncommitted leg kept the claim after failing")
	}

	// Drive a real nomination between an initiator leg and a responder.
	l := mk(2)
	resp := punch.New(punch.Config{Local: open, Rand: rand.New(rand.NewPCG(2, 2))})
	addrL, addrR := netip.MustParseAddrPort("198.51.100.1:40000"), netip.MustParseAddrPort("203.0.113.1:40000")
	now := time.Unix(1_800_000_000, 0)
	resp.Start(now, punch.Offer{Secret: secret, Candidates: []netip.AddrPort{addrL}, Profile: open})
	l.sess.Start(now, punch.Offer{Candidates: []netip.AddrPort{addrR}, Profile: open})
	for range 100 {
		now = now.Add(10 * time.Millisecond)
		l.sess.Tick(now)
		resp.Tick(now)
		sl, _ := l.sess.Drain()
		sr, _ := resp.Drain()
		for _, s := range sl {
			resp.HandlePacket(now, 0, addrL, s.Data)
		}
		for _, s := range sr {
			l.sess.HandlePacket(now, 0, addrR, s.Data)
		}
		if l.sess.Committed() {
			break
		}
	}
	if !l.sess.Committed() || owner.Load() != 2 {
		t.Fatalf("the leg never nominated (committed=%v, owner=%d)", l.sess.Committed(), owner.Load())
	}
	l.release()
	if owner.Load() != 2 {
		t.Fatal("a leg that nominated gave up the claim, so the other family could nominate too")
	}
}

// An offer that was never answered (publish nil) hands nothing to later
// copies.
func TestUnansweredOfferNotSentToCopies(t *testing.T) {
	o := &offerEntry{done: make(chan struct{})}
	o.publish(nil)
	if _, now := o.copyOf(dht.SessionID{1}); now {
		t.Fatal("a copy got an answer to an offer that was never answered")
	}
}
