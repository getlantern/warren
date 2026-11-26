package driver

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/getlantern/warren/dht"
	"github.com/getlantern/warren/krpc"
	"github.com/getlantern/warren/overlay"
)

var farsi = overlay.NewKey("fa")

func memberConfig(ro bool) dht.Config {
	var id krpc.NodeID
	rand.Read(id[:])
	return dht.Config{
		ID:           farsi.Tag(krpc.SecureID(netip.MustParseAddr("127.0.0.1"), id)),
		Community:    &farsi,
		ReadOnly:     ro,
		Unrestricted: true, // every node shares 127.0.0.1
		QueryTimeout: time.Second,
	}
}

func network(t *testing.T, size int) []*Node {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var nodes []*Node
	for i := range size {
		n, err := Listen("127.0.0.1:0", memberConfig(false))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { n.Close() })
		if i > 0 {
			if _, err := n.Bootstrap(ctx, []netip.AddrPort{nodes[0].Addr()}); err != nil {
				t.Fatal(err)
			}
		}
		nodes = append(nodes, n)
	}
	// A second pass lets early joiners learn about later ones.
	for _, n := range nodes {
		n.Bootstrap(ctx, []netip.AddrPort{nodes[len(nodes)-1].Addr()})
	}
	return nodes
}

func TestLoopbackNetwork(t *testing.T) {
	nodes := network(t, 16)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	phone, err := Listen("127.0.0.1:0", memberConfig(true))
	if err != nil {
		t.Fatal(err)
	}
	defer phone.Close()
	if res, err := phone.Bootstrap(ctx, []netip.AddrPort{nodes[5].Addr()}); err != nil || len(res.Closest) == 0 {
		t.Fatalf("phone bootstrap: %v %+v", err, res)
	}

	v := dht.ImmutableValue([]byte("hello over real UDP"))
	target, put, err := nodes[3].Put(ctx, v)
	if err != nil || put.Stored < 3 {
		t.Fatalf("put: %v, stored on %d", err, put.Stored)
	}
	if got, err := phone.Get(ctx, target); err != nil || string(got) != string(v) {
		t.Fatalf("phone get: %v %q", err, got)
	}

	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	key := [32]byte(priv.Public().(ed25519.PublicKey))
	for seq := int64(1); seq <= 2; seq++ {
		m, _ := dht.NewMutable(priv, []byte("inbox"), seq, dht.ImmutableValue([]byte{byte('0' + seq)}))
		if res, err := nodes[7].PutMutable(ctx, m, nil); err != nil || res.Stored == 0 {
			t.Fatalf("mutable put seq %d: %v %+v", seq, err, res)
		}
	}
	if it, err := nodes[11].GetMutable(ctx, key, []byte("inbox")); err != nil || it == nil || it.Seq != 2 {
		t.Fatalf("mutable get: %v %+v", err, it)
	}

	// The phone must not appear in any routing table (BEP 43).
	for _, n := range nodes {
		n.Inspect(ctx, func(d *dht.Node) {
			if d.Knows(phone.Addr()) {
				t.Errorf("%s holds the read-only phone in its table", n.Addr())
			}
		})
	}
}

// A node restarted from its snapshot rejoins with no bootstrap server, as a
// phone must during a shutdown when every foreign seed is unreachable.
func TestRestartFromSnapshot(t *testing.T) {
	nodes := network(t, 12)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	target, _, err := nodes[2].Put(ctx, dht.ImmutableValue([]byte("survives restarts")))
	if err != nil {
		t.Fatal(err)
	}

	snap, err := nodes[9].Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	nodes[9].Close()
	id, contacts, err := dht.ParseSnapshot(snap)
	if err != nil || len(contacts) < 5 {
		t.Fatalf("snapshot: %v, %d contacts", err, len(contacts))
	}

	cfg := memberConfig(false)
	cfg.ID = id
	again, err := Listen("127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if res, err := again.Rejoin(ctx, contacts); err != nil || len(res.Closest) == 0 {
		t.Fatalf("rejoin: %v %+v", err, res)
	}
	if got, err := again.Get(ctx, target); err != nil || got == nil {
		t.Fatalf("get after restart: %v %q", err, got)
	}
}

func TestCloseUnblocksCallers(t *testing.T) {
	n, err := Listen("127.0.0.1:0", memberConfig(false))
	if err != nil {
		t.Fatal(err)
	}
	// A lookup toward an address that never answers is still pending when
	// the node closes.
	errc := make(chan error, 1)
	go func() {
		_, err := n.Bootstrap(context.Background(), []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:9")})
		errc <- err
	}()
	time.Sleep(50 * time.Millisecond)
	n.Close()
	select {
	case err := <-errc:
		if err != ErrClosed {
			t.Fatalf("err = %v, want ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("caller still blocked after Close")
	}
}

// Two read-only phones signal each other over real UDP through holders.
func TestSignalOverUDP(t *testing.T) {
	nodes := network(t, 12)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	phone := func() *Node {
		n, err := Listen("127.0.0.1:0", memberConfig(true))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { n.Close() })
		if _, err := n.Bootstrap(ctx, []netip.AddrPort{nodes[4].Addr()}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	provider, caller := phone(), phone()
	pk := ed25519.NewKeyFromSeed([]byte("provider-seed-provider-seed-0123"))
	if err := provider.Listen(ctx, pk); err != nil {
		t.Fatal(err)
	}
	go func() {
		for e := range provider.Events() {
			if in, ok := e.(dht.Incoming); ok {
				provider.Answer(ctx, in.Session, append([]byte("re: "), in.Payload...))
			}
		}
	}()
	// Let the record reach its holders.
	deadline := time.Now().Add(5 * time.Second)
	for {
		var holders int
		provider.Inspect(ctx, func(d *dht.Node) { holders = len(d.Holders()) })
		if holders > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("record never reached holders")
		}
		time.Sleep(20 * time.Millisecond)
	}
	start := time.Now()
	got, err := caller.Signal(ctx, ed25519.NewKeyFromSeed(make([]byte, 32)), [32]byte(pk.Public().(ed25519.PublicKey)), []byte("hello"))
	if err != nil || string(got) != "re: hello" {
		t.Fatalf("signal: %v %q", err, got)
	}
	t.Logf("signaled over real UDP in %v", time.Since(start))
}

// Consumers ranging over Events must stop when the node closes.
func TestEventsClosedOnShutdown(t *testing.T) {
	n, err := Listen("127.0.0.1:0", memberConfig(false))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		for range n.Events() {
		}
		close(done)
	}()
	n.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Events consumer still blocked after Close")
	}
}

func memberConfig6(ro bool) dht.Config {
	c := memberConfig(ro)
	var id krpc.NodeID
	rand.Read(id[:])
	c.ID = farsi.Tag(krpc.SecureID(netip.MustParseAddr("::1"), id))
	return c
}

// A dual-stack network: each node runs an IPv4 and an IPv6 node as
// siblings. A provider listening on both is reachable by an IPv4-only
// caller and by an IPv6-only one, and each answer goes back through the
// node that delivered the offer.
func TestDualStackSignal(t *testing.T) {
	probe, err := ListenDual("256.0.0.1:0", "[::1]:0", memberConfig(false), memberConfig6(false))
	if err != nil {
		t.Skip("no IPv6 loopback:", err)
	}
	probe.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	dual := func(ro bool) *Node {
		n, err := ListenDual("127.0.0.1:0", "[::1]:0", memberConfig(ro), memberConfig6(ro))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { n.Close() })
		if len(n.Addrs()) != 2 {
			t.Fatalf("dual node bound %v", n.Addrs())
		}
		return n
	}
	var nodes []*Node
	for i := range 12 {
		n := dual(false)
		if i > 0 {
			if _, err := n.Bootstrap(ctx, nodes[0].Addrs()); err != nil {
				t.Fatal(err)
			}
		}
		nodes = append(nodes, n)
	}
	for _, n := range nodes {
		n.Bootstrap(ctx, nodes[len(nodes)-1].Addrs())
	}

	provider := dual(true)
	mapped := nodes[3].Addrs()
	mapped[0] = netip.AddrPortFrom(netip.AddrFrom16(mapped[0].Addr().As16()), mapped[0].Port()) // ::ffff:127.0.0.1
	if _, err := provider.Bootstrap(ctx, mapped); err != nil {
		t.Fatal(err)
	}
	var size4 int
	provider.InspectEach(ctx, func(a netip.AddrPort, d *dht.Node) {
		if a.Addr().Is4() {
			c, m := d.RoutingSize()
			size4 = c + m
		}
	})
	if size4 == 0 {
		t.Fatal("an IPv4-mapped seed didn't bootstrap the IPv4 node")
	}
	if _, err := provider.Bootstrap(ctx, nil); err != nil {
		t.Fatalf("bootstrapping a dual node from its own tables: %v", err)
	}
	pk := ed25519.NewKeyFromSeed([]byte("provider-seed-provider-seed-0123"))
	if err := provider.Listen(ctx, pk); err != nil {
		t.Fatal(err)
	}
	var keys [][32]byte
	provider.InspectEach(ctx, func(_ netip.AddrPort, d *dht.Node) { keys = append(keys, d.SignalKey()) })
	if len(keys) != 2 || keys[0] != keys[1] || keys[0] == ([32]byte{}) {
		t.Fatal("the two families listen with different signaling keys, so their records conflict")
	}
	go func() {
		for e := range provider.Events() {
			if in, ok := e.(dht.Incoming); ok {
				provider.Answer(ctx, in.Session, append([]byte("re: "), in.Payload...))
			}
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		withHolders := 0
		provider.InspectEach(ctx, func(_ netip.AddrPort, d *dht.Node) {
			if len(d.Holders()) > 0 {
				withHolders++
			}
		})
		if withHolders == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("records reached holders on %d of 2 families", withHolders)
		}
		time.Sleep(20 * time.Millisecond)
	}

	only4, err := Listen("127.0.0.1:0", memberConfig(true))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { only4.Close() })
	only6, err := ListenDual("256.0.0.1:0", "[::1]:0", memberConfig(true), memberConfig6(true))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { only6.Close() })
	if a := only6.Addrs(); len(a) != 1 || a[0].Addr().Is4() {
		t.Fatalf("IPv6-only node bound %v", a)
	}
	for name, caller := range map[string]*Node{"IPv4-only": only4, "IPv6-only": only6} {
		if _, err := caller.Bootstrap(ctx, nodes[5].Addrs()); err != nil {
			t.Fatalf("%s bootstrap: %v", name, err)
		}
		got, err := caller.Signal(ctx, ed25519.NewKeyFromSeed(make([]byte, 32)), [32]byte(pk.Public().(ed25519.PublicKey)), []byte(name))
		if err != nil || string(got) != "re: "+name {
			t.Fatalf("%s caller: %v %q", name, err, got)
		}
	}
}

// An offer seen through one family is not delivered again through the
// other, an answer to an unknown session fails instead of guessing a
// family, and a flood evicts the oldest sessions rather than all of them.
func TestSessionsDedupedAcrossFamilies(t *testing.T) {
	n := &Node{sessions: map[dht.SessionID]int{}}
	in := dht.Incoming{Session: dht.SessionID{1}}
	delivered := 0
	for _, fam := range []int{0, 1} {
		if n.admitSession(fam, in) {
			delivered++
		}
	}
	if delivered != 1 {
		t.Fatalf("the same offer through both families was delivered %d times", delivered)
	}
	if n.sessions[in.Session] != 0 {
		t.Fatal("the replay through the other family moved the answer route")
	}
	for i := range maxSessions {
		n.admitSession(0, dht.Incoming{Session: dht.SessionID{2, byte(i), byte(i >> 8)}})
	}
	if _, ok := n.sessions[in.Session]; ok {
		t.Fatal("the oldest session survived a full table")
	}
	if len(n.sessions) != maxSessions {
		t.Fatalf("sessions holds %d, want %d", len(n.sessions), maxSessions)
	}
}

func TestAnswerUnknownSessionFails(t *testing.T) {
	n, err := Listen("127.0.0.1:0", memberConfig(false))
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	if err := n.Answer(context.Background(), dht.SessionID{9}, []byte("x")); !errors.Is(err, ErrUnknownSession) {
		t.Fatalf("answer to an unknown session: %v", err)
	}
}

// An offer dropped on a full events channel isn't recorded, so its copy
// through the other family is still delivered and answerable.
func TestDroppedOfferStillDeliverable(t *testing.T) {
	n := &Node{sessions: map[dht.SessionID]int{}, events: make(chan dht.Event)} // nobody reading: full
	in := dht.Incoming{Session: dht.SessionID{7}}
	n.deliverIncoming(0, in)
	n.events = make(chan dht.Event, 1)
	n.deliverIncoming(1, in)
	if len(n.events) != 1 || n.sessions[in.Session] != 1 {
		t.Fatalf("the copy through the other family wasn't delivered: %d queued, route %v", len(n.events), n.sessions)
	}
}

func TestPutAcknowledgementsAddUp(t *testing.T) {
	got := sumPuts([]dht.Event{dht.PutDone{Stored: 0}, dht.PutDone{Stored: 5, Domestic: 2}})
	if got.Stored != 5 || got.Domestic != 2 {
		t.Fatalf("summed acknowledgements %+v, want 5 stored, 2 domestic", got)
	}
}

// After a network change the provider rebinds onto a new address, and
// callers still reach it: its records are re-signed and republished, so
// holders forward offers to the new address instead of the dead one.
func TestRebindKeepsProviderReachable(t *testing.T) {
	nodes := network(t, 12)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	phone := func() *Node {
		n, err := Listen("127.0.0.1:0", memberConfig(true))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { n.Close() })
		if _, err := n.Bootstrap(ctx, []netip.AddrPort{nodes[4].Addr()}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	provider, caller := phone(), phone()
	pk := ed25519.NewKeyFromSeed([]byte("provider-seed-provider-seed-0123"))
	if err := provider.Listen(ctx, pk); err != nil {
		t.Fatal(err)
	}
	go func() {
		for e := range provider.Events() {
			if in, ok := e.(dht.Incoming); ok {
				provider.Answer(ctx, in.Session, append([]byte("re: "), in.Payload...))
			}
		}
	}()
	waitHolders := func() {
		t.Helper()
		for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
			var holders int
			provider.Inspect(ctx, func(d *dht.Node) { holders = len(d.Holders()) })
			if holders > 0 {
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("record never reached holders")
			}
		}
	}
	signal := func(msg string) error {
		sctx, scancel := context.WithTimeout(ctx, 10*time.Second)
		defer scancel()
		got, err := caller.Signal(sctx, ed25519.NewKeyFromSeed(make([]byte, 32)), [32]byte(pk.Public().(ed25519.PublicKey)), []byte(msg))
		if err == nil && string(got) != "re: "+msg {
			return fmt.Errorf("got %q", got)
		}
		return err
	}
	waitHolders()
	if err := signal("before"); err != nil {
		t.Fatalf("before rebind: %v", err)
	}
	before := provider.Addr()
	if err := provider.Rebind(ctx); err != nil {
		t.Fatal(err)
	}
	if after := provider.Addr(); after == before {
		t.Fatalf("rebind kept address %v", after)
	}
	if err := signal("after"); err != nil {
		t.Fatalf("after rebind, the provider was unreachable: %v", err)
	}
}

// A fixed port is reused on rebind; a dual-stack node rebinds both families.
func TestRebindPorts(t *testing.T) {
	var n *Node
	var fixed netip.AddrPort
	for range 10 { // another socket may take the probed port first
		probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		fixed = probe.LocalAddr().(*net.UDPAddr).AddrPort()
		probe.Close()
		if n, err = Listen(fixed.String(), memberConfig(false)); err == nil {
			break
		}
		if !errors.Is(err, syscall.EADDRINUSE) {
			t.Fatal(err)
		}
	}
	if n == nil {
		t.Skip("couldn't hold a fixed port")
	}
	defer n.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := n.Rebind(ctx); err != nil {
		t.Fatal(err)
	}
	if n.Addr() != fixed {
		// The documented fallback when another socket took the port in the
		// window between releasing and rebinding it; anything else is a bug.
		if c, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(fixed)); err == nil {
			c.Close()
			t.Fatalf("fixed port %v became %v after rebind, though the port is free", fixed, n.Addr())
		}
		t.Skip("another socket took the fixed port during rebind")
	}
	d, err := ListenDual("127.0.0.1:0", "[::1]:0", memberConfig(false), memberConfig6(false))
	if err != nil {
		t.Skip("no loopback to bind:", err)
	}
	defer d.Close() // before any skip: a single-family node is still running
	if len(d.Addrs()) != 2 {
		t.Skip("no dual-stack loopback")
	}
	before := d.Addrs()
	if err := d.Rebind(ctx); err != nil {
		t.Fatal(err)
	}
	after := d.Addrs()
	for i := range before {
		if before[i] == after[i] {
			t.Fatalf("family %d kept address %v across rebind", i, after[i])
		}
	}
}

// Rebinding right after Listen, before the first reader has run, mustn't
// hand a reader the replaced (or nil) socket.
func TestRebindRightAfterListen(t *testing.T) {
	for range 50 {
		probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		fixed := probe.LocalAddr().String()
		probe.Close()
		n, err := Listen(fixed, memberConfig(false))
		if err != nil {
			continue // the port was taken meanwhile
		}
		if err := n.Rebind(context.Background()); err != nil {
			t.Fatal(err)
		}
		n.Close()
	}
}

// A family whose rebind fails is stale until RebindStale binds it, and a
// rebind after Close installs nothing.
func TestStaleRebindRetried(t *testing.T) {
	n, err := Listen("127.0.0.1:0", memberConfig(false))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	listenUDP = func(string, *net.UDPAddr) (*net.UDPConn, error) { return nil, errors.New("no network yet") }
	err = n.Rebind(ctx)
	listenUDP = net.ListenUDP
	if err == nil {
		t.Fatal("a failed bind reported success")
	}
	if stale, _ := n.Stale(ctx); !stale {
		t.Fatal("the family whose rebind failed isn't marked stale")
	}
	socketless := make(chan bool, 1)
	n.do(ctx, func(time.Time) { socketless <- n.fams[0].conn == nil })
	if !<-socketless {
		t.Fatal("a failed rebind left the old network's socket in use")
	}
	before := n.Addr()
	if err := n.RebindStale(ctx); err != nil {
		t.Fatal(err)
	}
	if stale, _ := n.Stale(ctx); stale || n.Addr() == before {
		t.Fatalf("RebindStale didn't repair the family (stale=%v, addr %v)", stale, n.Addr())
	}
	n.Close()
	if err := n.Rebind(ctx); err == nil {
		t.Fatal("rebind after Close succeeded")
	}
}

// A packet from a socket that Rebind replaced is dropped: it belongs to the
// old network.
func TestPacketsFromReplacedSocketDropped(t *testing.T) {
	old, cur := &net.UDPConn{}, &net.UDPConn{}
	n := &Node{fams: []*family{{conn: cur}}}
	if n.current(packet{fam: 0, conn: old}) {
		t.Fatal("a packet from the replaced socket was accepted")
	}
	if !n.current(packet{fam: 0, conn: cur}) {
		t.Fatal("a packet from the present socket was dropped")
	}
}

// budget signs with k for its first n signatures, then fails.
type budget struct {
	k ed25519.PrivateKey
	n int
}

func (b *budget) Public() crypto.PublicKey { return b.k.Public() }
func (b *budget) Sign(r io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	if b.n <= 0 {
		return nil, errors.New("device gone")
	}
	b.n--
	return b.k.Sign(r, msg, opts)
}

// TestListenNeverSplitsIdentities: a signer that works for one family and
// fails for the other leaves neither listening under different keys.
func TestListenNeverSplitsIdentities(t *testing.T) {
	n, err := ListenDual("127.0.0.1:0", "[::1]:0", memberConfig(false), memberConfig6(false))
	if err != nil {
		t.Skip("no IPv6 loopback:", err)
	}
	defer n.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	old := ed25519.NewKeyFromSeed(make([]byte, 32))
	if err := n.Listen(ctx, old); err != nil {
		t.Fatal(err)
	}
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	if err := n.Listen(ctx, &budget{k: k, n: 1}); !errors.Is(err, dht.ErrSigner) {
		t.Fatalf("a signer failing for one family: %v", err)
	}
	keys := map[[32]byte]bool{}
	n.InspectEach(ctx, func(_ netip.AddrPort, d *dht.Node) {
		if pk, ok := d.Listening(); ok {
			keys[pk] = true
		}
	})
	if len(keys) > 1 {
		t.Fatalf("families listen under %d different keys", len(keys))
	}
}
