package endpoint

import (
	"context"
	"crypto"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/getlantern/warren/dht"
	"github.com/getlantern/warren/driver"
	"github.com/getlantern/warren/group/keys"
	"github.com/getlantern/warren/krpc"
	"github.com/getlantern/warren/overlay"
)

var farsi = overlay.NewKey("fa")

func member(ro bool) dht.Config {
	var id krpc.NodeID
	crand.Read(id[:])
	return dht.Config{
		ID:           farsi.Tag(krpc.SecureID(netip.MustParseAddr("127.0.0.1"), id)),
		Community:    &farsi,
		ReadOnly:     ro,
		Unrestricted: true,
		QueryTimeout: time.Second,
	}
}

func key(seed string) ed25519.PrivateKey {
	s := sha256.Sum256([]byte(seed))
	return ed25519.NewKeyFromSeed(s[:])
}

func pub(k ed25519.PrivateKey) [32]byte { return [32]byte(k.Public().(ed25519.PublicKey)) }

// network starts DHT routers on loopback and returns a seed address.
func network(t *testing.T, size int) netip.AddrPort {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var nodes []*driver.Node
	for i := range size {
		n, err := driver.Listen("127.0.0.1:0", member(false))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { n.Close() })
		if i > 0 {
			n.Bootstrap(ctx, []netip.AddrPort{nodes[0].Addr()})
		}
		nodes = append(nodes, n)
	}
	for _, n := range nodes {
		n.Bootstrap(ctx, []netip.AddrPort{nodes[len(nodes)-1].Addr()})
	}
	return nodes[0].Addr()
}

func phone(t *testing.T, seed netip.AddrPort) *Endpoint {
	t.Helper()
	e, err := New(Config{DHT: member(true), DHTAddr: "127.0.0.1:0", DataIP: net.IPv4(127, 0, 0, 1)})
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

func listenAndWait(t *testing.T, e *Endpoint, k crypto.Signer) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := e.Listen(ctx, k); err != nil {
		t.Fatal(err)
	}
	for {
		var holders int
		e.DHT().Inspect(ctx, func(d *dht.Node) { holders = len(d.Holders()) })
		if holders > 0 {
			return
		}
		if ctx.Err() != nil {
			t.Fatal("record never reached holders")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func roundTrip(t *testing.T, from, to *Conn, msg string) {
	t.Helper()
	if err := from.Send([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	to.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 128)
	n, err := to.Recv(buf)
	if err != nil || string(buf[:n]) != msg {
		t.Fatalf("read: %v %q", err, buf[:n])
	}
}

func TestConnectByPublicKey(t *testing.T) {
	seed := network(t, 10)
	provider, caller := phone(t, seed), phone(t, seed)
	pk, ck := key("provider"), key("caller")
	listenAndWait(t, provider, pk)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	accepted := make(chan *Conn, 1)
	go func() {
		c, err := provider.Accept(ctx)
		if err != nil {
			t.Error(err)
		}
		accepted <- c
	}()
	start := time.Now()
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
	t.Logf("connected by public key in %v", time.Since(start))

	if out.PeerKey != pub(pk) || in.PeerKey != pub(ck) {
		t.Errorf("peer keys: caller sees %x, provider sees %x", out.PeerKey[:4], in.PeerKey[:4])
	}
	if string(out.Secret) != string(in.Secret) || len(out.Secret) != 32 {
		t.Error("ends do not share the session secret")
	}
	roundTrip(t, out, in, "hello provider")
	roundTrip(t, in, out, "hello caller")
}

// TestConnectUnderBlindedKeys: both ends sign with blinded keys, which
// have no seed and so aren't ed25519.PrivateKeys; the caller reaches the
// provider by its blinded public key, and each sees the other's.
func TestConnectUnderBlindedKeys(t *testing.T) {
	seed := network(t, 10)
	provider, caller := phone(t, seed), phone(t, seed)
	var g keys.Secret
	g[0] = 7
	pk := keys.CryptoSigner(keys.IdentityFromSeed([32]byte{1}).Rendezvous(g, 42))
	ck := keys.CryptoSigner(keys.IdentityFromSeed([32]byte{2}).Rendezvous(g, 42))
	listenAndWait(t, provider, pk)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	accepted := make(chan *Conn, 1)
	go func() {
		c, err := provider.Accept(ctx)
		if err != nil {
			t.Error(err)
		}
		accepted <- c
	}()
	ppub, cpub := [32]byte(pk.Public().(ed25519.PublicKey)), [32]byte(ck.Public().(ed25519.PublicKey))
	out, err := caller.Connect(ctx, ck, ppub)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	in := <-accepted
	if in == nil {
		t.Fatal("nothing accepted")
	}
	defer in.Close()
	if out.PeerKey != ppub || in.PeerKey != cpub {
		t.Errorf("peer keys: caller sees %x, provider sees %x", out.PeerKey[:4], in.PeerKey[:4])
	}
	roundTrip(t, out, in, "hello, blinded provider")
}

func TestConnectRefusesBadSigner(t *testing.T) {
	seed := network(t, 4)
	e := phone(t, seed)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var nilKey ed25519.PrivateKey
	for _, s := range []crypto.Signer{nil, nilKey, keys.CryptoSigner(nil)} {
		if _, err := e.Connect(ctx, s, [32]byte{1}); !errors.Is(err, dht.ErrSigner) {
			t.Fatalf("connect with signer %T: %v", s, err)
		}
	}
	if err := e.Listen(ctx, nil); err == nil {
		t.Fatal("listened with no signer")
	}
}

func TestConcurrentCallers(t *testing.T) {
	seed := network(t, 10)
	provider := phone(t, seed)
	pk := key("busy provider")
	listenAndWait(t, provider, pk)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const callers = 3
	got := make(chan [32]byte, callers)
	go func() {
		for range callers {
			c, err := provider.Accept(ctx)
			if err != nil {
				return
			}
			got <- c.PeerKey
			c.Close()
		}
	}()
	var wg sync.WaitGroup
	for i := range callers {
		c := phone(t, seed)
		wg.Go(func() {
			conn, err := c.Connect(ctx, key(fmt.Sprint("caller ", i)), pub(pk))
			if err != nil {
				t.Errorf("caller %d: %v", i, err)
				return
			}
			conn.Close()
		})
	}
	wg.Wait()
	seen := map[[32]byte]bool{}
	for range callers {
		select {
		case k := <-got:
			seen[k] = true
		case <-ctx.Done():
			t.Fatalf("accepted %d of %d", len(seen), callers)
		}
	}
	if len(seen) != callers {
		t.Fatalf("accepted %d distinct callers, want %d", len(seen), callers)
	}
}

func TestConnectUnknownKey(t *testing.T) {
	seed := network(t, 8)
	caller := phone(t, seed)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := caller.Connect(ctx, key("caller"), pub(key("nobody")))
	if err != dht.ErrNoRecord {
		t.Fatalf("err = %v, want ErrNoRecord", err)
	}
}

func TestAuthorizeRejects(t *testing.T) {
	seed := network(t, 10)
	pk, allowed, denied := key("picky"), key("friend"), key("stranger")
	provider, err := New(Config{
		DHT: member(true), DHTAddr: "127.0.0.1:0", DataIP: net.IPv4(127, 0, 0, 1),
		Authorize: func(c [32]byte) bool { return c == pub(allowed) },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	provider.DHT().Bootstrap(ctx, []netip.AddrPort{seed})
	listenAndWait(t, provider, pk)
	go func() {
		for {
			c, err := provider.Accept(ctx)
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	caller := phone(t, seed)
	// A rejected caller gets silence rather than a refusal, so a probe learns
	// nothing beyond the public record; it fails when its own deadline ends.
	deny, cancelDeny := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelDeny()
	if _, err := caller.Connect(deny, denied, pub(pk)); err == nil {
		t.Fatal("unauthorized caller connected")
	}
	allow, cancelAllow := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelAllow()
	if c, err := caller.Connect(allow, allowed, pub(pk)); err != nil {
		t.Fatalf("authorized caller: %v", err)
	} else {
		c.Close()
	}
}

// A punched connection nobody accepted is closed with the endpoint.
func TestCloseClosesUnaccepted(t *testing.T) {
	seed := network(t, 10)
	provider, caller := phone(t, seed), phone(t, seed)
	pk := key("unaccepted")
	listenAndWait(t, provider, pk)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := caller.Connect(ctx, key("c"), pub(pk)); err != nil {
		t.Fatal(err)
	}
	var pending *Conn
	for deadline := time.Now().Add(5 * time.Second); pending == nil; {
		select {
		case pending = <-provider.accept:
			provider.accept <- pending
		default:
			if time.Now().After(deadline) {
				t.Fatal("no inbound connection queued")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	provider.Close()
	if err := pending.Send([]byte("x")); err == nil {
		t.Fatal("unaccepted connection still open after Close")
	}
}

func TestRecvSkipsControlAndStrangers(t *testing.T) {
	a, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	peer, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	stranger, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer peer.Close()
	defer stranger.Close()
	remote := peer.LocalAddr().(*net.UDPAddr).AddrPort()
	c := &Conn{p: newPath(a, remote), Remote: remote}
	to := a.LocalAddr().(*net.UDPAddr)
	peer.WriteTo([]byte("d1:rd2:id20:aaaaaaaaaaaaaaaaaaaae1:t2:aa1:y1:re"), to)
	stranger.WriteTo([]byte("not from the peer"), to)
	peer.WriteTo([]byte("payload"), to)
	a.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 128)
	n, err := c.Recv(buf)
	if err != nil || string(buf[:n]) != "payload" {
		t.Fatalf("Recv = %q, %v", buf[:n], err)
	}
}

// oneSign signs once with k, then fails.
type oneSign struct {
	k    ed25519.PrivateKey
	used bool
}

func (o *oneSign) Public() crypto.PublicKey { return o.k.Public() }
func (o *oneSign) Sign(r io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	if o.used {
		return nil, errors.New("device gone")
	}
	o.used = true
	return o.k.Sign(r, msg, opts)
}

// TestSignerFailedReachesApp: a listener whose signer fails on a re-sign
// is told through Config.SignerFailed.
func TestSignerFailedReachesApp(t *testing.T) {
	got := make(chan error, 1)
	e, err := New(Config{DHT: member(true), DHTAddr: "127.0.0.1:0", DataIP: net.IPv4(127, 0, 0, 1),
		SignerFailed: func(listener [32]byte, err error) {
			if listener == pub(key("one sign")) {
				got <- err
			}
		}})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := e.Listen(ctx, &oneSign{k: key("one sign")}); err != nil {
		t.Fatal(err)
	}
	e.DHT().Inspect(ctx, func(d *dht.Node) { d.Rebound(time.Now()) }) // re-signs
	select {
	case err := <-got:
		if !errors.Is(err, dht.ErrSigner) {
			t.Fatalf("told %v", err)
		}
	case <-ctx.Done():
		t.Fatal("the app was never told its signer failed")
	}
}

// TestTwoListenerKeys: one endpoint listens under two keys; a caller
// reaches it by each, the connection says which key was called, and
// AuthorizeListener is asked with that key.
func TestTwoListenerKeys(t *testing.T) {
	seed := network(t, 10)
	asked := make(chan [2][32]byte, 4)
	provider, err := New(Config{DHT: member(true), DHTAddr: "127.0.0.1:0", DataIP: net.IPv4(127, 0, 0, 1),
		AuthorizeListener: func(listener, caller [32]byte) bool {
			asked <- [2][32]byte{listener, caller}
			return true
		}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { provider.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := provider.DHT().Bootstrap(ctx, []netip.AddrPort{seed}); err != nil {
		t.Fatal(err)
	}
	caller := phone(t, seed)
	ka, kb, ck := key("listener a"), key("listener b"), key("two-key caller")
	for _, k := range []ed25519.PrivateKey{ka, kb} {
		if err := provider.AddListener(ctx, k); err != nil {
			t.Fatal(err)
		}
	}
	for {
		var holders int
		provider.DHT().Inspect(ctx, func(d *dht.Node) { holders = len(d.Holders()) })
		if holders > 0 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("never published")
		case <-time.After(50 * time.Millisecond):
		}
	}
	for _, k := range []ed25519.PrivateKey{ka, kb} {
		accepted := make(chan *Conn, 1)
		go func() {
			c, _ := provider.Accept(ctx)
			accepted <- c
		}()
		out, err := caller.Connect(ctx, ck, pub(k))
		if err != nil {
			t.Fatalf("connect to listener: %v", err)
		}
		in := <-accepted
		if in == nil {
			t.Fatal("nothing accepted")
		}
		if in.LocalKey != pub(k) || out.LocalKey != pub(ck) {
			t.Errorf("local keys: provider sees %x, caller %x", in.LocalKey[:4], out.LocalKey[:4])
		}
		select {
		case a := <-asked:
			if a[0] != pub(k) || a[1] != pub(ck) {
				t.Errorf("AuthorizeListener asked for %x by %x", a[0][:4], a[1][:4])
			}
		default:
			t.Error("AuthorizeListener was never asked")
		}
		out.Close()
		in.Close()
	}
	// Removing one key leaves the other listening.
	if err := provider.RemoveListener(ctx, pub(ka)); err != nil {
		t.Fatal(err)
	}
	var keys [][32]byte
	provider.DHT().Inspect(ctx, func(d *dht.Node) {
		for _, l := range d.Listeners() {
			keys = append(keys, l.Key)
		}
	})
	if len(keys) != 1 || keys[0] != pub(kb) {
		t.Fatalf("listening under %x after removing one", keys)
	}
}

// TestAuthorizeListenerRefuses: a listener key's own rule refuses a caller.
func TestAuthorizeListenerRefuses(t *testing.T) {
	seed := network(t, 10)
	provider, err := New(Config{DHT: member(true), DHTAddr: "127.0.0.1:0", DataIP: net.IPv4(127, 0, 0, 1),
		AuthorizeListener: func(listener, caller [32]byte) bool { return false }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { provider.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := provider.DHT().Bootstrap(ctx, []netip.AddrPort{seed}); err != nil {
		t.Fatal(err)
	}
	pk := key("refusing listener")
	listenAndWait(t, provider, pk)
	cctx, ccancel := context.WithTimeout(ctx, 3*time.Second)
	defer ccancel()
	if _, err := phone(t, seed).Connect(cctx, key("refused caller"), pub(pk)); err == nil {
		t.Fatal("connected through a listener that refuses every caller")
	}
}
