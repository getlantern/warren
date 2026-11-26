package node

import (
	"context"
	crand "crypto/rand"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/getlantern/warren/dht"
	"github.com/getlantern/warren/driver"
	"github.com/getlantern/warren/endpoint"
	"github.com/getlantern/warren/group/keys"
	"github.com/getlantern/warren/group/memberlog"
	"github.com/getlantern/warren/group/roster"
	"github.com/getlantern/warren/krpc"
	"github.com/getlantern/warren/overlay"
	"github.com/getlantern/warren/transport/hy2"
)

var farsi = overlay.NewKey("fa")

func dhtConfig(ro bool) dht.Config {
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

// network starts DHT routers on loopback and returns a seed address.
func network(t *testing.T, size int) netip.AddrPort {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var nodes []*driver.Node
	for i := range size {
		n, err := driver.Listen("127.0.0.1:0", dhtConfig(false))
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

func host(t *testing.T, seed netip.AddrPort) *Host {
	t.Helper()
	h, err := NewHost(endpoint.Config{DHT: dhtConfig(true), DHTAddr: "127.0.0.1:0", DataIP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := h.Endpoint().DHT().Bootstrap(ctx, []netip.AddrPort{seed}); err != nil {
		t.Fatal(err)
	}
	return h
}

func me(b byte) *keys.Identity { return keys.IdentityFromSeed([32]byte{b}) }

// group is a roster with an owner and two members, and G.
type group struct {
	r                *roster.Roster
	g                keys.Secret
	owner, m1, m2, x *keys.Identity
}

func newGroup(t *testing.T) *group {
	t.Helper()
	x := &group{owner: me(1), m1: me(2), m2: me(3), x: me(9)}
	r, err := roster.Found(x.owner, "g", 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []*keys.Identity{x.m1, x.m2} {
		if _, err := (&roster.Writer{R: r, Me: x.owner}).Add(m.Public(), "m", roster.Member, keys.PublicKey{}); err != nil {
			t.Fatal(err)
		}
	}
	x.r, x.g = r, r.Keyring(x.owner).Secrets[r.Group()]
	return x
}

func copyRoster(t *testing.T, r *roster.Roster) *roster.Roster {
	t.Helper()
	c, err := roster.New(r.Op(r.Group()))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range r.IDs() {
		if id != r.Group() {
			if _, err := c.Add(r.Op(id)); err != nil {
				t.Fatal(err)
			}
		}
	}
	return c
}

// join puts id, with its own copy of r, on h, and waits until its
// listeners are published.
func (x *group) join(t *testing.T, h *Host, id *keys.Identity, r *roster.Roster) *Node {
	t.Helper()
	c := copyRoster(t, r)
	logs := memberlog.NewSet(c.Group())
	f, err := c.Fold()
	if err != nil {
		t.Fatal(err)
	}
	if err := logs.Update(f); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	n, err := h.Join(ctx, Config{Me: id, Group: x.g, Roster: c, Logs: logs, CallTimeout: 3 * time.Second, SessionTimeout: 15 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for {
		var holders int
		h.Endpoint().DHT().Inspect(ctx, func(d *dht.Node) { holders = len(d.Holders()) })
		if holders > 0 {
			return n
		}
		select {
		case <-ctx.Done():
			t.Fatal("listeners never published")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func TestMembersSyncOverNetwork(t *testing.T) {
	seed := network(t, 10)
	x := newGroup(t)
	a := x.join(t, host(t, seed), x.m1, x.r)
	b := x.join(t, host(t, seed), x.m2, x.r)
	f, _ := a.cfg.Roster.Fold()
	ep := a.cfg.Roster.Keyring(x.m1).Epochs[f.Current]
	e, err := memberlog.Write(x.m1, x.r.Group(), nil, f.Current, ep, memberlog.App, []byte("hello group"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.cfg.Logs.Add(e); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// Ticks alongside the session, which the race detector checks.
	ticking := make(chan struct{})
	go func() {
		defer close(ticking)
		for range 20 {
			_ = b.Tick(ctx)
			_ = a.Tick(ctx)
		}
	}()
	if err := a.Call(ctx, x.m2.Public()); err != nil {
		t.Fatal(err)
	}
	<-ticking
	eventually(t, "the callee's session didn't end", func() bool { return !b.active.Load() })
	if err := b.Call(ctx, x.m1.Public()); err != nil {
		t.Fatalf("a second session, the other way: %v", err)
	}
	b.mu.Lock()
	l := b.cfg.Logs.Log(x.m1.Public())
	got := l != nil && len(l.Entries()) == 1
	b.mu.Unlock()
	if !got {
		t.Fatal("the entry didn't reach the callee")
	}
	if _, ok := a.Seen()[x.m2.Public()]; !ok {
		t.Fatal("the caller didn't record reaching the callee")
	}
	// The callee records the session after its side returns, which can be
	// just after the caller's.
	eventually(t, "the callee didn't record being reached", func() bool {
		_, ok := b.Seen()[x.m1.Public()]
		return ok
	})
}

func eventually(t *testing.T, msg string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !ok(); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal(msg)
		}
	}
}

// TestMutualCallsFailFast: two members calling each other at once don't
// each wait on the other's session until the session times out.
func TestMutualCallsFailFast(t *testing.T) {
	seed := network(t, 10)
	x := newGroup(t)
	a := x.join(t, host(t, seed), x.m1, x.r)
	b := x.join(t, host(t, seed), x.m2, x.r)
	// Two rounds: on loopback every host is one network, which the
	// endpoint allows three calls a minute.
	for range 2 {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		errs := make(chan error, 2)
		start := time.Now()
		go func() { errs <- a.Call(ctx, x.m2.Public()) }()
		go func() { errs <- b.Call(ctx, x.m1.Public()) }()
		e1, e2 := <-errs, <-errs
		cancel()
		if d := time.Since(start); d > 10*time.Second {
			t.Fatalf("mutual calls took %v; they waited on each other", d)
		}
		if e1 != nil && e2 != nil {
			t.Fatalf("neither mutual call synced: %v / %v", e1, e2)
		}
		eventually(t, "a session didn't end", func() bool { return !a.active.Load() && !b.active.Load() })
	}
}

// TestBusyCalleeAnswers: a callee in another session answers busy, and the
// caller gives up at once rather than waiting out its session or trying
// again under the sync key.
func TestBusyCalleeAnswers(t *testing.T) {
	seed := network(t, 10)
	x := newGroup(t)
	a := x.join(t, host(t, seed), x.m1, x.r)
	b := x.join(t, host(t, seed), x.m2, x.r)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	b.active.Store(true) // as if in another session
	start := time.Now()
	err := a.Call(ctx, x.m2.Public())
	b.active.Store(false)
	if d := time.Since(start); d > a.cfg.CallTimeout {
		t.Fatalf("the busy call took %v", d)
	}
	// A caller in another session gives up too, once connected.
	a.active.Store(true)
	p := keys.PeriodOf(time.Now())
	callee := x.m2.Rendezvous(x.g, p).Public()
	answered, err2 := a.callAs(ctx, x.m1.Rendezvous(x.g, p), callee)
	a.active.Store(false)
	if !answered || !errors.Is(err2, ErrBusy) {
		t.Fatalf("a busy caller: answered=%v err=%v, want ErrBusy", answered, err2)
	}
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("got %v, want ErrBusy", err)
	}
	if u, ok := err.(interface{ Unwrap() []error }); ok && len(u.Unwrap()) != 1 {
		t.Fatalf("an answered call was tried again: %v", err)
	}
}

// TestNewMemberViaSyncKey: a member the callee hasn't heard of yet isn't
// answered under its rendezvous key, and gets in under the sync key.
func TestNewMemberViaSyncKey(t *testing.T) {
	seed := network(t, 10)
	x := newGroup(t)
	b := x.join(t, host(t, seed), x.m2, x.r) // before the newcomer's add
	newcomer := me(7)
	if _, err := (&roster.Writer{R: x.r, Me: x.owner}).Add(newcomer.Public(), "n", roster.Member, keys.PublicKey{}); err != nil {
		t.Fatal(err)
	}
	n := x.join(t, host(t, seed), newcomer, x.r)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := n.Call(ctx, x.m2.Public()); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	f, _ := b.cfg.Roster.Fold()
	b.mu.Unlock()
	if f.Roles[newcomer.Public()] != roster.Member {
		t.Fatal("the callee didn't learn of the newcomer")
	}
	rv := newcomer.Rendezvous(x.g, keys.PeriodOf(time.Now())).Public()
	eventually(t, "the callee doesn't admit the newcomer's rendezvous key", func() bool { return b.admits(rv) })
}

// TestStrangerRefused: a key the roster doesn't hold reaches no session.
func TestStrangerRefused(t *testing.T) {
	seed := network(t, 10)
	x := newGroup(t)
	b := x.join(t, host(t, seed), x.m2, x.r)
	s := x.join(t, host(t, seed), x.x, x.r) // holds G, never admitted
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := s.Call(ctx, x.m2.Public()); err == nil {
		t.Fatal("a stranger reached a session")
	}
	if len(b.Seen()) != 0 {
		t.Fatal("the callee recorded a session with a stranger")
	}
}

// TestPublishAndReadDirectory: a member's published liveness is read by
// another.
func TestPublishAndReadDirectory(t *testing.T) {
	seed := network(t, 10)
	x := newGroup(t)
	a := x.join(t, host(t, seed), x.m1, x.r)
	b := x.join(t, host(t, seed), x.m2, x.r)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := a.Publish(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := b.Directory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got[x.m1.Public()]; !ok {
		t.Fatal("the directory didn't show the member that published")
	}
}

// TestTickRotates: a new period adds its next rendezvous key and drops the
// one two periods back.
func TestTickRotates(t *testing.T) {
	seed := network(t, 6)
	x := newGroup(t)
	now := time.Now()
	clock := func() time.Time { return now }
	h := host(t, seed)
	c := copyRoster(t, x.r)
	logs := memberlog.NewSet(c.Group())
	f, _ := c.Fold()
	logs.Update(f)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	n, err := h.Join(ctx, Config{Me: x.m1, Group: x.g, Roster: c, Logs: logs, Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	p := keys.PeriodOf(now)
	key := func(q uint64) keys.PublicKey { return x.m1.Rendezvous(x.g, q).Public() }
	if !n.listensUnder(key(p)) || !n.listensUnder(key(p+1)) {
		t.Fatal("not listening under this and the next period's keys")
	}
	now = now.Add(2 * time.Hour)
	if err := n.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if n.listensUnder(key(p)) || !n.listensUnder(key(p+2)) || !n.listensUnder(key(p+3)) {
		t.Fatal("Tick didn't rotate the listeners")
	}
	now = now.Add(-2 * time.Hour) // the clock is corrected back
	if err := n.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if !n.listensUnder(key(p)) || n.listensUnder(key(p+2)) || n.listensUnder(key(p+3)) {
		t.Fatal("Tick kept listening for periods the clock left")
	}
}

// TestAdmits: listeners admit members' rendezvous keys for the previous,
// current and next period and the sync keys for calling us, and nothing
// else; the host routes each check to the group listening under the key
// called.
func TestAdmits(t *testing.T) {
	seed := network(t, 6)
	x := newGroup(t)
	now := time.Now()
	h := host(t, seed)
	c := copyRoster(t, x.r)
	logs := memberlog.NewSet(c.Group())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	n, err := h.Join(ctx, Config{Me: x.m1, Group: x.g, Roster: c, Logs: logs, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	p := keys.PeriodOf(now)
	rv := func(id *keys.Identity, q uint64) keys.PublicKey { return id.Rendezvous(x.g, q).Public() }
	sync := func(q uint64) keys.PublicKey { return x.g.SyncKey(q, rv(x.m1, q)).Public() }
	ours := rv(x.m1, p)
	for _, q := range []uint64{p - 1, p, p + 1} {
		for _, k := range []keys.PublicKey{rv(x.m2, q), rv(x.owner, q), sync(q)} {
			if !n.admits(k) || !h.authorize(ours, k) {
				t.Fatalf("period %d: a key the group admits was refused", q-p+1)
			}
		}
	}
	for name, k := range map[string]keys.PublicKey{
		"a stranger":               rv(x.x, p),
		"our own key":              rv(x.m1, p),
		"a member two periods out": rv(x.m2, p+2),
		"a sync key for another":   x.g.SyncKey(p, rv(x.m2, p)).Public(),
	} {
		if n.admits(k) {
			t.Fatalf("admitted %s", name)
		}
	}
	if h.authorize(rv(x.m2, p), rv(x.m2, p)) {
		t.Fatal("a listener the host doesn't hold admitted a caller")
	}
}

// TestJoinFailureLeavesNothing: a join that can't listen isn't left on the
// host.
func TestJoinFailureLeavesNothing(t *testing.T) {
	seed := network(t, 6)
	x := newGroup(t)
	h := host(t, seed)
	c := copyRoster(t, x.r)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = h.Endpoint().Close() // so the join can't listen
	if _, err := h.Join(ctx, Config{Me: x.m1, Group: x.g, Roster: c, Logs: memberlog.NewSet(c.Group())}); err == nil {
		t.Fatal("a join on a closed endpoint still listened")
	}
	h.mu.Lock()
	left := len(h.groups)
	h.mu.Unlock()
	if left != 0 {
		t.Fatal("a failed join stayed on the host")
	}
}

// TestStalledCallerReleasesGroup: a caller with an admitted key that never
// proves membership holds the group busy only until its admission times
// out, not for the whole session.
func TestStalledCallerReleasesGroup(t *testing.T) {
	seed := network(t, 10)
	x := newGroup(t)
	a := x.join(t, host(t, seed), x.m1, x.r)
	b := x.join(t, host(t, seed), x.m2, x.r)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p := keys.PeriodOf(time.Now())
	c, err := a.h.ep.Connect(ctx, keys.CryptoSigner(x.m1.Rendezvous(x.g, p)), x.m2.Rendezvous(x.g, p).Public())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	cl, err := hy2.Dial(ctx, c, c.Remote, c.PeerKey, hy2.FromSecret(c.Secret, hy2.ObfsUTP))
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	stream, err := cl.DialConn(ctx, streamName)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err := stream.Write([]byte{preamble}); err != nil {
		t.Fatal(err)
	}
	var ans [1]byte
	if _, err := io.ReadFull(stream, ans[:]); err != nil || ans[0] != answerGo {
		t.Fatalf("answer %q, %v", ans[0], err)
	}
	start := time.Now()
	for deadline := time.Now().Add(10 * time.Second); b.active.Load(); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("a stalled caller kept the group busy")
		}
	}
	if d := time.Since(start); d > b.cfg.CallTimeout+2*time.Second {
		t.Fatalf("the group stayed busy %v", d)
	}
}
