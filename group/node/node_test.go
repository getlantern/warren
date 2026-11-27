package node

import (
	"context"
	crand "crypto/rand"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
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
	// clock, if set, is every joined node's clock, so tests that must agree
	// on the period don't straddle an hour.
	clock func() time.Time
}

func (x *group) now() time.Time {
	if x.clock != nil {
		return x.clock()
	}
	return time.Now()
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

// join puts id, with its own copy of r, on h, and waits until its listener
// for the current period is published (not just any on the host).
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
	n, err := h.Join(ctx, Config{Me: id, Group: x.g, Roster: c, Logs: logs, Now: x.clock, CallTimeout: 3 * time.Second, SessionTimeout: 15 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	key := id.Rendezvous(x.g, keys.PeriodOf(x.now())).Public()
	for {
		var holders int
		h.Endpoint().DHT().Inspect(ctx, func(d *dht.Node) { holders = len(d.HoldersFor(key)) })
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

// post appends an app entry to id's log on n, through Do.
func post(t *testing.T, n *Node, id *keys.Identity, msg string) {
	t.Helper()
	err := n.Do(func(r *roster.Roster, logs *memberlog.Set) error {
		f, err := r.Fold()
		if err != nil {
			return err
		}
		e, err := memberlog.Write(id, r.Group(), nil, f.Current, r.Keyring(id).Epochs[f.Current], memberlog.App, []byte(msg))
		if err != nil {
			return err
		}
		_, err = logs.Add(e)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestMembersSyncOverNetwork(t *testing.T) {
	seed := network(t, 10)
	x := newGroup(t)
	a := x.join(t, host(t, seed), x.m1, x.r)
	b := x.join(t, host(t, seed), x.m2, x.r)
	post(t, a, x.m1, "hello group")
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
	for deadline := time.Now().Add(10 * time.Second); !ok(); time.Sleep(20 * time.Millisecond) {
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
// caller tries a bounded number of times on the same connection, then
// gives up, without waiting out its session or falling back to the sync
// key.
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
	if d := time.Since(start); d > 2*a.cfg.CallTimeout {
		t.Fatalf("the busy call took %v", d)
	}
	// Once the caller has used its tries, the callee lets the connection go.
	eventually(t, "the callee kept serving a caller that gave up", func() bool { return b.h.serving.Load() == 0 })
	// A caller in another session gives up too, once connected.
	a.active.Store(true)
	p := keys.PeriodOf(time.Now())
	callee := x.m2.Rendezvous(x.g, p).Public()
	answered, err2 := a.callAs(ctx, x.m1.Rendezvous(x.g, p), callee)
	a.active.Store(false)
	if !answered || !errors.Is(err2, ErrBusy) {
		t.Fatalf("a busy caller: answered=%v err=%v, want ErrBusy", answered, err2)
	}
	// None of those tries reached the callee, which lets the idle
	// connection go well before the session would have timed out.
	eventually(t, "the callee kept serving a caller whose tries never came", func() bool { return b.h.serving.Load() == 0 })
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
	fixed := time.Now()
	x.clock = func() time.Time { return fixed }
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
	n.ready.Store(false) // as while Join is still listening
	if h.authorize(ours, rv(x.m2, p)) {
		t.Fatal("the host routed a call to a group whose join hadn't finished")
	}
	n.ready.Store(true)
	// A member added through Do is admitted at once.
	newcomer := me(7)
	if err := n.Do(func(r *roster.Roster, _ *memberlog.Set) error {
		_, err := (&roster.Writer{R: r, Me: x.owner}).Add(newcomer.Public(), "n", roster.Member, keys.PublicKey{})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !n.admits(rv(newcomer, p)) {
		t.Fatal("a member added through Do wasn't admitted")
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
	stream := rawStream(t, a, x.m1, x.m2, x.g)
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

// rawStream opens a session stream from a, as from, to member to, writing
// nothing on it.
func rawStream(t *testing.T, a *Node, from, to *keys.Identity, g keys.Secret) net.Conn {
	t.Helper()
	return rawStreamTo(t, a, from, to, g, streamName)
}

// rawStreamTo is rawStream asking for dest.
func rawStreamTo(t *testing.T, a *Node, from, to *keys.Identity, g keys.Secret, dest string) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	p := keys.PeriodOf(time.Now())
	c, err := a.h.ep.Connect(ctx, keys.CryptoSigner(from.Rendezvous(g, p)), to.Rendezvous(g, p).Public())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	cl, err := hy2.Dial(ctx, c, c.Remote, c.PeerKey, hy2.FromSecret(c.Secret, hy2.ObfsUTP))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cl.Close() })
	stream, err := cl.DialConn(ctx, dest)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stream.Close() })
	return stream
}

// TestBadPreambleEndsServe: a connection whose stream doesn't open with the
// preamble isn't kept until the session would have timed out.
func TestBadPreambleEndsServe(t *testing.T) {
	seed := network(t, 10)
	x := newGroup(t)
	a := x.join(t, host(t, seed), x.m1, x.r)
	b := x.join(t, host(t, seed), x.m2, x.r)
	stream := rawStream(t, a, x.m1, x.m2, x.g)
	if _, err := stream.Write([]byte{'?'}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the callee kept serving a stream with a bad preamble", func() bool { return b.h.serving.Load() == 0 })
}

// TestCallDoesntWaitOutASession: a call made while the group is in a
// session gives up busy rather than waiting for the session's lock.
func TestCallDoesntWaitOutASession(t *testing.T) {
	seed := network(t, 10)
	x := newGroup(t)
	x.join(t, host(t, seed), x.m1, x.r)
	b := x.join(t, host(t, seed), x.m2, x.r)
	if !b.begin() { // as a session does, holding mu throughout
		t.Fatal("begin")
	}
	defer b.end()
	got := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		got <- b.Call(ctx, x.m1.Public())
	}()
	select {
	case err := <-got:
		if !errors.Is(err, ErrBusy) {
			t.Fatalf("got %v, want ErrBusy", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the call waited on the session")
	}
}

// TestCallAfterClose: a closed host places no calls.
func TestCallAfterClose(t *testing.T) {
	seed := network(t, 6)
	x := newGroup(t)
	h := host(t, seed)
	a := x.join(t, h, x.m1, x.r)
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if err := a.Call(context.Background(), x.m2.Public()); !errors.Is(err, ErrClosed) {
		t.Fatalf("got %v, want ErrClosed", err)
	}
}

// TestRotateWithFullListeners: with the endpoint's listener table full, a
// new period still drops the old keys and takes the new one.
func TestRotateWithFullListeners(t *testing.T) {
	seed := network(t, 6)
	x := newGroup(t)
	now := time.Now()
	h := host(t, seed)
	c := copyRoster(t, x.r)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	n, err := h.Join(ctx, Config{Me: x.m1, Group: x.g, Roster: c, Logs: memberlog.NewSet(c.Group()), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	for i := range dht.MaxListeners - 2 { // the rest of the table
		if err := h.ep.AddListener(ctx, keys.CryptoSigner(me(byte(100+i)).Rendezvous(x.g, 0))); err != nil {
			t.Fatal(err)
		}
	}
	p := keys.PeriodOf(now)
	key := func(q uint64) keys.PublicKey { return x.m1.Rendezvous(x.g, q).Public() }
	now = now.Add(2 * time.Hour)
	if err := n.Tick(ctx); err == nil {
		t.Fatal("two new keys fit in one free slot")
	}
	if n.listensUnder(key(p)) || !n.listensUnder(key(p+2)) {
		t.Fatal("a full table kept the old key and not the new period's")
	}
}

// TestSyncAllCarriesOn: SyncAll reaches the members it can even when one
// doesn't answer, and returns that one's error.
func TestSyncAllCarriesOn(t *testing.T) {
	seed := network(t, 10)
	x := newGroup(t)
	a := x.join(t, host(t, seed), x.m1, x.r)
	b := x.join(t, host(t, seed), x.m2, x.r) // the owner never joins
	post(t, a, x.m1, "hi")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := a.SyncAll(ctx); err == nil {
		t.Fatal("reached an owner that never joined")
	}
	if _, ok := a.Seen()[x.m2.Public()]; !ok {
		t.Fatal("SyncAll didn't reach the member that answers")
	}
	if _, ok := a.Seen()[x.m1.Public()]; ok {
		t.Fatal("SyncAll called itself")
	}
	b.mu.Lock()
	l := b.cfg.Logs.Log(x.m1.Public())
	b.mu.Unlock()
	if l == nil || len(l.Entries()) != 1 {
		t.Fatal("the entry didn't reach the member that answers")
	}
}

// TestPublishSightings: a member publishes the members it reached this
// period, so others see them in the directory though they never published.
func TestPublishSightings(t *testing.T) {
	seed := network(t, 10)
	x := newGroup(t)
	fixed := time.Now()
	x.clock = func() time.Time { return fixed }
	a := x.join(t, host(t, seed), x.m1, x.r)
	b := x.join(t, host(t, seed), x.m2, x.r)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := a.Call(ctx, x.m2.Public()); err != nil {
		t.Fatal(err)
	}
	if err := a.Publish(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := b.Directory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got[x.m2.Public()]; !ok {
		t.Fatal("the directory didn't show the member that was reached")
	}
}

// TestTwoGroupsOnOneHost: a host routes each call to the group listening
// under the key called, not just the first group it joined.
func TestTwoGroupsOnOneHost(t *testing.T) {
	seed := network(t, 10)
	x, y := newGroup(t), newGroup(t) // the same members, two groups
	h := host(t, seed)
	x.join(t, h, x.m1, x.r)
	ny := y.join(t, h, y.m1, y.r)
	b := y.join(t, host(t, seed), y.m2, y.r)
	post(t, ny, y.m1, "to the second group")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := b.Call(ctx, y.m1.Public()); err != nil {
		t.Fatalf("calling the second group on a host: %v", err)
	}
	var got int
	_ = b.Do(func(_ *roster.Roster, logs *memberlog.Set) error {
		if l := logs.Log(y.m1.Public()); l != nil {
			got = len(l.Entries())
		}
		return nil
	})
	if got != 1 {
		t.Fatal("the second group's entry didn't sync")
	}
}

// TestSyncAllOrder: SyncAll calls the members reached most recently first.
func TestSyncAllOrder(t *testing.T) {
	seed := network(t, 10)
	x := newGroup(t)
	a := x.join(t, host(t, seed), x.m1, x.r)
	x.join(t, host(t, seed), x.m2, x.r)
	x.join(t, host(t, seed), x.owner, x.r)
	// Reach first the member that key order would put first, so recency
	// and key order disagree.
	first, last := x.owner.Public(), x.m2.Public()
	if slices.Compare(first[:], last[:]) > 0 {
		first, last = last, first
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	for _, m := range []keys.PublicKey{first, last} {
		if err := a.Call(ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.SyncAll(ctx); err != nil {
		t.Fatal(err)
	}
	seen := a.Seen()
	if !seen[last].Before(seen[first]) {
		t.Fatal("SyncAll didn't call the most recently reached member first")
	}
}

// TestDoWaitsForSession: Do doesn't reach the roster and logs while a
// session holds them, or while another Do does.
func TestDoWaitsForSession(t *testing.T) {
	n := &Node{cfg: Config{Me: me(2), Group: newGroup(t).g, Roster: copyRoster(t, newGroup(t).r)}}
	if !n.begin() {
		t.Fatal("begin")
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	go func() {
		_ = n.Do(func(*roster.Roster, *memberlog.Set) error {
			close(entered)
			<-release
			return nil
		})
	}()
	select {
	case <-entered:
		t.Fatal("Do ran during a session")
	case <-time.After(200 * time.Millisecond):
	}
	n.end()
	<-entered
	second := make(chan struct{})
	go func() {
		_ = n.Do(func(*roster.Roster, *memberlog.Set) error { close(second); return nil })
	}()
	select {
	case <-second:
		t.Fatal("two Do calls overlapped")
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	<-second
}

// TestLingerBounded: linger gives up on a peer that stops reading or never
// answers, at CallTimeout or when its context ends.
func TestLingerBounded(t *testing.T) {
	n := &Node{cfg: Config{CallTimeout: 200 * time.Millisecond}}
	bounded := func(name string, d time.Duration, f func()) {
		t.Helper()
		start := time.Now()
		f()
		if e := time.Since(start); e > d {
			t.Fatalf("%s: linger took %v", name, e)
		}
	}
	// The peer never reads, so the write blocks.
	a, _ := net.Pipe()
	bounded("an unread write", 2*time.Second, func() { n.linger(context.Background(), a) })
	// The peer reads our done but never answers.
	a, b := net.Pipe()
	go func() { _, _ = io.ReadFull(b, make([]byte, 1)) }()
	bounded("an unanswered read", 2*time.Second, func() { n.linger(context.Background(), a) })
	// The same, ended by the context long before CallTimeout.
	slow := &Node{cfg: Config{CallTimeout: time.Minute}}
	for _, readFirst := range []bool{false, true} {
		a, b := net.Pipe()
		if readFirst {
			go func() { _, _ = io.ReadFull(b, make([]byte, 1)) }()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		bounded("a cancelled linger", 2*time.Second, func() { slow.linger(ctx, a) })
		cancel()
	}
}

// TestWrongStreamEndsServe: a stream asking for another destination ends
// the connection at once, rather than keeping it until it goes idle.
func TestWrongStreamEndsServe(t *testing.T) {
	seed := network(t, 10)
	x := newGroup(t)
	a := x.join(t, host(t, seed), x.m1, x.r)
	b := x.join(t, host(t, seed), x.m2, x.r)
	stream := rawStreamTo(t, a, x.m1, x.m2, x.g, "elsewhere:1")
	if _, err := stream.Write([]byte{preamble}); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	eventually(t, "the callee kept serving a stream for another destination", func() bool { return b.h.serving.Load() == 0 })
	if d := time.Since(start); d > b.cfg.CallTimeout {
		t.Fatalf("the connection lasted %v, as if left to go idle", d)
	}
}

// TestJoinTwiceRefused: a host can't join one group as one member twice.
func TestJoinTwiceRefused(t *testing.T) {
	seed := network(t, 6)
	x := newGroup(t)
	h := host(t, seed)
	x.join(t, h, x.m1, x.r)
	c := copyRoster(t, x.r)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := h.Join(ctx, Config{Me: x.m1, Group: x.g, Roster: c, Logs: memberlog.NewSet(c.Group())}); !errors.Is(err, ErrJoined) {
		t.Fatalf("got %v, want ErrJoined", err)
	}
	h.mu.Lock()
	groups := len(h.groups)
	h.mu.Unlock()
	if groups != 1 {
		t.Fatalf("%d groups on the host, want 1", groups)
	}
}

// TestDoMakesBusy: while Do holds the roster, a session can't begin, and
// trying leaves the group not busy.
func TestDoMakesBusy(t *testing.T) {
	x := newGroup(t)
	n := &Node{cfg: Config{Me: me(2), Group: x.g, Roster: copyRoster(t, x.r)}}
	inDo, release, out := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(out)
		_ = n.Do(func(*roster.Roster, *memberlog.Set) error {
			close(inDo)
			<-release
			return nil
		})
	}()
	<-inDo
	got := make(chan bool, 1)
	go func() { got <- n.begin() }()
	select {
	case ok := <-got:
		if ok {
			t.Fatal("a session began while Do held the roster")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("begin waited on Do")
	}
	if n.active.Load() {
		t.Fatal("a refused begin left the group busy")
	}
	close(release)
	<-out
}

// TestNoFallbackForAbsentMember: a member that isn't listening at all isn't
// called again under the sync key, which dials the same listener.
func TestNoFallbackForAbsentMember(t *testing.T) {
	seed := network(t, 6)
	x := newGroup(t)
	a := x.join(t, host(t, seed), x.m1, x.r) // m2 never joins
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := a.Call(ctx, x.m2.Public())
	if !errors.Is(err, dht.ErrNoRecord) {
		t.Fatalf("got %v, want ErrNoRecord", err)
	}
	if u, ok := err.(interface{ Unwrap() []error }); ok && len(u.Unwrap()) != 1 {
		t.Fatalf("an absent member was called again under the sync key: %v", err)
	}
}
