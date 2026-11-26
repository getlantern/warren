package node

import (
	"context"
	crand "crypto/rand"
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
	if err := a.Call(ctx, x.m2.Public()); err != nil {
		t.Fatal(err)
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
	if _, ok := b.Seen()[x.m1.Public()]; !ok {
		t.Fatal("the callee didn't record being reached")
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
	if !b.admits(newcomer.Rendezvous(x.g, keys.PeriodOf(time.Now())).Public()) {
		t.Fatal("the callee doesn't yet admit the newcomer's rendezvous key")
	}
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
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := h.Join(ctx, Config{Me: x.m1, Group: x.g, Roster: c, Logs: memberlog.NewSet(c.Group())}); err == nil {
		t.Fatal("a cancelled join still listened")
	}
	h.mu.Lock()
	left := len(h.groups)
	h.mu.Unlock()
	if left != 0 {
		t.Fatal("a failed join stayed on the host")
	}
}
