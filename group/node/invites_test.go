package node

import (
	"context"
	crand "crypto/rand"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/getlantern/warren/dht"
	"github.com/getlantern/warren/endpoint"
	"github.com/getlantern/warren/group/join"
	"github.com/getlantern/warren/group/keys"
	"github.com/getlantern/warren/group/memberlog"
	"github.com/getlantern/warren/group/roster"
	"github.com/getlantern/warren/transport/hy2"
)

// memberlogSet is a log set brought up to r's fold.
func memberlogSet(t *testing.T, r *roster.Roster) *memberlog.Set {
	t.Helper()
	logs := memberlog.NewSet(r.Group())
	f, err := r.Fold()
	if err != nil {
		t.Fatal(err)
	}
	if err := logs.Update(f); err != nil {
		t.Fatal(err)
	}
	return logs
}

var joinCfg = Config{CallTimeout: 3 * time.Second, SessionTimeout: 15 * time.Second}

// TestJoinByInvite: the owner issues an invite, a newcomer joins through
// it, and the newcomer then reaches the owner as a member, under its own
// rendezvous key.
func TestJoinByInvite(t *testing.T) {
	seed := network(t, 10)
	x := newGroup(t)
	owner := x.join(t, host(t, seed), x.owner, x.r)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	issued, err := owner.Invite(ctx, 1, time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	newcomer := me(40)
	iv, err := join.ParseLink(issued.Invite.Link())
	if err != nil {
		t.Fatal(err)
	}
	n, err := host(t, seed).JoinByInvite(ctx, iv, newcomer, "newcomer", joinCfg)
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	roles, _ := n.view()
	if roles[newcomer.Public()] != roster.Member {
		t.Fatal("the newcomer's node doesn't hold it as a member")
	}
	eventually(t, "the newcomer's listener was never published", func() bool {
		var ok bool
		n.h.Endpoint().DHT().Inspect(ctx, func(d *dht.Node) {
			ok = len(d.HoldersFor(newcomer.Rendezvous(n.cfg.Group, keys.PeriodOf(time.Now())).Public())) > 0
		})
		return ok
	})
	if err := n.Call(ctx, x.owner.Public()); err != nil {
		t.Fatalf("the newcomer couldn't reach the owner: %v", err)
	}
	if _, ok := owner.Seen()[newcomer.Public()]; !ok {
		eventually(t, "the owner didn't record the newcomer", func() bool {
			_, ok := owner.Seen()[newcomer.Public()]
			return ok
		})
	}
}

// TestRejoinByInvite: a member rejoins on a new host through an invite and
// gets a working node.
func TestRejoinByInvite(t *testing.T) {
	seed := network(t, 10)
	x := newGroup(t)
	owner := x.join(t, host(t, seed), x.owner, x.r)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	issued, err := owner.Invite(ctx, 1, time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	n, err := host(t, seed).Rejoin(ctx, issued.Invite, x.m1, joinCfg)
	if err != nil {
		t.Fatalf("rejoin: %v", err)
	}
	roles, _ := n.view()
	if roles[x.m1.Public()] != roster.Member {
		t.Fatal("the rejoined node doesn't hold the member")
	}
}

// TestJoinRefusals: a wrong invite secret reaches no listener; an expired
// invite and a declined request are refused, writing nothing.
func TestJoinRefusals(t *testing.T) {
	seed := network(t, 10)
	x := newGroup(t)
	var clock atomic.Int64 // UnixNano, read by the serving goroutine
	clock.Store(time.Now().UnixNano())
	h := host(t, seed)
	c := copyRoster(t, x.r)
	var declined atomic.Bool
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	owner := x.join(t, h, x.owner, x.r)
	_ = owner.Leave(ctx) // rejoin it with a clock and Approve the test controls
	logs := owner.cfg.Logs
	o, err := h.Join(ctx, Config{Me: x.owner, Group: x.g, Roster: c, Logs: logs, Now: func() time.Time { return time.Unix(0, clock.Load()) },
		CallTimeout: 3 * time.Second, SessionTimeout: 15 * time.Second,
		Approve: func(join.Request) bool { return !declined.Load() }})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := o.Invite(ctx, 5, time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	wrong := issued.Invite
	wrong.Secret[0] ^= 1
	if _, err := host(t, seed).JoinByInvite(ctx, wrong, me(41), "w", joinCfg); !errors.Is(err, ErrNoListener) {
		t.Fatalf("a wrong secret: %v, want ErrNoListener", err)
	}
	declined.Store(true)
	if _, err := host(t, seed).JoinByInvite(ctx, issued.Invite, me(42), "d", joinCfg); !errors.Is(err, join.ErrNotApproved) {
		t.Fatalf("declined: %v, want ErrNotApproved", err)
	}
	declined.Store(false)
	clock.Add(int64(time.Hour + time.Minute)) // expired, within the retry grace: still listening
	if _, err := host(t, seed).JoinByInvite(ctx, issued.Invite, me(43), "e", joinCfg); !errors.Is(err, join.ErrInviteUnusable) {
		t.Fatalf("expired: %v, want ErrInviteUnusable", err)
	}
	var added int
	_ = o.Do(ctx, func(r *roster.Roster, _ *memberlog.Set) error {
		f, _ := r.Fold()
		for _, k := range []*keys.Identity{me(41), me(42), me(43)} {
			if f.Roles[k.Public()] != roster.None {
				added++
			}
		}
		return nil
	})
	if added != 0 {
		t.Fatal("a refused joiner was added")
	}
}

// TestInviteListenerRotates: an invite is listened for under this and the
// next period's blinded keys, rotates with the clock, and is dropped past
// its retry grace.
func TestInviteListenerRotates(t *testing.T) {
	seed := network(t, 6)
	x := newGroup(t)
	now := time.Now()
	h := host(t, seed)
	c := copyRoster(t, x.r)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	n, err := h.Join(ctx, Config{Me: x.owner, Group: x.g, Roster: c, Logs: memberlogSet(t, c), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := n.Invite(ctx, 1, time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	p := keys.PeriodOf(now)
	key := func(q uint64) keys.PublicKey { k, _ := issued.Invite.Listener(q); return k }
	if !n.listensUnder(key(p)) || !n.listensUnder(key(p+1)) || !n.isInviteKey(key(p)) || n.isInviteKey(issued.Invite.Key) {
		t.Fatal("not listening under the invite's blinded keys")
	}
	if !h.authorize(key(p), me(99).Public()) {
		t.Fatal("an invite listener refused a fresh caller")
	}
	now = now.Add(time.Hour)
	if err := n.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if !n.listensUnder(key(p+2)) || !n.listensUnder(key(p)) {
		t.Fatal("the invite's listener didn't rotate, keeping the previous period's")
	}
	now = now.Add(time.Hour)
	if err := n.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if n.listensUnder(key(p)) {
		t.Fatal("an invite listener two periods back wasn't dropped")
	}
	now = time.Unix(issued.Invite.Expires, 0).Add(join.RetryGrace + time.Second)
	if err := n.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	q := keys.PeriodOf(now)
	if n.listensUnder(key(q)) || n.listensUnder(key(p+2)) {
		t.Fatal("an invite past its retry grace is still listened for")
	}
	n.lmu.Lock()
	left := len(n.invites)
	n.lmu.Unlock()
	if left != 0 {
		t.Fatal("an invite past its retry grace is still held")
	}
}

// TestLeave: a node that leaves is routed nothing and drops its listeners.
func TestLeave(t *testing.T) {
	seed := network(t, 6)
	x := newGroup(t)
	h := host(t, seed)
	n := x.join(t, h, x.owner, x.r)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	issued, err := n.Invite(ctx, 1, time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	p := keys.PeriodOf(time.Now())
	ik, _ := issued.Invite.Listener(p)
	rk := x.owner.Rendezvous(x.g, p).Public()
	if err := n.Leave(ctx); err != nil {
		t.Fatal(err)
	}
	if h.groupFor(rk) != nil || h.groupFor(ik) != nil {
		t.Fatal("a node that left is still routed to")
	}
	if n.listensUnder(rk) || n.listensUnder(ik) {
		t.Fatal("a node that left still listens")
	}
}

// TestJoinAcrossPeriodBoundary: a joiner whose clock is a period behind or
// ahead of the admin's still reaches the invite's listener, by trying the
// next and the previous period's keys.
func TestJoinAcrossPeriodBoundary(t *testing.T) {
	seed := network(t, 10)
	x := newGroup(t)
	owner := x.join(t, host(t, seed), x.owner, x.r)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	issued, err := owner.Invite(ctx, 2, 3*time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i, skew := range []time.Duration{-time.Hour, 2 * time.Hour} {
		cfg := joinCfg
		cfg.Now = func() time.Time { return time.Now().Add(skew) }
		if _, err := host(t, seed).JoinByInvite(ctx, issued.Invite, me(byte(50+i)), "s", cfg); err != nil {
			t.Fatalf("a joiner %v off the admin's clock: %v", skew, err)
		}
	}
}

// TestStalledInviteCaller: a caller on an invite listener that never
// finishes its request doesn't take the group: members still sync.
func TestStalledInviteCaller(t *testing.T) {
	seed := network(t, 10)
	x := newGroup(t)
	owner := x.join(t, host(t, seed), x.owner, x.r)
	m1 := x.join(t, host(t, seed), x.m1, x.r)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	issued, err := owner.Invite(ctx, 1, time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	listener, _ := issued.Invite.Listener(keys.PeriodOf(time.Now()))
	caller, _ := keys.NewIdentity(crand.Reader)
	c, err := m1.h.ep.Connect(ctx, keys.CryptoSigner(caller), listener)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	cl, err := hy2.Dial(ctx, c, c.Remote, c.PeerKey, hy2.FromSecret(c.Secret, hy2.ObfsUTP))
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	stream, err := cl.DialConn(ctx, joinStream)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err := stream.Write([]byte{0, 0}); err != nil { // part of a frame header
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if owner.active.Load() || owner.doWaiting.Load() != 0 {
		t.Fatal("an unverified caller took the group")
	}
	if err := m1.Call(ctx, x.owner.Public()); err != nil {
		t.Fatalf("a member couldn't sync while an invite caller stalled: %v", err)
	}
}

// TestSlowApproval: a join whose Approve takes longer than the idle bound
// (twice CallTimeout) but within SessionTimeout still completes.
func TestSlowApproval(t *testing.T) {
	seed := network(t, 10)
	x := newGroup(t)
	h := host(t, seed)
	c := copyRoster(t, x.r)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	o, err := h.Join(ctx, Config{Me: x.owner, Group: x.g, Roster: c, Logs: memberlogSet(t, c),
		CallTimeout: time.Second, SessionTimeout: 15 * time.Second,
		Approve: func(join.Request) bool { time.Sleep(3 * time.Second); return true }})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := o.Invite(ctx, 1, time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := host(t, seed).JoinByInvite(ctx, issued.Invite, me(44), "slow", joinCfg); err != nil {
		t.Fatalf("a slowly approved join: %v", err)
	}
}

// TestNothingBeginsAfterLeave: once a node has left, a Do or session
// refuses, so the roster and logs stay the caller's.
func TestNothingBeginsAfterLeave(t *testing.T) {
	seed := network(t, 6)
	x := newGroup(t)
	n := x.join(t, host(t, seed), x.owner, x.r)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := n.Leave(ctx); err != nil {
		t.Fatal(err)
	}
	ran := false
	if err := n.Do(ctx, func(*roster.Roster, *memberlog.Set) error { ran = true; return nil }); !errors.Is(err, ErrLeft) || ran {
		t.Fatalf("a Do after Leave: %v, ran=%v", err, ran)
	}
	if n.begin() {
		t.Fatal("a session began after Leave")
	}
}

// TestJoinFromHints: a joiner whose host has never bootstrapped finds the
// admin through the invite's hints alone.
func TestJoinFromHints(t *testing.T) {
	seed := network(t, 10)
	x := newGroup(t)
	owner := x.join(t, host(t, seed), x.owner, x.r)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	issued, err := owner.Invite(ctx, 1, time.Hour, []netip.AddrPort{seed})
	if err != nil {
		t.Fatal(err)
	}
	cold, err := NewHost(endpoint.Config{DHT: dhtConfig(true), DHTAddr: "127.0.0.1:0", DataIP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cold.Close() })
	if _, err := cold.JoinByInvite(ctx, issued.Invite, me(45), "cold", joinCfg); err != nil {
		t.Fatalf("joining from hints alone: %v", err)
	}
}

// TestNoListenersAfterLeave: Tick and Invite after Leave refuse, adding no
// listeners to a node the host no longer routes.
func TestNoListenersAfterLeave(t *testing.T) {
	seed := network(t, 6)
	x := newGroup(t)
	n := x.join(t, host(t, seed), x.owner, x.r)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := n.Leave(ctx); err != nil {
		t.Fatal(err)
	}
	if err := n.Tick(ctx); !errors.Is(err, ErrLeft) {
		t.Fatalf("Tick after Leave: %v", err)
	}
	if _, err := n.Invite(ctx, 1, time.Hour, nil); !errors.Is(err, ErrLeft) {
		t.Fatalf("Invite after Leave: %v", err)
	}
	if n.listensUnder(x.owner.Rendezvous(x.g, keys.PeriodOf(time.Now())).Public()) {
		t.Fatal("a node that left listens again")
	}
	// The roster is the caller's: Tick doesn't read it, so the node's view
	// doesn't follow a change made after Leave.
	newcomer := me(46)
	if _, err := (&roster.Writer{R: n.cfg.Roster, Me: x.owner}).Add(newcomer.Public(), "n", roster.Member, keys.PublicKey{}); err != nil {
		t.Fatal(err)
	}
	_ = n.Tick(ctx)
	if roles, _ := n.view(); roles[newcomer.Public()] != roster.None {
		t.Fatal("Tick read the roster after Leave")
	}
}

// TestRejoinKeepsLogs: a member that rejoins with its logs keeps its own
// entries, so its log carries on rather than restarting.
func TestRejoinKeepsLogs(t *testing.T) {
	seed := network(t, 10)
	x := newGroup(t)
	owner := x.join(t, host(t, seed), x.owner, x.r)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	h := host(t, seed)
	old := x.join(t, h, x.m1, x.r)
	post(t, old, x.m1, "written before rejoining")
	if err := old.Leave(ctx); err != nil {
		t.Fatal(err)
	}
	issued, err := owner.Invite(ctx, 1, time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := joinCfg
	cfg.Logs = old.cfg.Logs
	n, err := h.Rejoin(ctx, issued.Invite, x.m1, cfg)
	if err != nil {
		t.Fatalf("rejoin: %v", err)
	}
	var entries int
	_ = n.Do(ctx, func(_ *roster.Roster, logs *memberlog.Set) error {
		if l := logs.Log(x.m1.Public()); l != nil {
			entries = len(l.Entries())
		}
		return nil
	})
	if entries != 1 {
		t.Fatalf("the rejoined node holds %d of the member's entries, want 1", entries)
	}
}

// TestRejoinAfterRekey: a member rejoining after a rekey gets a node on the
// new group secret, and reaches a current member with it.
func TestRejoinAfterRekey(t *testing.T) {
	seed := network(t, 10)
	x := newGroup(t)
	if _, err := (&roster.Writer{R: x.r, Me: x.owner}).Rekey(); err != nil {
		t.Fatal(err)
	}
	f, _ := x.r.Fold()
	oldG := x.g
	x.g = x.r.Keyring(x.owner).Secrets[f.Current]
	if x.g == oldG {
		t.Fatal("the rekey didn't change G")
	}
	owner := x.join(t, host(t, seed), x.owner, x.r)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	issued, err := owner.Invite(ctx, 1, time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	n, err := host(t, seed).Rejoin(ctx, issued.Invite, x.m1, joinCfg)
	if err != nil {
		t.Fatalf("rejoin: %v", err)
	}
	if n.cfg.Group != x.g {
		t.Fatal("the rejoined node isn't on the current group secret")
	}
	eventually(t, "the rejoined node's listener was never published", func() bool {
		var ok bool
		n.h.Endpoint().DHT().Inspect(ctx, func(d *dht.Node) {
			ok = len(d.HoldersFor(x.m1.Rendezvous(x.g, keys.PeriodOf(time.Now())).Public())) > 0
		})
		return ok
	})
	if err := n.Call(ctx, x.owner.Public()); err != nil {
		t.Fatalf("the rejoined member couldn't reach the owner: %v", err)
	}
}

// TestRejoinMergesSavedRoster: a rejoiner's saved roster holds a rekey the
// admin hasn't seen, and its saved logs an entry under that epoch; the
// rejoin merges the saved roster, so the entry survives.
func TestRejoinMergesSavedRoster(t *testing.T) {
	seed := network(t, 10)
	x := newGroup(t)
	owner := x.join(t, host(t, seed), x.owner, x.r)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// The member's saved state: the roster plus a rekey (on a branch the
	// admin's node never received), and an entry under its epoch.
	saved := copyRoster(t, x.r)
	rk, err := (&roster.Writer{R: saved, Me: x.owner}).Rekey()
	if err != nil {
		t.Fatal(err)
	}
	logs := memberlogSet(t, saved)
	e, err := memberlog.Write(x.m1, saved.Group(), nil, rk.ID(), saved.Keyring(x.m1).Epochs[rk.ID()], memberlog.App, []byte("under the newer epoch"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := logs.Add(e); err != nil {
		t.Fatal(err)
	}
	issued, err := owner.Invite(ctx, 1, time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := joinCfg
	cfg.Roster, cfg.Logs = saved, logs
	n, err := host(t, seed).Rejoin(ctx, issued.Invite, x.m1, cfg)
	if err != nil {
		t.Fatalf("rejoin: %v", err)
	}
	var entries int
	_ = n.Do(ctx, func(r *roster.Roster, logs *memberlog.Set) error {
		if l := logs.Log(x.m1.Public()); l != nil {
			entries = len(l.Entries())
		}
		return nil
	})
	if entries != 1 {
		t.Fatalf("the rejoined node holds %d of the member's entries, want 1", entries)
	}
}

// TestInvitePartlyListened: with room for only one of an invite's two
// listeners, Invite returns the invite with the error, holding it so Tick
// can retry.
func TestInvitePartlyListened(t *testing.T) {
	seed := network(t, 6)
	x := newGroup(t)
	h := host(t, seed)
	n := x.join(t, h, x.owner, x.r)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	for i := range dht.MaxListeners - 3 { // two rendezvous keys, one slot left
		if err := h.ep.AddListener(ctx, keys.CryptoSigner(me(byte(100+i)).Rendezvous(x.g, 0))); err != nil {
			t.Fatal(err)
		}
	}
	issued, err := n.Invite(ctx, 1, time.Hour, nil)
	if err == nil {
		t.Fatal("both listeners fit in one free slot")
	}
	if issued == nil {
		t.Fatal("a recorded invite's link was lost with the listener error")
	}
	n.lmu.Lock()
	held := n.invites[issued.Invite.Key] != nil
	n.lmu.Unlock()
	if !held {
		t.Fatal("the node doesn't hold the invite to retry its listener")
	}
}
