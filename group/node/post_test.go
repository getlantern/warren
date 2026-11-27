package node

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/getlantern/warren/group/keys"
	"github.com/getlantern/warren/group/memberlog"
	"github.com/getlantern/warren/group/roster"
)

// admins adds an admin, a, and a member, y, to x's roster, returning a.
func (x *group) admins(t *testing.T) *keys.Identity {
	t.Helper()
	ow := &roster.Writer{R: x.r, Me: x.owner}
	if _, err := ow.Add(me(4).Public(), "a", roster.Admin, keys.PublicKey{}); err != nil {
		t.Fatal(err)
	}
	if _, err := ow.Add(me(5).Public(), "y", roster.Member, keys.PublicKey{}); err != nil {
		t.Fatal(err)
	}
	return me(4)
}

// expose has the owner remove m2 from r while the admin from admins
// concurrently removes y: each removal's new keys reach the other's target,
// so r then calls for a corrective rekey.
func (x *group) expose(r *roster.Roster) error {
	c := r.Clone()
	if _, err := (&roster.Writer{R: r, Me: x.owner}).Remove(x.m2.Public(), 0, [32]byte{}); err != nil {
		return err
	}
	o, err := (&roster.Writer{R: c, Me: me(4)}).Remove(me(5).Public(), 0, [32]byte{})
	if err != nil {
		return err
	}
	if _, err := r.Add(o); err != nil {
		return err
	}
	f, err := r.Fold()
	if err != nil {
		return err
	}
	if !r.NeedsRekey(f) {
		return errors.New("the concurrent removals don't call for a rekey")
	}
	return nil
}

// bodies opens id's log entries on n, checking each is under the current
// epoch.
func bodies(t *testing.T, n *Node, id *keys.Identity) []string {
	t.Helper()
	var got []string
	if err := n.Do(context.Background(), func(r *roster.Roster, logs *memberlog.Set) error {
		f, err := r.Fold()
		if err != nil {
			return err
		}
		l := logs.Log(id.Public())
		if l == nil {
			return nil
		}
		for _, e := range l.Entries() {
			if e.Epoch != f.Current {
				t.Errorf("entry %d is under epoch %v, not the current %v", e.Seq, e.Epoch, f.Current)
			}
			_, b, err := e.Open(r.Keyring(id).Epochs[e.Epoch])
			if err != nil {
				return err
			}
			got = append(got, string(b))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return got
}

func ops(t *testing.T, n *Node) int {
	t.Helper()
	var c int
	if err := n.Do(context.Background(), func(r *roster.Roster, _ *memberlog.Set) error {
		c = len(r.IDs())
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return c
}

// TestPostAppends: unpaused, posts go straight onto the member's own log,
// chained.
func TestPostAppends(t *testing.T) {
	x := newGroup(t)
	n := x.join(t, host(t, network(t, 5)), x.m1, x.r)
	if n.Paused() {
		t.Fatal("a fresh group is paused")
	}
	for _, b := range []string{"one", "two"} {
		queued, err := n.Post(context.Background(), []byte(b))
		if err != nil || queued {
			t.Fatalf("post %q: queued %v, %v", b, queued, err)
		}
	}
	if got := bodies(t, n, x.m1); len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Fatalf("log %q", got)
	}
}

// TestPausedPostsFlushAfterRekey: while the roster calls for a rekey, posts
// are held, then appended in order under the corrective rekey's epoch
// once it arrives; past MaxQueued, a post is refused.
func TestPausedPostsFlushAfterRekey(t *testing.T) {
	x := newGroup(t)
	x.admins(t)
	if err := x.expose(x.r); err != nil {
		t.Fatal(err)
	}
	f, err := x.r.Fold()
	if err != nil {
		t.Fatal(err)
	}
	x.g = x.r.Keyring(x.owner).Secrets[f.Current]
	n := x.join(t, host(t, network(t, 5)), x.m1, x.r)
	if !n.Paused() {
		t.Fatal("not paused on an exposed roster")
	}
	// Refused, not held where it would block the queue's flush.
	if queued, err := n.Post(context.Background(), make([]byte, memberlog.MaxBody+1)); err == nil || queued {
		t.Fatalf("an oversized post while paused: queued %v, %v", queued, err)
	}
	defer func(m int) { MaxQueued = m }(MaxQueued)
	MaxQueued = 2
	for _, b := range []string{"one", "two"} {
		queued, err := n.Post(context.Background(), []byte(b))
		if err != nil || !queued {
			t.Fatalf("post %q: queued %v, %v", b, queued, err)
		}
	}
	if _, err := n.Post(context.Background(), []byte("three")); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("a post past MaxQueued: %v", err)
	}
	if got := bodies(t, n, x.m1); len(got) != 0 {
		t.Fatalf("paused posts were written: %q", got)
	}
	// The owner's corrective rekey reaches the node, as by a session.
	if err := n.Do(context.Background(), func(r *roster.Roster, _ *memberlog.Set) error {
		_, err := (&roster.Writer{R: r, Me: x.owner}).Rekey()
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if n.Paused() {
		t.Fatal("still paused after the corrective rekey")
	}
	if got := bodies(t, n, x.m1); len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Fatalf("log after the rekey %q", got)
	}
	queued, err := n.Post(context.Background(), []byte("four"))
	if err != nil || queued {
		t.Fatalf("a post after the flush: queued %v, %v", queued, err)
	}
}

// TestAdminCorrectsOnTick: once a running node learns of an exposure, an
// owner's or admin's node writes the corrective rekey on its next Tick,
// once; a member's doesn't, and stays paused.
func TestAdminCorrectsOnTick(t *testing.T) {
	x := newGroup(t)
	a := x.admins(t)
	f, err := x.r.Fold()
	if err != nil {
		t.Fatal(err)
	}
	x.g = x.r.Keyring(x.owner).Secrets[f.Current]
	seed := network(t, 8)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	exposed := func(n *Node) int {
		t.Helper()
		if err := n.Do(ctx, func(r *roster.Roster, _ *memberlog.Set) error { return x.expose(r) }); err != nil {
			t.Fatal(err)
		}
		if !n.Paused() {
			t.Fatal("not paused once exposed")
		}
		return ops(t, n)
	}

	m := x.join(t, host(t, seed), x.m1, x.r)
	before := exposed(m)
	if err := m.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if ops(t, m) != before || !m.Paused() {
		t.Fatal("a member's node wrote a rekey")
	}
	// Held posts are the caller's after Leave.
	if _, err := m.Post(ctx, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := m.Leave(ctx); err != nil {
		t.Fatal(err)
	}
	if h := m.TakeHeld(); len(h) != 1 || string(h[0]) != "one" {
		t.Fatalf("held after Leave %q", h)
	}

	for _, id := range []*keys.Identity{x.owner, a} {
		n := x.join(t, host(t, seed), id, x.r)
		before := exposed(n)
		if err := n.Tick(ctx); err != nil {
			t.Fatal(err)
		}
		if n.Paused() || ops(t, n) != before+1 {
			t.Fatalf("after a Tick: paused %v, %d ops, want %d", n.Paused(), ops(t, n), before+1)
		}
		if err := n.Tick(ctx); err != nil {
			t.Fatal(err)
		}
		if ops(t, n) != before+1 {
			t.Fatal("a second Tick wrote another rekey")
		}
	}
}

// TestAdminJoiningExposedCorrects: an admin's node joining an exposed
// roster corrects it straight away (Join ticks).
func TestAdminJoiningExposedCorrects(t *testing.T) {
	x := newGroup(t)
	x.admins(t)
	if err := x.expose(x.r); err != nil {
		t.Fatal(err)
	}
	before := len(x.r.IDs())
	f, err := x.r.Fold()
	if err != nil {
		t.Fatal(err)
	}
	x.g = x.r.Keyring(x.owner).Secrets[f.Current]
	n := x.join(t, host(t, network(t, 5)), x.owner, x.r)
	if n.Paused() || ops(t, n) != before+1 {
		t.Fatalf("after joining: paused %v, %d ops, want %d", n.Paused(), ops(t, n), before+1)
	}
}

// TestPostWithoutEpochKeyQueues: a member added concurrently with a rekey
// holds no key for the current epoch, though nothing calls for a rekey, so
// its posts are held until a deliver brings the key.
func TestPostWithoutEpochKeyQueues(t *testing.T) {
	x := newGroup(t)
	a := x.admins(t)
	k := me(6)
	c := x.r.Clone()
	if _, err := (&roster.Writer{R: x.r, Me: x.owner}).Rekey(); err != nil {
		t.Fatal(err)
	}
	o, err := (&roster.Writer{R: c, Me: a}).Add(k.Public(), "k", roster.Member, keys.PublicKey{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x.r.Add(o); err != nil {
		t.Fatal(err)
	}
	f, err := x.r.Fold()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := x.r.Keyring(k).Epochs[f.Current]; ok || x.r.NeedsRekey(f) {
		t.Fatal("the setup doesn't leave k without the current epoch key, unpaused")
	}
	x.g = x.r.Keyring(k).Secrets[x.r.Group()]
	n := x.join(t, host(t, network(t, 5)), k, x.r)
	if n.Paused() {
		t.Fatal("paused")
	}
	queued, err := n.Post(context.Background(), []byte("one"))
	if err != nil || !queued {
		t.Fatalf("a post without the epoch key: queued %v, %v", queued, err)
	}
	if err := n.Do(context.Background(), func(r *roster.Roster, _ *memberlog.Set) error {
		_, err := (&roster.Writer{R: r, Me: x.owner}).Deliver(k.Public(), keys.PublicKey{})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if got := bodies(t, n, k); len(got) != 1 || got[0] != "one" {
		t.Fatalf("log after the deliver %q", got)
	}
}

// TestPostRefusals: a mirror's post is refused, and a post goes in behind
// anything held.
func TestPostRefusals(t *testing.T) {
	x := newGroup(t)
	mirror := me(7)
	if _, err := (&roster.Writer{R: x.r, Me: x.owner}).Add(mirror.Public(), "mirror", roster.Mirror, keys.PublicKey{}); err != nil {
		t.Fatal(err)
	}
	seed := network(t, 6)
	n := x.join(t, host(t, seed), x.m1, x.r)
	n.mu.Lock()
	n.queue = append(n.queue, &heldPost{body: []byte("held")})
	n.mu.Unlock()
	// Queued behind it, then Do's refresh flushes both, the held one first,
	// so it's no longer held when Post returns.
	if queued, err := n.Post(context.Background(), []byte("next")); err != nil || queued {
		t.Fatalf("a post behind a held one: queued %v, %v", queued, err)
	}
	if got := bodies(t, n, x.m1); len(got) != 2 || got[0] != "held" || got[1] != "next" {
		t.Fatalf("log %q", got)
	}
	if h := n.TakeHeld(); len(h) != 0 {
		t.Fatalf("held after the flush %q", h)
	}

	mn := x.join(t, host(t, seed), mirror, x.r)
	mn.mu.Lock()
	mn.flushErr = errors.New("an old failure") // not what a mirror should hear
	mn.mu.Unlock()
	if _, err := mn.Post(context.Background(), []byte("x")); !errors.Is(err, roster.ErrNotAllowed) {
		t.Fatalf("a mirror's post: %v", err)
	}
}

// TestPausedMemberTickDoesntWait: a paused member's node has no rekey to
// write, so its Tick doesn't wait for the group.
func TestPausedMemberTickDoesntWait(t *testing.T) {
	x := newGroup(t)
	x.admins(t)
	if err := x.expose(x.r); err != nil {
		t.Fatal(err)
	}
	f, err := x.r.Fold()
	if err != nil {
		t.Fatal(err)
	}
	x.g = x.r.Keyring(x.owner).Secrets[f.Current]
	n := x.join(t, host(t, network(t, 5)), x.m1, x.r)
	held, release := make(chan struct{}), make(chan struct{})
	go func() {
		_ = n.Do(context.Background(), func(*roster.Roster, *memberlog.Set) error {
			close(held)
			<-release
			return nil
		})
	}()
	defer close(release)
	<-held
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := n.Tick(ctx); err != nil {
		t.Fatalf("a paused member's Tick waited on the group: %v", err)
	}
}

// TestPostAfterEpochStopsCounting: posts flushed under an admin's
// corrective rekey that then stops counting (the owner demoted the admin
// concurrently) are still this member's, and memberlog hides them and
// everything after. So later posts are refused (ErrHidden), not appended
// hidden or at a number that would fork the log, and held ones stay held.
func TestPostAfterEpochStopsCounting(t *testing.T) {
	x := newGroup(t)
	a := x.admins(t)
	if err := x.expose(x.r); err != nil {
		t.Fatal(err)
	}
	f, err := x.r.Fold()
	if err != nil {
		t.Fatal(err)
	}
	x.g = x.r.Keyring(x.owner).Secrets[f.Current]
	n := x.join(t, host(t, network(t, 5)), x.m1, x.r)
	ctx := context.Background()
	if _, err := n.Post(ctx, []byte("one")); err != nil {
		t.Fatal(err)
	}
	var stale *roster.Roster
	if err := n.Do(ctx, func(r *roster.Roster, _ *memberlog.Set) error {
		stale = r.Clone() // the owner's view, without the admin's rekey
		_, err := (&roster.Writer{R: r, Me: a}).Rekey()
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if h := n.TakeHeld(); len(h) != 0 {
		t.Fatalf("not flushed under the admin's rekey: %q", h)
	}
	if err := n.Do(ctx, func(r *roster.Roster, _ *memberlog.Set) error {
		o, err := (&roster.Writer{R: stale, Me: x.owner}).SetRole(a.Public(), roster.Member)
		if err != nil {
			return err
		}
		_, err = r.Add(o)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !n.Paused() {
		t.Fatal("the admin's rekey still counts")
	}
	if queued, err := n.Post(ctx, []byte("two")); !errors.Is(err, ErrHidden) || queued {
		t.Fatalf("a post behind hidden entries: queued %v, %v", queued, err)
	}
	n.mu.Lock()
	n.queue = append(n.queue, &heldPost{body: []byte("held")})
	n.mu.Unlock()
	if err := n.Do(ctx, func(r *roster.Roster, _ *memberlog.Set) error {
		_, err := (&roster.Writer{R: r, Me: x.owner}).Rekey()
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if n.Paused() {
		t.Fatal("still paused after the owner's rekey")
	}
	if queued, err := n.Post(ctx, []byte("three")); !errors.Is(err, ErrHidden) || queued {
		t.Fatalf("a post after the owner's rekey: queued %v, %v", queued, err)
	}
	n.mu.Lock()
	l := n.cfg.Logs.Log(x.m1.Public())
	last, fork, ferr := l.Last(), l.Fork(), n.flushErr
	n.mu.Unlock()
	if last == nil || last.Seq != 1 || fork != nil || ferr != nil {
		t.Fatalf("the member's own chain: last %v, fork %v, flush %v", last, fork != nil, ferr)
	}
	if h := n.TakeHeld(); len(h) != 1 || string(h[0]) != "held" {
		t.Fatalf("held %q", h)
	}
}

// TestHeldFailureSurfaces: a held post that fails to append is reported to
// later posts (ErrHeldFailed) rather than piling them up behind it, until
// TakeHeld hands it over.
func TestHeldFailureSurfaces(t *testing.T) {
	x := newGroup(t)
	n := x.join(t, host(t, network(t, 5)), x.m1, x.r)
	ctx := context.Background()
	n.mu.Lock()
	n.queue = append(n.queue, &heldPost{body: make([]byte, memberlog.MaxBody+1)}) // can't be written
	n.mu.Unlock()
	if _, err := n.Post(ctx, []byte("a")); err != nil {
		t.Fatal(err) // queued behind it; its flush fails
	}
	if _, err := n.Post(ctx, []byte("b")); !errors.Is(err, ErrHeldFailed) {
		t.Fatalf("a post behind a failing one: %v", err)
	}
	if h := n.TakeHeld(); len(h) != 2 || string(h[1]) != "a" {
		t.Fatalf("held %d", len(h))
	}
	if queued, err := n.Post(ctx, []byte("b")); err != nil || queued {
		t.Fatalf("a post after TakeHeld: queued %v, %v", queued, err)
	}
}

// TestLeaveDoesntFlush: Leave's own refresh leaves held posts to the
// caller, even once they could be appended.
func TestLeaveDoesntFlush(t *testing.T) {
	x := newGroup(t)
	n := x.join(t, host(t, network(t, 5)), x.m1, x.r)
	n.mu.Lock()
	n.queue = append(n.queue, &heldPost{body: []byte("held")}) // unpaused, holding the key
	n.mu.Unlock()
	if err := n.Leave(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h := n.TakeHeld(); len(h) != 1 || string(h[0]) != "held" {
		t.Fatalf("held after Leave %q", h)
	}
	n.mu.Lock()
	l := n.cfg.Logs.Log(x.m1.Public())
	n.mu.Unlock()
	if l != nil && len(l.Entries()) != 0 {
		t.Fatal("Leave appended the held post")
	}
}

// TestPostOnForkedOwnLog: a forked own log refuses posts as forked, not as
// stalled.
func TestPostOnForkedOwnLog(t *testing.T) {
	x := newGroup(t)
	n := x.join(t, host(t, network(t, 5)), x.m1, x.r)
	ctx := context.Background()
	if _, err := n.Post(ctx, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := n.Do(ctx, func(r *roster.Roster, logs *memberlog.Set) error {
		f, err := r.Fold()
		if err != nil {
			return err
		}
		e, err := memberlog.Write(x.m1, r.Group(), nil, f.Current, r.Keyring(x.m1).Epochs[f.Current], memberlog.App, []byte("other one"))
		if err != nil {
			return err
		}
		if _, err := logs.Add(e); !errors.Is(err, memberlog.ErrForked) {
			return fmt.Errorf("a second entry at seq 1: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := n.Post(ctx, []byte("two")); !errors.Is(err, memberlog.ErrForked) {
		t.Fatalf("a post on a forked own log: %v", err)
	}
}
