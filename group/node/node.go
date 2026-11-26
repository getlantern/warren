// Package node is a group member's runtime (docs/groups-design.md,
// *Sessions*, *Discovery*): a Host owns the warren endpoint, and each group
// it joins is a Node that listens under its member's rendezvous keys,
// admits callers the roster lets in, calls members, runs group/session
// over hysteria2 on each connection, keeps when it last reached each
// member, and publishes its liveness to the group directory.
package node

import (
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/getlantern/warren/endpoint"
	"github.com/getlantern/warren/group/directory"
	"github.com/getlantern/warren/group/keys"
	"github.com/getlantern/warren/group/memberlog"
	"github.com/getlantern/warren/group/roster"
	"github.com/getlantern/warren/group/session"
	"github.com/getlantern/warren/transport/hy2"
)

// streamName is the hysteria2 destination a session stream asks for.
const streamName = "warren-group:1"

// busyTries and busyWait bound a call's tries of a busy group.
const (
	busyTries = 3
	busyWait  = 500 * time.Millisecond
)

// A caller writes preamble as soon as it opens the stream: a hysteria2
// server isn't handed a stream until its client writes, and a sync-key
// caller writes nothing of the session until it has the callee's hello.
// The callee answers go, or busy if it's in another session (see
// Node.active).
// It answers rather than just closing, since a close can be lost with the
// connection's teardown and leave the caller waiting out its session.
const (
	preamble = 'g'
	answerGo = 'y'
	busy     = 'b'
	doneMark = 'd' // after a session; see Node.linger
)

var (
	// ErrNotMember means a member the roster doesn't hold was called.
	ErrNotMember = errors.New("node: not a member")
	// ErrBusy means the group was in another session when its call
	// connected.
	ErrBusy = errors.New("node: in another session")
	// ErrClosed means the host was closed.
	ErrClosed = errors.New("node: host closed")
)

// Host owns a warren endpoint and routes its listeners and connections to
// the groups joined on it.
type Host struct {
	ep      *endpoint.Endpoint
	mu      sync.Mutex
	groups  []*Node
	ctx     context.Context // ends at Close
	cancel  context.CancelFunc
	closed  bool // under mu: no new calls
	done    chan struct{}
	serves  sync.WaitGroup // inbound connections
	calls   sync.WaitGroup // outbound calls
	serving atomic.Int32   // inbound connections being served
}

// NewHost starts an endpoint from cfg, deciding admission itself: cfg's
// AuthorizeListener is replaced (Authorize, if set, still applies first).
func NewHost(cfg endpoint.Config) (*Host, error) {
	h := &Host{done: make(chan struct{})}
	cfg.AuthorizeListener = h.authorize
	ep, err := endpoint.New(cfg)
	if err != nil {
		return nil, err
	}
	h.ep = ep
	h.ctx, h.cancel = context.WithCancel(context.Background())
	go h.accept(h.ctx)
	return h, nil
}

// Endpoint is the host's endpoint, for bootstrapping its DHT.
func (h *Host) Endpoint() *endpoint.Endpoint { return h.ep }

// Close stops every group and the endpoint, and waits for sessions in and
// out to end, so the rosters and logs are the caller's again.
func (h *Host) Close() error {
	h.mu.Lock()
	h.closed = true
	h.mu.Unlock()
	h.cancel()
	err := h.ep.Close()
	<-h.done
	h.serves.Wait()
	h.calls.Wait()
	return err
}

// call registers an outbound call, which Close cancels and waits for; the
// returned context ends with ctx or the host, and done must be called.
func (h *Host) call(ctx context.Context) (context.Context, func(), error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil, nil, ErrClosed
	}
	h.calls.Add(1)
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(h.ctx, cancel)
	return ctx, func() {
		stop()
		cancel()
		h.calls.Done()
	}, nil
}

// groupFor is the group listening under key, or nil.
func (h *Host) groupFor(key keys.PublicKey) *Node {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, n := range h.groups {
		if n.listensUnder(key) {
			return n
		}
	}
	return nil
}

func (h *Host) authorize(listener, caller [32]byte) bool {
	n := h.groupFor(listener)
	return n != nil && n.admits(caller)
}

func (h *Host) accept(ctx context.Context) {
	defer close(h.done)
	for {
		c, err := h.ep.Accept(ctx)
		if err != nil {
			return
		}
		n := h.groupFor(c.LocalKey)
		if n == nil {
			_ = c.Close()
			continue
		}
		h.serves.Add(1)
		h.serving.Add(1)
		go func() {
			defer h.serves.Done()
			defer h.serving.Add(-1)
			n.serve(ctx, c)
		}()
	}
}

// Config is one group a host joins.
type Config struct {
	Me     *keys.Identity
	Group  keys.Secret
	Roster *roster.Roster
	Logs   *memberlog.Set
	// Now is the clock that places the group in a period; nil means
	// time.Now.
	Now func() time.Time
	// CallTimeout bounds one attempt to reach a member, the wait between
	// tries of a busy one, and a session's admission (a caller holding an
	// admitted key, such as any holder of G with a sync key, can't hold the
	// group busy past it without proving it's a member). A connection with
	// no session and no new try for twice it is let go. Zero means 15s.
	CallTimeout time.Duration
	// SessionTimeout bounds one session; zero means a minute.
	SessionTimeout time.Duration
}

// Node is one group on a host.
type Node struct {
	h   *Host
	cfg Config
	// mu holds the roster, logs and admission set; a session holds it
	// throughout, and other readers only briefly.
	mu sync.Mutex
	// active is set while a session runs: one at a time per group. No
	// session waits for another: a call in that finds one running is
	// answered busy, and a call out gives up with ErrBusy. A session that
	// waited could hold up its peer's, and two members calling each other
	// could each end up waiting on the other until the session timed out.
	active atomic.Bool

	lmu       sync.Mutex
	listening map[uint64]keys.Signer // period → the rendezvous key listened under
	admit     atomic.Pointer[map[keys.PublicKey]bool]
	// roles is the roster's members as of the last refresh, read without
	// mu so a call or a directory write doesn't wait out a session.
	roles atomic.Pointer[rolesView]

	shards uint32 // the genesis op's, fixed for the group's life

	smu  sync.Mutex
	seen map[keys.PublicKey]time.Time // member → last session with it
}

// Join listens for cfg's group on the host under this and the next
// period's rendezvous keys.
func (h *Host) Join(ctx context.Context, cfg Config) (*Node, error) {
	if cfg.CallTimeout == 0 {
		cfg.CallTimeout = 15 * time.Second
	}
	if cfg.SessionTimeout == 0 {
		cfg.SessionTimeout = time.Minute
	}
	n := &Node{h: h, cfg: cfg, listening: map[uint64]keys.Signer{}, seen: map[keys.PublicKey]time.Time{},
		shards: cfg.Roster.Op(cfg.Roster.Group()).Shards}
	n.mu.Lock()
	n.refresh()
	n.mu.Unlock()
	h.mu.Lock()
	h.groups = append(h.groups, n)
	h.mu.Unlock()
	if err := n.Tick(ctx); err != nil {
		n.leave()
		return nil, err
	}
	return n, nil
}

// leave takes n off the host and drops its listeners.
func (n *Node) leave() {
	n.h.mu.Lock()
	for i, g := range n.h.groups {
		if g == n {
			n.h.groups = append(n.h.groups[:i], n.h.groups[i+1:]...)
			break
		}
	}
	n.h.mu.Unlock()
	n.lmu.Lock()
	defer n.lmu.Unlock()
	for q, s := range n.listening {
		_ = n.h.ep.RemoveListener(context.Background(), s.Public())
		delete(n.listening, q)
	}
}

func (n *Node) now() time.Time {
	if n.cfg.Now != nil {
		return n.cfg.Now()
	}
	return time.Now()
}

type rolesView struct {
	roles map[keys.PublicKey]roster.Role
	err   error // the fold's, if it failed
}

// Tick brings the listeners up to the clock: this and the next period's
// rendezvous keys, the older ones dropped, and the admission set rebuilt.
// Run it every few minutes (and after a roster change from outside a
// session).
func (n *Node) Tick(ctx context.Context) error {
	err := n.rotate(ctx)
	// After lmu is released, as the host's admission and routing take it.
	// A session holding mu refreshes when it ends, with the clock then.
	if n.mu.TryLock() {
		n.refresh()
		n.mu.Unlock()
	}
	return err
}

// rotate listens under this and the next period's rendezvous keys and
// drops the rest, keeping the previous period's for a call across the
// boundary.
func (n *Node) rotate(ctx context.Context) error {
	p := keys.PeriodOf(n.now())
	n.lmu.Lock()
	defer n.lmu.Unlock()
	// Drop first, so a full listener table doesn't keep the old keys.
	for q, s := range n.listening {
		if q+1 < p || q > p+1 { // q > p+1: the clock went back
			if n.h.ep.RemoveListener(ctx, s.Public()) == nil { // else the next Tick retries
				delete(n.listening, q)
			}
		}
	}
	var errs []error
	for _, q := range []uint64{p, p + 1} {
		if _, ok := n.listening[q]; ok {
			continue
		}
		s := n.cfg.Me.Rendezvous(n.cfg.Group, q)
		if err := n.h.ep.AddListener(ctx, keys.CryptoSigner(s)); err != nil {
			errs = append(errs, err)
			continue
		}
		n.listening[q] = s
	}
	return errors.Join(errs...)
}

func (n *Node) listensUnder(key keys.PublicKey) bool {
	n.lmu.Lock()
	defer n.lmu.Unlock()
	return n.signerFor(key) != nil
}

// signerFor is the listener signer whose key is key; lmu held.
func (n *Node) signerFor(key keys.PublicKey) keys.Signer {
	for _, s := range n.listening {
		if s.Public() == key {
			return s
		}
	}
	return nil
}

// refresh rebuilds the set of caller keys the listeners admit: members'
// rendezvous keys for the previous, current and next period, and the sync
// keys for calling each of ours. mu held, so a set built from an older
// roster can't replace a newer one.
func (n *Node) refresh() {
	// A roster that won't fold admits no member keys (a stale set may hold
	// a removed member), but still the sync keys, which need no roster.
	var roles map[keys.PublicKey]roster.Role
	f, err := n.cfg.Roster.Fold()
	if err == nil {
		roles = f.Roles
	}
	n.roles.Store(&rolesView{roles: roles, err: err})
	admit := map[keys.PublicKey]bool{}
	p := keys.PeriodOf(n.now())
	for _, q := range []uint64{p - 1, p, p + 1} {
		for m := range roles {
			if m == n.cfg.Me.Public() {
				continue
			}
			if r, err := keys.Rendezvous(n.cfg.Group, q, m); err == nil {
				admit[r] = true
			}
		}
		ours := n.cfg.Me.Rendezvous(n.cfg.Group, q).Public()
		admit[n.cfg.Group.SyncKey(q, ours).Public()] = true
	}
	n.admit.Store(&admit)
}

func (n *Node) admits(caller keys.PublicKey) bool {
	a := n.admit.Load()
	return a != nil && (*a)[caller]
}

// serve runs the session an admitted caller opens on c.
func (n *Node) serve(ctx context.Context, c *endpoint.Conn) {
	defer func() { _ = c.Close() }()
	n.lmu.Lock()
	signer := n.signerFor(c.LocalKey)
	n.lmu.Unlock()
	if signer == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, n.cfg.SessionTimeout)
	defer cancel()
	// The connection ends when its session does, or, with no session
	// begun, when the caller has used its tries, sends something else, or
	// goes idle: no stream for idleFor (its tries come at most CallTimeout
	// apart, and some never reach us, so a count alone can't tell).
	done := make(chan struct{})
	var (
		streams  atomic.Int32 // tries the caller has made
		cmu      sync.Mutex   // started and finished, so neither undoes the other
		started  bool         // a session has begun on c
		finished bool
	)
	finish := func() {
		if !finished {
			finished = true
			close(done)
		}
	}
	giveUp := func() { // cmu not held
		cmu.Lock()
		defer cmu.Unlock()
		if !started {
			finish()
		}
	}
	idleFor := 2 * n.cfg.CallTimeout
	idle := time.AfterFunc(idleFor, giveUp)
	defer idle.Stop()
	// Handlers are joined before serve returns, so Host.Close waits for a
	// session to end and not just for serve.
	var (
		hmu      sync.Mutex
		returned bool
		handlers sync.WaitGroup
	)
	srv, err := hy2.Serve(ctx, c, keys.CryptoSigner(signer), hy2.FromSecret(c.Secret, hy2.ObfsUTP), func(stream net.Conn, dest string) {
		hmu.Lock()
		if returned {
			hmu.Unlock()
			_ = stream.Close()
			return
		}
		handlers.Add(1)
		hmu.Unlock()
		defer handlers.Done()
		defer stream.Close()
		stop := context.AfterFunc(ctx, func() { _ = stream.Close() })
		defer stop()
		// Each try is a stream; one session per connection.
		idle.Reset(idleFor)
		try := streams.Add(1)
		if dest != streamName || try > busyTries {
			return
		}
		var b [1]byte
		if _, err := io.ReadFull(stream, b[:]); err != nil || b[0] != preamble {
			giveUp() // not a caller of ours
			return
		}
		if !n.begin() {
			// In a session already. Hold the stream until the caller hangs
			// up, so the answer isn't lost with the teardown.
			if _, err := stream.Write([]byte{busy}); err == nil {
				_, _ = io.Copy(io.Discard, stream)
			}
			if try == busyTries { // the caller's last
				giveUp()
			}
			return
		}
		cmu.Lock()
		if started || finished {
			cmu.Unlock()
			n.end()
			return
		}
		started = true
		cmu.Unlock()
		idle.Stop()
		defer func() {
			cmu.Lock()
			finish()
			cmu.Unlock()
		}()
		if _, err := stream.Write([]byte{answerGo}); err != nil {
			n.end()
			return
		}
		if _, err := n.session(ctx, stream, c, false); err == nil {
			n.linger(stream)
		}
	})
	if err != nil {
		return
	}
	select {
	case <-done:
	case <-ctx.Done():
	}
	cancel()
	_ = srv.Close()
	hmu.Lock()
	returned = true
	hmu.Unlock()
	handlers.Wait()
}

// begin starts a session unless one is running; see active.
func (n *Node) begin() bool {
	if !n.active.CompareAndSwap(false, true) {
		return false
	}
	n.mu.Lock()
	return true
}

func (n *Node) end() {
	n.mu.Unlock()
	n.active.Store(false)
}

// session runs one session on stream, begun, which it ends, and records
// the peer as reached when it ends well.
func (n *Node) session(ctx context.Context, stream net.Conn, c *endpoint.Conn, caller bool) (keys.PublicKey, error) {
	defer n.end()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	admission := time.AfterFunc(n.cfg.CallTimeout, cancel) // see CallTimeout
	defer admission.Stop()
	peer, err := session.Run(ctx, stream, session.Config{
		Me: n.cfg.Me, Group: n.cfg.Group, Roster: n.cfg.Roster, Logs: n.cfg.Logs,
		Secret: c.Secret, Caller: caller, Local: c.LocalKey, Peer: c.PeerKey, Now: n.now(),
		Admitted: func() { admission.Stop() },
	})
	if err == nil {
		n.smu.Lock()
		n.seen[peer] = n.now()
		n.smu.Unlock()
	}
	n.refresh() // even a failed session may have kept a newcomer's add chain
	return peer, err
}

// view is the roster's members as of the last refresh.
func (n *Node) view() (map[keys.PublicKey]roster.Role, error) {
	v := n.roles.Load()
	return v.roles, v.err
}

// linger, after a session that ended well, holds the stream until the
// peer has finished too, so this side's last frame isn't lost with the
// teardown (sync's Finished allows it to be still on its way). Each side
// writes done once its session has ended, which needs the other's last
// frame, so reading the peer's done means ours arrived. It waits no
// longer than a call.
func (n *Node) linger(stream net.Conn) {
	if _, err := stream.Write([]byte{doneMark}); err != nil {
		return
	}
	t := time.AfterFunc(n.cfg.CallTimeout, func() { _ = stream.Close() })
	defer t.Stop()
	var b [1]byte
	_, _ = io.ReadFull(stream, b[:])
}

// Call reaches member and syncs with it: under this period's rendezvous
// key first, and if the member doesn't answer (it may not know us yet, and
// a listener stays silent to a caller it doesn't admit), under the sync
// key for calling it. A member that answers and then fails the session
// isn't called again.
func (n *Node) Call(ctx context.Context, member keys.PublicKey) error {
	roles, err := n.view()
	if err != nil {
		return err
	}
	if roles[member] == roster.None {
		return ErrNotMember
	}
	ctx, finished, err := n.h.call(ctx)
	if err != nil {
		return err
	}
	defer finished()
	p := keys.PeriodOf(n.now())
	callee, err := keys.Rendezvous(n.cfg.Group, p, member)
	if err != nil {
		return err
	}
	var errs []error
	for _, as := range []keys.Signer{n.cfg.Me.Rendezvous(n.cfg.Group, p), n.cfg.Group.SyncKey(p, callee)} {
		answered, err := n.callAs(ctx, as, callee)
		if err == nil {
			return nil
		}
		errs = append(errs, err)
		if answered || ctx.Err() != nil {
			break
		}
	}
	return errors.Join(errs...)
}

// callAs calls callee under as, reporting whether it answered.
func (n *Node) callAs(ctx context.Context, as keys.Signer, callee keys.PublicKey) (bool, error) {
	cctx, cancel := context.WithTimeout(ctx, n.cfg.CallTimeout)
	defer cancel()
	c, err := n.h.ep.Connect(cctx, keys.CryptoSigner(as), callee)
	if err != nil {
		return false, err
	}
	defer func() { _ = c.Close() }()
	sctx, scancel := context.WithTimeout(ctx, n.cfg.SessionTimeout)
	defer scancel()
	cl, err := hy2.Dial(sctx, c, c.Remote, c.PeerKey, hy2.FromSecret(c.Secret, hy2.ObfsUTP))
	if err != nil {
		return true, err
	}
	defer func() { _ = cl.Close() }()
	// A busy group, ours or the callee's, is tried again on the same
	// connection after a random wait: two members calling each other at
	// once (or a ring of them) each find the other busy, and a new Connect
	// would spend the callee's per-caller budget.
	// The wait is random over a window that starts at four round trips
	// (at least busyWait), so two callers retrying at once rarely collide
	// again even on a slow path, and doubles each try, up to CallTimeout
	// (which also keeps our tries within the callee's idle bound).
	window := busyWait
	for try := 1; ; try++ {
		if try > 1 {
			select {
			case <-time.After(rand.N(window)):
			case <-sctx.Done():
				return true, sctx.Err()
			}
			window = min(2*window, n.cfg.CallTimeout)
		}
		rtt, err := n.try(sctx, cl, c)
		if !errors.Is(err, ErrBusy) || try == busyTries {
			return true, err
		}
		window = min(max(window, 4*rtt), n.cfg.CallTimeout)
	}
}

// try is one stream of callAs: open it (the first does the handshake, so
// before our session begins), begin our session, ask the callee, and run
// it if the callee answers go. It reports the answer's round trip, zero if
// none was asked.
func (n *Node) try(ctx context.Context, cl *hy2.Client, c *endpoint.Conn) (time.Duration, error) {
	stream, err := cl.DialConn(ctx, streamName)
	if err != nil {
		return 0, err
	}
	defer stream.Close() // unwritten, the callee never sees it
	if !n.begin() {
		return 0, ErrBusy // see active
	}
	start := time.Now()
	if err := n.answer(ctx, stream); err != nil {
		n.end()
		return time.Since(start), err
	}
	_, err = n.session(ctx, stream, c, true)
	rtt := time.Since(start)
	if err == nil {
		n.linger(stream)
	}
	return rtt, err
}

// answer writes the preamble and reads the callee's answer, waiting no
// longer than a call.
func (n *Node) answer(ctx context.Context, stream net.Conn) error {
	if _, err := stream.Write([]byte{preamble}); err != nil {
		return err
	}
	t := time.AfterFunc(n.cfg.CallTimeout, func() { _ = stream.Close() })
	defer t.Stop()
	stop := context.AfterFunc(ctx, func() { _ = stream.Close() })
	defer stop()
	var b [1]byte
	if _, err := io.ReadFull(stream, b[:]); err != nil {
		return err
	}
	switch b[0] {
	case answerGo:
		return nil
	case busy:
		return ErrBusy
	}
	return errors.New("node: bad answer")
}

// Seen is when each member was last reached in a session.
func (n *Node) Seen() map[keys.PublicKey]time.Time {
	n.smu.Lock()
	defer n.smu.Unlock()
	out := make(map[keys.PublicKey]time.Time, len(n.seen))
	for k, v := range n.seen {
		out[k] = v
	}
	return out
}

// SyncAll calls every other member, those reached most recently first,
// returning the errors of those it couldn't reach.
func (n *Node) SyncAll(ctx context.Context) error {
	roles, err := n.view()
	if err != nil {
		return err
	}
	seen := n.Seen()
	var members []keys.PublicKey
	for m := range roles {
		if m != n.cfg.Me.Public() {
			members = append(members, m)
		}
	}
	slices.SortFunc(members, func(a, b keys.PublicKey) int {
		if c := seen[b].Compare(seen[a]); c != 0 {
			return c
		}
		return slices.Compare(a[:], b[:])
	})
	var errs []error
	for _, m := range members {
		if err := n.Call(ctx, m); err != nil {
			errs = append(errs, err)
		}
		if ctx.Err() != nil {
			break
		}
	}
	return errors.Join(errs...)
}

// dir is the group's directory, on the host's DHT.
func (n *Node) dir() *directory.Directory {
	return &directory.Directory{Group: n.cfg.Group, Shards: n.shards, Store: n.h.ep.DHT(), Now: n.now}
}

func (n *Node) members() ([]keys.PublicKey, error) {
	roles, err := n.view()
	if err != nil {
		return nil, err
	}
	var out []keys.PublicKey
	for m := range roles {
		out = append(out, m)
	}
	return out, nil
}

// Publish writes this member's liveness to the directory for the current
// period, and that of members it reached this period.
func (n *Node) Publish(ctx context.Context) error {
	members, err := n.members()
	if err != nil {
		return err
	}
	now := n.now()
	p := keys.PeriodOf(now)
	entries := []directory.Entry{{Key: n.cfg.Me.Rendezvous(n.cfg.Group, p).Public(), Seen: now}}
	for m, t := range n.Seen() {
		if keys.PeriodOf(t) != p {
			continue
		}
		if r, err := keys.Rendezvous(n.cfg.Group, p, m); err == nil {
			entries = append(entries, directory.Entry{Key: r, Seen: t})
		}
	}
	return n.dir().Write(ctx, p, members, entries)
}

// Directory reads when each member was last seen, as the directory says
// for the current period.
func (n *Node) Directory(ctx context.Context) (map[keys.PublicKey]time.Time, error) {
	members, err := n.members()
	if err != nil {
		return nil, err
	}
	return n.dir().Read(ctx, keys.PeriodOf(n.now()), members)
}
