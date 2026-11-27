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
	"maps"
	"math/rand/v2"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/getlantern/warren/dht"
	"github.com/getlantern/warren/endpoint"
	"github.com/getlantern/warren/group/directory"
	"github.com/getlantern/warren/group/join"
	"github.com/getlantern/warren/group/keys"
	"github.com/getlantern/warren/group/memberlog"
	"github.com/getlantern/warren/group/roster"
	"github.com/getlantern/warren/group/session"
	"github.com/getlantern/warren/transport/hy2"
)

// streamName is the hysteria2 destination a session stream asks for.
const streamName = "warren-group:1"

// Grace is how long after a node first sees the group secret replaced (a
// remove or rekey) it keeps listening under, and admitting members' keys
// from, the superseded secret: a member that missed the change reaches it
// there and gets the change by gossip (docs/groups-design.md, *Removal*,
// step 4). Operations carry no time, so it runs from this node's own
// observation. With the listener table full, the current secret takes
// the listeners of the superseded secret whose window ends soonest: that
// secret is still admitted and called under for its window, but no longer
// listened under.
const Grace = 24 * time.Hour

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
	// ErrJoined means the host has already joined the group as that
	// member: the two would listen under the same keys.
	ErrJoined = errors.New("node: already joined")
	// ErrLeft means the node has left its host (Node.Leave).
	ErrLeft = errors.New("node: left")
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
		if n.ready.Load() && n.listensUnder(key) {
			return n
		}
	}
	return nil
}

func (h *Host) authorize(listener, caller [32]byte) bool {
	n := h.groupFor(listener)
	return n != nil && (n.isInviteKey(listener) || n.admits(caller))
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

// Config is one group a host joins. Once joined, its Roster and Logs are
// shared with the group's sessions: use Node.Do to reach them.
type Config struct {
	Me *keys.Identity
	// Group is the group secret the node starts on. It follows the
	// roster's current secret from then on (Node.Group), keeping
	// superseded ones for Grace.
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
	// Approve decides a join or rejoin request under one of this node's
	// invites, its proofs checked; nil approves every request the invite
	// covers. It runs with the group free, so it may run alongside sessions
	// and other approvals: it must reach the roster and logs only through
	// Node.Do. It is given the session's context (bounded by
	// SessionTimeout), should return when that ends, and nothing is
	// committed once it has. A retry after a lost answer isn't put to it.
	Approve func(context.Context, join.Request) bool
}

func withDefaults(cfg Config) Config {
	if cfg.CallTimeout == 0 {
		cfg.CallTimeout = 15 * time.Second
	}
	if cfg.SessionTimeout == 0 {
		cfg.SessionTimeout = time.Minute
	}
	return cfg
}

// Node is one group on a host.
type Node struct {
	h   *Host
	cfg Config
	// mu holds the roster, logs and admission set; a session holds it
	// throughout, and other readers only briefly.
	mu sync.Mutex
	// active is set while a session or a Do runs: one at a time per group.
	// No session waits for another: a call in that finds one running is
	// answered busy, and a call out gives up with ErrBusy. A session that
	// waited could hold up its peer's, and two members calling each other
	// could each end up waiting on the other until the session timed out.
	active atomic.Bool
	// doWaiting counts Do calls waiting for the group; see Do.
	doWaiting atomic.Int32
	// left is set by Leave, under the group: no session or Do begins after.
	left atomic.Bool

	lmu       sync.Mutex
	listening map[listenKey]keys.Signer  // the rendezvous keys listened under
	invites   map[keys.PublicKey]*invite // by invite key
	admit     atomic.Pointer[map[keys.PublicKey]bool]
	// roles is the roster's members as of the last refresh, read without
	// mu so a call or a directory write doesn't wait out a session.
	roles atomic.Pointer[rolesView]

	shards uint32 // the genesis op's, fixed for the group's life

	// ready is set once Join succeeds: until then the host routes nothing
	// to the group, so a failed join is never reached.
	ready atomic.Bool

	smu  sync.Mutex
	seen map[keys.PublicKey]sighting // member → last session with it

	// gmu holds the group secrets: the current one and those superseded
	// within Grace. It is taken last, under mu or lmu.
	gmu        sync.Mutex
	current    keys.Secret
	superseded []supersededSecret
	// seenKeys is, per counting key-making operation the node has seen,
	// until when its secret is kept once superseded: Grace from when the
	// node first saw the operation, whether or not it held the secret then.
	// The roster's history at the first refresh is past its window, so a
	// secret delivered late (even a hand-made deliver of an old one) never
	// starts one. nil until the first refresh. mu held.
	seenKeys map[roster.ID]time.Time
	// rekeyed is set when refresh moves to a new secret, so whoever ends
	// the session or Do rotates the listeners onto it.
	rekeyed atomic.Bool
}

// sighting is a session with a member: when, and under which group secret.
type sighting struct {
	at time.Time
	g  keys.Secret
}

// listenKey is a rendezvous listener's secret and period.
type listenKey struct {
	g keys.Secret
	q uint64
}

type supersededSecret struct {
	g     keys.Secret
	until time.Time
	// ranOn is set for a secret the node ran on itself, kept for Grace
	// whatever becomes of its operation (members may still be on it). The
	// rest come from the roster each refresh, and go when their operation
	// stops counting.
	ranOn bool
}

// Group is the group secret the node runs on now: the roster's current one
// once its keyring holds it.
func (n *Node) Group() keys.Secret {
	n.gmu.Lock()
	defer n.gmu.Unlock()
	return n.current
}

// secrets is the current group secret, then those superseded within Grace
// at now, by when their window ends, latest first: the last is the one a
// full listener table gives up first.
func (n *Node) secrets(now time.Time) []keys.Secret {
	n.gmu.Lock()
	live := make([]supersededSecret, 0, len(n.superseded))
	for _, s := range n.superseded {
		if now.Before(s.until) {
			live = append(live, s)
		}
	}
	out := []keys.Secret{n.current}
	n.gmu.Unlock()
	slices.SortStableFunc(live, func(a, b supersededSecret) int { return b.until.Compare(a.until) })
	for _, s := range live {
		out = append(out, s.g)
	}
	return out
}

// follow moves n to g if it isn't on it already, keeping the secret it
// leaves for Grace, and replaces the secrets kept from the roster with
// cands (superseded secrets of counting operations, with their own
// deadlines). It reports whether the secrets n listens under changed.
func (n *Node) follow(g keys.Secret, cands []supersededSecret, now time.Time) bool {
	n.gmu.Lock()
	defer n.gmu.Unlock()
	before := map[keys.Secret]bool{n.current: true}
	for _, s := range n.superseded {
		if now.Before(s.until) {
			before[s.g] = true
		}
	}
	var kept []supersededSecret
	has := func(x keys.Secret) bool {
		return slices.ContainsFunc(kept, func(s supersededSecret) bool { return s.g == x })
	}
	for _, s := range n.superseded {
		if s.ranOn && now.Before(s.until) && s.g != g {
			kept = append(kept, s)
		}
	}
	if g != n.current && !has(n.current) {
		kept = append(kept, supersededSecret{g: n.current, until: now.Add(Grace), ranOn: true})
	}
	for _, c := range cands {
		if c.g != g && now.Before(c.until) && !has(c.g) {
			kept = append(kept, c)
		}
	}
	n.superseded, n.current = kept, g
	after := map[keys.Secret]bool{g: true}
	for _, s := range kept {
		after[s.g] = true
	}
	return !maps.Equal(before, after)
}

// Join listens for cfg's group on the host under this and the next
// period's rendezvous keys.
func (h *Host) Join(ctx context.Context, cfg Config) (*Node, error) {
	cfg = withDefaults(cfg)
	n := &Node{h: h, cfg: cfg, listening: map[listenKey]keys.Signer{}, invites: map[keys.PublicKey]*invite{},
		seen: map[keys.PublicKey]sighting{}, shards: cfg.Roster.Op(cfg.Roster.Group()).Shards, current: cfg.Group}
	n.mu.Lock()
	n.refresh()
	n.mu.Unlock()
	h.mu.Lock()
	for _, g := range h.groups {
		if g.cfg.Roster.Group() == cfg.Roster.Group() && g.cfg.Me.Public() == cfg.Me.Public() {
			h.mu.Unlock()
			return nil, ErrJoined
		}
	}
	h.groups = append(h.groups, n)
	h.mu.Unlock()
	if err := n.Tick(ctx); err != nil {
		n.leave()
		return nil, err
	}
	n.ready.Store(true)
	return n, nil
}

// leave takes n off the host and drops its listeners, invites' included.
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
	for k, iv := range n.invites {
		for _, s := range iv.listening {
			_ = n.h.ep.RemoveListener(context.Background(), s.Public())
		}
		delete(n.invites, k)
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
// rendezvous keys and invite keys, the older ones (and invites past their
// retry grace) dropped, and the admission set rebuilt.
// Run it every few minutes.
func (n *Node) Tick(ctx context.Context) error {
	if n.left.Load() {
		return ErrLeft // the roster is the caller's again
	}
	err := n.rotate(ctx)
	// After lmu is released, as the host's admission and routing take it.
	// A session holding mu refreshes when it ends, with the clock then.
	// Leave may have run meanwhile: checked again under mu, which Leave's
	// Do held, before reading the roster.
	if n.mu.TryLock() {
		if !n.left.Load() {
			n.refresh()
		}
		n.mu.Unlock()
	}
	return err
}

// rotate listens under this and the next period's rendezvous keys and
// drops the rest, keeping the previous period's for a call across the
// boundary.
func (n *Node) rotate(ctx context.Context) error {
	n.lmu.Lock()
	defer n.lmu.Unlock()
	if n.left.Load() { // Leave sets it before taking lmu to drop the listeners
		return ErrLeft
	}
	now := n.now()
	p := keys.PeriodOf(now) // under lmu, so an older Tick can't undo a newer
	live := map[keys.Secret]bool{}
	gs := n.secrets(now)
	for _, g := range gs {
		live[g] = true
	}
	// Drop first, so a full listener table doesn't keep the old keys: a
	// superseded secret past Grace, and periods out of range.
	for k, s := range n.listening {
		if !live[k.g] || k.q+1 < p || k.q > p+1 { // q > p+1: the clock went back
			if n.h.ep.RemoveListener(ctx, s.Public()) == nil { // else the next Tick retries
				delete(n.listening, k)
			}
		}
	}
	var errs []error
	for i, g := range gs {
		for _, q := range []uint64{p, p + 1} {
			k := listenKey{g, q}
			if _, ok := n.listening[k]; ok {
				continue
			}
			s := n.cfg.Me.Rendezvous(g, q)
			err := n.h.ep.AddListener(ctx, keys.CryptoSigner(s))
			// The current secret is the one every up-to-date member calls:
			// with the table full (and only then: not on a cancelled
			// context, say), it takes the listeners of the superseded
			// secret whose window ends soonest, gs being ordered so (the
			// secret stays in Grace for admission and calls).
			for j := len(gs) - 1; errors.Is(err, dht.ErrTooManyListeners) && i == 0 && j > 0; j-- {
				if n.dropListeners(ctx, gs[j]) {
					err = n.h.ep.AddListener(ctx, keys.CryptoSigner(s))
				}
			}
			if err != nil {
				errs = append(errs, err)
				continue
			}
			n.listening[k] = s
		}
	}
	errs = append(errs, n.rotateInvites(ctx, p)...)
	return errors.Join(errs...)
}

// dropListeners removes the rendezvous listeners under g, reporting
// whether it removed any; lmu held.
func (n *Node) dropListeners(ctx context.Context, g keys.Secret) bool {
	dropped := false
	for k, s := range n.listening {
		if k.g == g && n.h.ep.RemoveListener(ctx, s.Public()) == nil {
			delete(n.listening, k)
			dropped = true
		}
	}
	return dropped
}

func (n *Node) listensUnder(key keys.PublicKey) bool {
	n.lmu.Lock()
	defer n.lmu.Unlock()
	if is, _ := n.inviteFor(key); is != nil {
		return true
	}
	s, _ := n.signerFor(key)
	return s != nil
}

// signerFor is the rendezvous listener whose key is key, and its group
// secret, or nil; lmu held.
func (n *Node) signerFor(key keys.PublicKey) (keys.Signer, keys.Secret) {
	for k, s := range n.listening {
		if s.Public() == key {
			return s, k.g
		}
	}
	return nil, keys.Secret{}
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
	now := n.now()
	// Follow the roster's current secret once the keyring holds it (a
	// member added concurrently with a rekey may not, until a deliver), and
	// keep for Grace every secret superseded since the last refresh, an
	// intermediate one in a batch of rekeys included: a member admitted
	// while it was current may hold no other.
	if err == nil {
		k := n.cfg.Roster.Keyring(n.cfg.Me)
		first := n.seenKeys == nil
		if first {
			n.seenKeys = map[roster.ID]time.Time{}
		}
		for _, o := range f.Order {
			// Only a counting key-making operation (the kinds that commit a
			// secret): a keyring holds rejected ones' secrets too, and a
			// member could otherwise fill the listener table with secrets
			// of rekeys it had no authority to write.
			if o.CommitSecret == ([32]byte{}) || !f.Counts[o.ID()] {
				continue
			}
			if _, ok := n.seenKeys[o.ID()]; !ok {
				if first {
					n.seenKeys[o.ID()] = time.Time{} // history: its window is over
				} else {
					n.seenKeys[o.ID()] = now.Add(Grace)
				}
			}
		}
		var cands []supersededSecret
		for id, until := range n.seenKeys {
			// Still counting: an operation counted when first seen can stop
			// (a concurrent demotion of its author, say).
			if id == f.Current || !now.Before(until) || !f.Counts[id] {
				continue
			}
			if g, ok := k.Secrets[id]; ok {
				cands = append(cands, supersededSecret{g: g, until: until})
			}
		}
		// Kept even while the current secret isn't held yet (pending a
		// deliver).
		g, ok := k.Secrets[f.Current]
		if !ok {
			g = n.Group()
		}
		if n.follow(g, cands, now) {
			n.rekeyed.Store(true)
		}
	}
	admit := map[keys.PublicKey]bool{}
	p := keys.PeriodOf(now)
	for _, g := range n.secrets(now) {
		for _, q := range []uint64{p - 1, p, p + 1} {
			for m := range roles {
				if m == n.cfg.Me.Public() {
					continue
				}
				if r, err := keys.Rendezvous(g, q, m); err == nil {
					admit[r] = true
				}
			}
			ours := n.cfg.Me.Rendezvous(g, q).Public()
			admit[g.SyncKey(q, ours).Public()] = true
		}
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
	signer, g := n.signerFor(c.LocalKey)
	issued, inviteSigner := n.inviteFor(c.LocalKey)
	n.lmu.Unlock()
	if issued != nil {
		n.serveJoin(ctx, c, issued, inviteSigner)
		return
	}
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
	// The idle timer can fire just as a stream arrives and resets it, so
	// it checks when the last one came and re-arms if that was too recent.
	idleFor := 2 * n.cfg.CallTimeout
	var lastStream atomic.Int64 // UnixNano
	lastStream.Store(time.Now().UnixNano())
	var idle *time.Timer
	idle = time.AfterFunc(idleFor, func() {
		if left := idleFor - time.Since(time.Unix(0, lastStream.Load())); left > 0 {
			idle.Reset(left)
			return
		}
		giveUp()
	})
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
		lastStream.Store(time.Now().UnixNano())
		idle.Reset(idleFor)
		try := streams.Add(1)
		if dest != streamName || try > busyTries {
			giveUp() // keeps a connection whose session has started
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
		if _, err := n.session(ctx, stream, c, false, g); err == nil {
			n.linger(ctx, stream)
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
	if n.doWaiting.Load() > 0 || !n.active.CompareAndSwap(false, true) {
		return false // a session, or a Do running or waiting
	}
	if n.left.Load() {
		n.active.Store(false)
		return false
	}
	n.mu.Lock() // held otherwise only by a refresh, briefly
	return true
}

func (n *Node) end() {
	n.mu.Unlock()
	n.active.Store(false)
}

// session runs one session on stream, begun, which it ends, and records
// the peer as reached when it ends well.
func (n *Node) session(ctx context.Context, stream net.Conn, c *endpoint.Conn, caller bool, g keys.Secret) (keys.PublicKey, error) {
	defer n.afterGroup()
	defer n.end()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	admission := time.AfterFunc(n.cfg.CallTimeout, cancel) // see CallTimeout
	defer admission.Stop()
	peer, err := session.Run(ctx, stream, session.Config{
		Me: n.cfg.Me, Group: g, Roster: n.cfg.Roster, Logs: n.cfg.Logs,
		Secret: c.Secret, Caller: caller, Local: c.LocalKey, Peer: c.PeerKey, Now: n.now(),
		Admitted: func() { admission.Stop() },
	})
	if err == nil {
		n.smu.Lock()
		n.seen[peer] = sighting{at: n.now(), g: g}
		n.smu.Unlock()
	}
	n.refresh() // even a failed session may have kept a newcomer's add chain
	return peer, err
}

// Do runs fn on the group's roster and logs, which a joined group shares
// with its sessions: change or read them only through Do. It waits for a
// running session to end (or ctx), and refreshes what the group admits
// afterwards.
func (n *Node) Do(ctx context.Context, fn func(*roster.Roster, *memberlog.Set) error) error {
	// Do claims the group as a session does, so a session finds it busy
	// rather than waiting on a callback nothing can cancel. While Do waits,
	// no new session begins, so callers can't starve it (it may be applying
	// a removal).
	n.doWaiting.Add(1)
	for !n.active.CompareAndSwap(false, true) {
		select {
		case <-time.After(10 * time.Millisecond):
		case <-ctx.Done():
			n.doWaiting.Add(-1)
			return ctx.Err()
		}
	}
	n.doWaiting.Add(-1)
	if n.left.Load() {
		n.active.Store(false)
		return ErrLeft
	}
	defer n.afterGroup() // after end, so outside the group
	n.mu.Lock()
	defer n.end()
	if err := ctx.Err(); err != nil {
		return err // ended while Do waited for the group
	}
	err := fn(n.cfg.Roster, n.cfg.Logs)
	n.refresh()
	return err
}

// afterGroup, once a session or Do has ended (deferred before end, so it
// runs after it), moves the listeners onto a group secret refresh just
// moved to.
func (n *Node) afterGroup() {
	if n.rekeyed.Swap(false) && n.ready.Load() && !n.left.Load() { // Join rotates on its own
		ctx, cancel := context.WithTimeout(context.Background(), n.cfg.CallTimeout)
		defer cancel()
		_ = n.rotate(ctx) // the next Tick retries what fails
	}
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
func (n *Node) linger(ctx context.Context, stream net.Conn) {
	t := time.AfterFunc(n.cfg.CallTimeout, func() { _ = stream.Close() })
	defer t.Stop()
	stop := context.AfterFunc(ctx, func() { _ = stream.Close() })
	defer stop()
	if _, err := stream.Write([]byte{doneMark}); err != nil {
		return
	}
	var b [1]byte
	_, _ = io.ReadFull(stream, b[:])
}

// Call reaches member and syncs with it: under this period's rendezvous
// key first, and if the member doesn't answer (it may not know us yet, and
// a listener stays silent to a caller it doesn't admit), under the sync
// key for calling it. A member that answers, or that isn't listening at
// all, isn't called again.
func (n *Node) Call(ctx context.Context, member keys.PublicKey) error {
	if n.left.Load() {
		return ErrLeft
	}
	ctx, finished, err := n.h.call(ctx)
	if err != nil {
		return err
	}
	defer finished()
	roles, err := n.view()
	if err != nil {
		return err
	}
	if roles[member] == roster.None {
		return ErrNotMember
	}
	now := n.now()
	p := keys.PeriodOf(now)
	var errs []error
	// The current secret first, then those superseded within Grace, for a
	// member that hasn't moved yet (it missed the change).
	for _, g := range n.secrets(now) {
		callee, err := keys.Rendezvous(g, p, member)
		if err != nil {
			return err
		}
		for _, as := range []keys.Signer{n.cfg.Me.Rendezvous(g, p), g.SyncKey(p, callee)} {
			connected, err := n.callAs(ctx, as, callee, g)
			if err == nil {
				return nil
			}
			errs = append(errs, err)
			if connected || ctx.Err() != nil {
				return errors.Join(errs...) // it answered, and the session failed
			}
			if !n.silent(ctx, err) {
				break // not listening under this secret: try the next
			}
			// Silent: it may not know us yet, so the sync key.
		}
	}
	return errors.Join(errs...)
}

// silent reports whether a failed Connect means the callee didn't answer
// (the one case a sync-key call can help): no holder delivered an answer,
// or the call ran out of time while ctx, the caller's, didn't.
func (n *Node) silent(ctx context.Context, err error) bool {
	return errors.Is(err, dht.ErrNoAnswer) || (errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil)
}

// callAs calls callee under as, reporting whether it connected: after
// that, the callee answered, and an error is the session's.
func (n *Node) callAs(ctx context.Context, as keys.Signer, callee keys.PublicKey, g keys.Secret) (bool, error) {
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
		rtt, err := n.try(sctx, cl, c, g)
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
func (n *Node) try(ctx context.Context, cl *hy2.Client, c *endpoint.Conn, g keys.Secret) (time.Duration, error) {
	dctx, cancel := context.WithTimeout(ctx, n.cfg.CallTimeout) // the first does the handshake
	stream, err := cl.DialConn(dctx, streamName)
	cancel()
	if err != nil {
		return 0, err
	}
	defer stream.Close() // unwritten, the callee never sees it
	if !n.begin() {
		if n.left.Load() {
			return 0, ErrLeft
		}
		return 0, ErrBusy // see active
	}
	start := time.Now()
	if err := n.answer(ctx, stream); err != nil {
		n.end()
		return time.Since(start), err
	}
	_, err = n.session(ctx, stream, c, true, g)
	rtt := time.Since(start)
	if err == nil {
		n.linger(ctx, stream)
	}
	return rtt, err
}

// answer writes the preamble and reads the callee's answer, waiting no
// longer than a call.
func (n *Node) answer(ctx context.Context, stream net.Conn) error {
	t := time.AfterFunc(n.cfg.CallTimeout, func() { _ = stream.Close() })
	defer t.Stop()
	stop := context.AfterFunc(ctx, func() { _ = stream.Close() })
	defer stop()
	if _, err := stream.Write([]byte{preamble}); err != nil {
		return err
	}
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
		out[k] = v.at
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
	return &directory.Directory{Group: n.Group(), Shards: n.shards, Store: n.h.ep.DHT(), Now: n.now}
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
	d := n.dir() // one snapshot of the secret, for the entries and the write
	g := d.Group
	entries := []directory.Entry{{Key: n.cfg.Me.Rendezvous(g, p).Public(), Seen: now}}
	n.smu.Lock()
	seen := maps.Clone(n.seen)
	n.smu.Unlock()
	for m, sg := range seen {
		// A member reached this period under this secret: one reached under
		// another may not be on this one, so it isn't published under it.
		t := sg.at
		if keys.PeriodOf(t) != p || sg.g != g {
			continue
		}
		if r, err := keys.Rendezvous(g, p, m); err == nil {
			entries = append(entries, directory.Entry{Key: r, Seen: t})
		}
	}
	return d.Write(ctx, p, members, entries)
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
