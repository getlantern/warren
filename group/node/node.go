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

// preamble is the byte a caller writes as soon as it opens the stream: a
// hysteria2 server isn't handed a stream until its client writes, and a
// sync-key caller writes nothing of the session until it has the callee's
// hello.
const preamble = 'g'

// ErrNotMember means a member the roster doesn't hold was called.
var ErrNotMember = errors.New("node: not a member")

// Host owns a warren endpoint and routes its listeners and connections to
// the groups joined on it.
type Host struct {
	ep     *endpoint.Endpoint
	mu     sync.Mutex
	groups []*Node
	cancel context.CancelFunc
	done   chan struct{}
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
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go h.accept(ctx)
	return h, nil
}

// Endpoint is the host's endpoint, for bootstrapping its DHT.
func (h *Host) Endpoint() *endpoint.Endpoint { return h.ep }

// Close stops every group and the endpoint.
func (h *Host) Close() error {
	h.cancel()
	err := h.ep.Close()
	<-h.done
	return err
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
		go n.serve(ctx, c)
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
	// CallTimeout bounds one attempt to reach a member; zero means 15s.
	CallTimeout time.Duration
	// SessionTimeout bounds one session; zero means a minute.
	SessionTimeout time.Duration
}

// Node is one group on a host.
type Node struct {
	h   *Host
	cfg Config
	// mu holds the roster and logs, which aren't safe for concurrent use:
	// one session at a time per group.
	mu sync.Mutex

	lmu       sync.Mutex
	listening map[uint64]keys.Signer // period → the rendezvous key listened under
	admit     atomic.Pointer[map[keys.PublicKey]bool]

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
	n := &Node{h: h, cfg: cfg, listening: map[uint64]keys.Signer{}, seen: map[keys.PublicKey]time.Time{}}
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

// Tick brings the listeners up to the clock: this and the next period's
// rendezvous keys, the older ones dropped, and the admission set rebuilt.
// Run it every few minutes (and after a roster change from outside a
// session).
func (n *Node) Tick(ctx context.Context) error {
	p := keys.PeriodOf(n.now())
	n.lmu.Lock()
	defer n.lmu.Unlock()
	for _, q := range []uint64{p, p + 1} {
		if _, ok := n.listening[q]; ok {
			continue
		}
		s := n.cfg.Me.Rendezvous(n.cfg.Group, q)
		if err := n.h.ep.AddListener(ctx, keys.CryptoSigner(s)); err != nil {
			return err
		}
		n.listening[q] = s
	}
	for q, s := range n.listening {
		if q+1 < p { // keep the previous period's for a call across the boundary
			if n.h.ep.RemoveListener(ctx, s.Public()) == nil { // else the next Tick retries
				delete(n.listening, q)
			}
		}
	}
	n.refresh()
	return nil
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
// keys for calling each of ours. The roster is read under mu.
func (n *Node) refresh() {
	n.mu.Lock()
	f, err := n.cfg.Roster.Fold()
	n.mu.Unlock()
	if err != nil {
		return
	}
	p := keys.PeriodOf(n.now())
	admit := map[keys.PublicKey]bool{}
	for _, q := range []uint64{p - 1, p, p + 1} {
		for m := range f.Roles {
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
	done := make(chan struct{})
	var once sync.Once
	srv, err := hy2.Serve(ctx, c, keys.CryptoSigner(signer), hy2.FromSecret(c.Secret, hy2.ObfsUTP), func(stream net.Conn, dest string) {
		defer stream.Close()
		if dest != streamName {
			return
		}
		once.Do(func() {
			defer close(done)
			var b [1]byte
			if _, err := io.ReadFull(stream, b[:]); err != nil || b[0] != preamble {
				return
			}
			_, _ = n.session(ctx, stream, c, false)
		})
	})
	if err != nil {
		return
	}
	defer func() { _ = srv.Close() }()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// session runs one session on stream, holding the group's lock, and
// records the peer as reached when it ends well.
func (n *Node) session(ctx context.Context, stream net.Conn, c *endpoint.Conn, caller bool) (keys.PublicKey, error) {
	n.mu.Lock()
	peer, err := session.Run(ctx, stream, session.Config{
		Me: n.cfg.Me, Group: n.cfg.Group, Roster: n.cfg.Roster, Logs: n.cfg.Logs,
		Secret: c.Secret, Caller: caller, Local: c.LocalKey, Peer: c.PeerKey, Now: n.now(),
	})
	n.mu.Unlock()
	if err == nil {
		n.smu.Lock()
		n.seen[peer] = n.now()
		n.smu.Unlock()
		n.refresh() // the session may have changed the roster
	}
	return peer, err
}

// Call reaches member and syncs with it: under this period's rendezvous
// key first, and if the member doesn't answer (it may not know us yet, and
// a listener stays silent to a caller it doesn't admit), under the sync
// key for calling it.
func (n *Node) Call(ctx context.Context, member keys.PublicKey) error {
	n.mu.Lock()
	f, err := n.cfg.Roster.Fold()
	n.mu.Unlock()
	if err != nil {
		return err
	}
	if f.Roles[member] == roster.None {
		return ErrNotMember
	}
	p := keys.PeriodOf(n.now())
	callee, err := keys.Rendezvous(n.cfg.Group, p, member)
	if err != nil {
		return err
	}
	var errs []error
	for _, as := range []keys.Signer{n.cfg.Me.Rendezvous(n.cfg.Group, p), n.cfg.Group.SyncKey(p, callee)} {
		err := n.callAs(ctx, as, callee)
		if err == nil {
			return nil
		}
		errs = append(errs, err)
		if ctx.Err() != nil {
			break
		}
	}
	return errors.Join(errs...)
}

func (n *Node) callAs(ctx context.Context, as keys.Signer, callee keys.PublicKey) error {
	cctx, cancel := context.WithTimeout(ctx, n.cfg.CallTimeout)
	defer cancel()
	c, err := n.h.ep.Connect(cctx, keys.CryptoSigner(as), callee)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	sctx, scancel := context.WithTimeout(ctx, n.cfg.SessionTimeout)
	defer scancel()
	cl, err := hy2.Dial(sctx, c, c.Remote, c.PeerKey, hy2.FromSecret(c.Secret, hy2.ObfsUTP))
	if err != nil {
		return err
	}
	defer func() { _ = cl.Close() }()
	stream, err := cl.DialConn(sctx, streamName)
	if err != nil {
		return err
	}
	defer stream.Close()
	if _, err := stream.Write([]byte{preamble}); err != nil {
		return err
	}
	_, err = n.session(sctx, stream, c, true)
	return err
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
	n.mu.Lock()
	f, err := n.cfg.Roster.Fold()
	n.mu.Unlock()
	if err != nil {
		return err
	}
	seen := n.Seen()
	var members []keys.PublicKey
	for m := range f.Roles {
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
	return &directory.Directory{Group: n.cfg.Group, Shards: n.cfg.Roster.Op(n.cfg.Roster.Group()).Shards, Store: n.h.ep.DHT(), Now: n.now}
}

func (n *Node) members() ([]keys.PublicKey, error) {
	n.mu.Lock()
	f, err := n.cfg.Roster.Fold()
	n.mu.Unlock()
	if err != nil {
		return nil, err
	}
	var out []keys.PublicKey
	for m := range f.Roles {
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
