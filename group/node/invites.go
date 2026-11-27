package node

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/getlantern/warren/endpoint"
	"github.com/getlantern/warren/group/join"
	"github.com/getlantern/warren/group/keys"
	"github.com/getlantern/warren/group/memberlog"
	"github.com/getlantern/warren/group/roster"
	"github.com/getlantern/warren/transport/hy2"
)

// joinStream is the hysteria2 destination a join session stream asks for.
const joinStream = "warren-join:1"

// invite is an invite the node issued and listens under, per period, until
// join.RetryGrace past its expiry.
type invite struct {
	issued    *join.Issued
	listening map[uint64]keys.Signer
}

// Invite issues an invite admitting up to uses joiners and rejoiners for
// ttl, records it in the roster, and listens for it; the returned invite's
// Link is what the app hands out. n's member must be an owner or admin.
func (n *Node) Invite(ctx context.Context, uses uint32, ttl time.Duration, hints []netip.AddrPort) (*join.Issued, error) {
	var issued *join.Issued
	err := n.Do(ctx, func(r *roster.Roster, _ *memberlog.Set) error {
		var err error
		issued, _, err = join.Issue(&roster.Writer{R: r, Me: n.cfg.Me, Now: n.now}, uses, ttl, hints, nil)
		return err
	})
	if err != nil {
		return nil, err
	}
	n.lmu.Lock()
	n.invites[issued.Invite.Key] = &invite{issued: issued, listening: map[uint64]keys.Signer{}}
	n.lmu.Unlock()
	return issued, n.rotate(ctx)
}

// rotateInvites listens under each invite's key blinded for this and the
// next period, keeping the previous period's for a call across the
// boundary, and drops an invite join.RetryGrace past its expiry. lmu held.
func (n *Node) rotateInvites(ctx context.Context, p uint64) []error {
	var errs []error
	now := n.now()
	for k, iv := range n.invites {
		over := now.After(time.Unix(iv.issued.Invite.Expires, 0).Add(join.RetryGrace))
		for q, s := range iv.listening {
			if over || q+1 < p || q > p+1 {
				if n.h.ep.RemoveListener(ctx, s.Public()) == nil { // else the next Tick retries
					delete(iv.listening, q)
				}
			}
		}
		if over {
			if len(iv.listening) == 0 {
				delete(n.invites, k)
			}
			continue
		}
		for _, q := range []uint64{p, p + 1} {
			if _, ok := iv.listening[q]; ok {
				continue
			}
			s := iv.issued.Listener(q)
			if err := n.h.ep.AddListener(ctx, keys.CryptoSigner(s)); err != nil {
				errs = append(errs, err)
				continue
			}
			iv.listening[q] = s
		}
	}
	return errs
}

// inviteFor is the invite listening under key, and its signer, or nil; lmu
// held.
func (n *Node) inviteFor(key keys.PublicKey) (*join.Issued, keys.Signer) {
	for _, iv := range n.invites {
		for _, s := range iv.listening {
			if s.Public() == key {
				return iv.issued, s
			}
		}
	}
	return nil, nil
}

// isInviteKey reports whether key is one of n's invite listeners: anyone
// holding the link may call it, with a fresh key, and the join session's
// proofs decide.
func (n *Node) isInviteKey(key keys.PublicKey) bool {
	n.lmu.Lock()
	defer n.lmu.Unlock()
	is, _ := n.inviteFor(key)
	return is != nil
}

// serveJoin runs one join session on c, a call to an invite listener: the
// roster is the session's alone (Do), and the answer is held until the
// joiner hangs up, so it isn't lost with the teardown.
func (n *Node) serveJoin(ctx context.Context, c *endpoint.Conn, issued *join.Issued, signer keys.Signer) {
	ctx, cancel := context.WithTimeout(ctx, n.cfg.SessionTimeout)
	defer cancel()
	done := make(chan struct{})
	var (
		once     sync.Once
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
		ran := false
		once.Do(func() { ran = true })
		if !ran || dest != joinStream {
			return // one join session per connection
		}
		defer close(done)
		var served bool
		_ = n.Do(ctx, func(r *roster.Roster, _ *memberlog.Set) error {
			_, _, err := join.Serve(ctx, stream, join.AdminConfig{
				Roster: r, Me: n.cfg.Me, Invite: issued.Invite, Secret: c.Secret,
				Approve: n.cfg.Approve, Now: n.now, Answered: &issued.Answered,
			})
			served = err == nil
			return err
		})
		if served {
			// Hold the stream until the joiner, having read the answer,
			// hangs up, for no longer than a call.
			t := time.AfterFunc(n.cfg.CallTimeout, func() { _ = stream.Close() })
			defer t.Stop()
			_, _ = io.Copy(io.Discard, stream)
		}
	})
	if err != nil {
		return
	}
	idle := time.NewTimer(2 * n.cfg.CallTimeout) // no stream: let it go
	defer idle.Stop()
	select {
	case <-done:
	case <-idle.C:
		once.Do(func() {}) // a stream arriving now finds the session taken
	case <-ctx.Done():
	}
	cancel()
	_ = srv.Close()
	hmu.Lock()
	returned = true
	hmu.Unlock()
	handlers.Wait()
}

// ErrNoListener means no listener for the invite answered in this or a
// neighboring period.
var ErrNoListener = errors.New("node: the invite's admin didn't answer")

// JoinByInvite joins the group an invite is for as a new member, me (a
// fresh identity), named name, and returns the group's node on h. cfg
// gives its clock and timeouts; its Me, Group, Roster and Logs are filled
// in from the answer. The DHT is bootstrapped from the invite's hints, if
// any.
func (h *Host) JoinByInvite(ctx context.Context, iv join.Invite, me *keys.Identity, name string, cfg Config) (*Node, error) {
	return h.byInvite(ctx, iv, me, name, false, cfg)
}

// Rejoin comes back to a group under an existing member key, me, through
// an invite: for a member away past the grace window, which lacks the
// current group secret. It returns a fresh node on h for the group; leave
// any stale one first (Node.Leave).
func (h *Host) Rejoin(ctx context.Context, iv join.Invite, me *keys.Identity, cfg Config) (*Node, error) {
	return h.byInvite(ctx, iv, me, "", true, cfg)
}

func (h *Host) byInvite(ctx context.Context, iv join.Invite, me *keys.Identity, name string, rejoin bool, cfg Config) (*Node, error) {
	ctx, finished, err := h.call(ctx)
	if err != nil {
		return nil, err
	}
	defer finished()
	cfg = withDefaults(cfg)
	if len(iv.Hints) > 0 {
		_, _ = h.ep.DHT().Bootstrap(ctx, iv.Hints) // the DHT may already be up
	}
	r, err := h.joinSession(ctx, iv, me, name, rejoin, cfg)
	if err != nil {
		return nil, err
	}
	f, err := r.Fold()
	if err != nil {
		return nil, err
	}
	logs := memberlog.NewSet(r.Group())
	if err := logs.Update(f); err != nil {
		return nil, err
	}
	cfg.Me, cfg.Group, cfg.Roster, cfg.Logs = me, r.Keyring(me).Secrets[f.Current], r, logs
	return h.Join(ctx, cfg)
}

// joinSession calls the invite's listener under a fresh key, for this
// period, then the next and the previous across a boundary, and runs the
// join session on the first that answers.
func (h *Host) joinSession(ctx context.Context, iv join.Invite, me *keys.Identity, name string, rejoin bool, cfg Config) (*roster.Roster, error) {
	now := time.Now
	if cfg.Now != nil {
		now = cfg.Now
	}
	p := keys.PeriodOf(now())
	var errs []error
	for _, q := range []uint64{p, p + 1, p - 1} {
		listener, err := iv.Listener(q)
		if err != nil {
			return nil, err
		}
		caller, err := keys.NewIdentity(rand.Reader)
		if err != nil {
			return nil, err
		}
		cctx, cancel := context.WithTimeout(ctx, cfg.CallTimeout)
		c, err := h.ep.Connect(cctx, keys.CryptoSigner(caller), listener)
		cancel()
		if err != nil {
			errs = append(errs, err)
			if ctx.Err() != nil {
				break
			}
			continue
		}
		r, err := runJoin(ctx, c, iv, me, name, rejoin, cfg)
		_ = c.Close()
		return r, err
	}
	return nil, errors.Join(append([]error{ErrNoListener}, errs...)...)
}

func runJoin(ctx context.Context, c *endpoint.Conn, iv join.Invite, me *keys.Identity, name string, rejoin bool, cfg Config) (*roster.Roster, error) {
	sctx, cancel := context.WithTimeout(ctx, cfg.SessionTimeout)
	defer cancel()
	cl, err := hy2.Dial(sctx, c, c.Remote, c.PeerKey, hy2.FromSecret(c.Secret, hy2.ObfsUTP))
	if err != nil {
		return nil, err
	}
	defer func() { _ = cl.Close() }()
	dctx, dcancel := context.WithTimeout(sctx, cfg.CallTimeout)
	stream, err := cl.DialConn(dctx, joinStream)
	dcancel()
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	return join.Join(sctx, stream, join.JoinConfig{Invite: iv, Me: me, Name: name, Rejoin: rejoin, Secret: c.Secret})
}

// Leave takes the group off its host: it waits for a running session or Do
// to end (or ctx), then drops its listeners, invites included. The roster
// and logs are the caller's again.
func (n *Node) Leave(ctx context.Context) error {
	return n.Do(ctx, func(*roster.Roster, *memberlog.Set) error {
		n.ready.Store(false)
		n.leave()
		return nil
	})
}
