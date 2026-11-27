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
// Link is what the app hands out. n's member must be an owner or admin. It
// serves joins only while n runs on the group's current secret, which it
// follows; until its keyring holds a new one (a concurrent add, say, before
// a deliver), it refuses them (join.ErrAdminBehind). If
// a listener fails (a full listener table, say), the invite is still
// returned, with the error: it is recorded and held, and Tick retries the
// listener.
func (n *Node) Invite(ctx context.Context, uses uint32, ttl time.Duration, hints []netip.AddrPort) (*join.Issued, error) {
	var issued *join.Issued
	err := n.Do(ctx, func(r *roster.Roster, _ *memberlog.Set) error {
		var err error
		if issued, _, err = join.Issue(&roster.Writer{R: r, Me: n.cfg.Me, Now: n.now}, uses, ttl, hints, nil); err != nil {
			return err
		}
		// Registered and listened for within the Do, so a Leave (also a
		// Do) comes wholly before or after it.
		n.lmu.Lock()
		n.invites[issued.Invite.Key] = &invite{issued: issued, listening: map[uint64]keys.Signer{}}
		n.lmu.Unlock()
		return n.rotate(ctx)
	})
	return issued, err
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

// serveJoin runs one join session on c, a call to an invite listener. The
// request's proofs are checked first, within a call's time and without the
// roster, so a caller that can't prove the invite secret never takes the
// group; the answer is then decided with the roster to itself (Do), and
// the stream, a refusal's too, is held until the joiner hangs up, so the
// answer isn't lost with the teardown.
func (n *Node) serveJoin(ctx context.Context, c *endpoint.Conn, issued *join.Issued, signer keys.Signer) {
	ctx, cancel := context.WithTimeout(ctx, n.cfg.SessionTimeout)
	defer cancel()
	done := make(chan struct{})
	idle := time.NewTimer(2 * n.cfg.CallTimeout) // no stream: let it go
	defer idle.Stop()
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
		claimed := false
		once.Do(func() { claimed = true })
		if !claimed || dest != joinStream {
			return // one join session per connection
		}
		idle.Stop() // the session is under way: SessionTimeout bounds it
		defer close(done)
		defer n.holdAnswer(stream)
		vctx, vcancel := context.WithTimeout(ctx, n.cfg.CallTimeout)
		req, err := join.Verify(vctx, stream, issued.Invite, c.Secret)
		vcancel()
		if err != nil {
			return
		}
		cfg := func(r *roster.Roster) join.AdminConfig {
			return join.AdminConfig{Roster: r, Me: n.cfg.Me, Invite: issued.Invite, Secret: c.Secret,
				Now: n.now, Answered: &issued.Answered}
		}
		// Approve is the app's, and may take a while: it runs with the
		// group free, between a brief check of whether it's needed and the
		// answer, which checks everything again.
		var ask bool
		err = n.Do(ctx, func(r *roster.Roster, _ *memberlog.Set) error {
			if !n.onCurrentSecret(r) {
				return join.ErrAdminBehind
			}
			ask = join.NeedsApproval(cfg(r), req)
			return nil
		})
		if errors.Is(err, join.ErrAdminBehind) {
			_ = join.Refuse(ctx, stream, err)
			return
		}
		if err != nil {
			return
		}
		approved := n.cfg.Approve == nil
		if ask && n.cfg.Approve != nil {
			if !n.cfg.Approve(ctx, req) {
				_ = join.Refuse(ctx, stream, join.ErrNotApproved)
				return
			}
			if ctx.Err() != nil {
				return // the session ended while Approve decided
			}
			approved = true
		}
		_ = n.Do(ctx, func(r *roster.Roster, _ *memberlog.Set) error {
			if !n.onCurrentSecret(r) {
				return join.Refuse(ctx, stream, join.ErrAdminBehind)
			}
			// Fail closed: the answer asks for approval whenever it isn't
			// a retry, and gets yes only if the app gave it above. A check
			// that failed at the first Do and passes now (an issuer
			// promoted between them, say) is refused, not admitted unasked.
			c := cfg(r)
			c.Approve = func(context.Context, join.Request) bool { return approved }
			_, err := join.Answer(ctx, stream, c, req)
			return err
		})
	})
	if err != nil {
		return
	}
	select {
	case <-done:
	case <-idle.C:
		won := false
		once.Do(func() { won = true }) // a stream arriving now finds the session taken
		if !won {
			// A stream claimed it just as the timer fired: the session is
			// under way, and SessionTimeout bounds it.
			select {
			case <-done:
			case <-ctx.Done():
			}
		}
	case <-ctx.Done():
	}
	cancel()
	_ = srv.Close()
	hmu.Lock()
	returned = true
	hmu.Unlock()
	handlers.Wait()
}

// onCurrentSecret reports whether n runs on r's current group secret, and
// listens under it this period: it follows the roster's once its keyring
// holds it, and a joiner given a secret n isn't on (or doesn't listen
// under) couldn't reach it. mu held.
func (n *Node) onCurrentSecret(r *roster.Roster) bool {
	f, err := r.Fold()
	if err != nil {
		return false
	}
	g, ok := r.Keyring(n.cfg.Me).Secrets[f.Current]
	if !ok || g != n.Group() {
		return false
	}
	// And listening under it, or a joiner given it couldn't reach n (a
	// full listener table can fail the rotation onto a new secret).
	n.lmu.Lock()
	defer n.lmu.Unlock()
	_, listening := n.listening[listenKey{g, keys.PeriodOf(n.now())}]
	return listening
}

// holdAnswer holds stream, after an answer (or refusal) was written to it,
// until the joiner, having read it, hangs up, for no longer than a call.
func (n *Node) holdAnswer(stream net.Conn) {
	t := time.AfterFunc(n.cfg.CallTimeout, func() { _ = stream.Close() })
	defer t.Stop()
	_, _ = io.Copy(io.Discard, stream)
}

// ErrNoListener means no listener for the invite answered in this or a
// neighboring period.
var ErrNoListener = errors.New("node: the invite's admin didn't answer")

// JoinByInvite joins the group an invite is for as a new member, me (a
// fresh identity), named name, and returns the group's node on h. cfg
// gives its clock, timeouts and Approve; its Me, Group, Roster and Logs are
// filled in from the answer, whatever they held. The DHT is bootstrapped
// from the invite's hints, if any.
func (h *Host) JoinByInvite(ctx context.Context, iv join.Invite, me *keys.Identity, name string, cfg Config) (*Node, error) {
	return h.byInvite(ctx, iv, me, name, false, cfg)
}

// Rejoin comes back to a group under an existing member key, me, through
// an invite: for a member away past the grace window, which lacks the
// current group secret. It returns a fresh node on h for the group; leave
// any stale one first (Node.Leave), and pass its roster and logs as
// cfg.Roster and cfg.Logs. The saved roster is merged into the answer's
// (the admin may lack operations it holds, such as a rekey on a branch the
// admin hasn't seen), and the logs brought up to the merge, so the
// member's own log carries on rather than losing entries or restarting
// (which members would take as a fork). The node starts on the answer's
// group secret (following the merge's from there), and a saved removal of
// the member refuses the rejoin (ErrNotMember).
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
	// The node starts on the answer's group secret, the one the admin and
	// the members it knows of use. A saved rekey merged below may make
	// another current: the node then follows it, keeping the answer's for
	// Grace, so it still reaches them and passes the rekey on.
	fa, err := r.Fold()
	if err != nil {
		return nil, err
	}
	g, ok := r.Keyring(me).Secrets[fa.Current]
	if !ok {
		return nil, join.ErrBadAnswer
	}
	if rejoin && cfg.Roster != nil {
		if cfg.Roster.Group() != r.Group() {
			return nil, ErrNotMember // another group's state
		}
		saved, err := cfg.Roster.Fold()
		if err != nil {
			return nil, err
		}
		for _, o := range saved.Order[1:] { // causal order, past the genesis
			if _, err := r.Add(o); err != nil {
				return nil, err
			}
		}
	}
	f, err := r.Fold()
	if err != nil {
		return nil, err
	}
	if f.Roles[me.Public()] == roster.None {
		return nil, ErrNotMember // the saved roster holds this member's removal
	}
	logs := cfg.Logs
	if !rejoin || logs == nil { // a new member has no log to carry on
		logs = memberlog.NewSet(r.Group())
	}
	if err := logs.Update(f); err != nil {
		return nil, err
	}
	cfg.Me, cfg.Group, cfg.Roster, cfg.Logs = me, g, r, logs
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
		var t transportErr
		if errors.As(err, &t) && ctx.Err() == nil {
			errs = append(errs, err) // before the request was sent: try the next
			continue
		}
		return r, err
	}
	return nil, errors.Join(append([]error{ErrNoListener}, errs...)...)
}

// transportErr is a failure before a join request was sent, so another
// period's listener may still be tried.
type transportErr struct{ error }

func (e transportErr) Unwrap() error { return e.error }

func runJoin(ctx context.Context, c *endpoint.Conn, iv join.Invite, me *keys.Identity, name string, rejoin bool, cfg Config) (*roster.Roster, error) {
	sctx, cancel := context.WithTimeout(ctx, cfg.SessionTimeout)
	defer cancel()
	cl, err := hy2.Dial(sctx, c, c.Remote, c.PeerKey, hy2.FromSecret(c.Secret, hy2.ObfsUTP))
	if err != nil {
		return nil, transportErr{err}
	}
	defer func() { _ = cl.Close() }()
	dctx, dcancel := context.WithTimeout(sctx, cfg.CallTimeout)
	stream, err := cl.DialConn(dctx, joinStream)
	dcancel()
	if err != nil {
		return nil, transportErr{err}
	}
	defer stream.Close()
	return join.Join(sctx, stream, join.JoinConfig{Invite: iv, Me: me, Name: name, Rejoin: rejoin, Secret: c.Secret})
}

// Leave takes the group off its host: it waits for a running session or Do
// to end (or ctx), then drops its listeners, invites included. The roster
// and logs are the caller's again: no session or Do begins after, even one
// already waiting (ErrLeft).
func (n *Node) Leave(ctx context.Context) error {
	return n.Do(ctx, func(*roster.Roster, *memberlog.Set) error {
		n.left.Store(true)
		n.ready.Store(false)
		n.leave()
		return nil
	})
}
