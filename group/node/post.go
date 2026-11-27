package node

import (
	"context"
	"fmt"

	"github.com/getlantern/warren/group/keys"
	"github.com/getlantern/warren/group/memberlog"
	"github.com/getlantern/warren/group/roster"
)

// Paused reports whether publishing is paused: the roster's current keys
// have reached a key that isn't a member (a removal racing another, say),
// so the node holds its posts until an admin's corrective rekey lands
// (docs/groups-design.md, *Removal*, step 3). A roster that won't fold
// pauses it too.
func (n *Node) Paused() bool { return n.paused.Load() }

// Post appends an app entry, body, to this member's own log under the
// current epoch key. While publishing is paused, or the member doesn't hold
// that key yet (pending a deliver), it is held instead and appended, in
// order, once it can be: queued reports that it wasn't appended by the
// time Post returns (it's held, or TakeHeld has handed it over), and
// ErrQueueFull a hold past MaxQueued. A mirror or a removed member can't
// post (roster.ErrNotAllowed), nor can a body over memberlog.MaxBody be.
// While this member's own log holds entries past what shows, a post is
// refused (ErrHidden), held or not, and held posts stay held: anything
// appended would be hidden too. A forked own log refuses posts too
// (memberlog.ErrForked). Otherwise, if held posts failed to append, a post
// is refused with that failure (ErrHeldFailed) until they do or TakeHeld
// clears them.
func (n *Node) Post(ctx context.Context, body []byte) (queued bool, err error) {
	if len(body) > memberlog.MaxBody {
		return false, fmt.Errorf("node: post of %d bytes is over memberlog.MaxBody", len(body))
	}
	var held *heldPost
	err = n.Do(ctx, func(r *roster.Roster, logs *memberlog.Set) error {
		f, err := r.Fold()
		if err == nil {
			if role := f.Roles[n.cfg.Me.Public()]; role == roster.None || role == roster.Mirror {
				return roster.ErrNotAllowed
			}
		}
		var key keys.EpochKey
		ok := false
		if err == nil {
			if err := logs.Update(f); err != nil {
				return err
			}
			if err := n.ownLog(logs); err != nil {
				return err
			}
			key, ok = r.Keyring(n.cfg.Me).Epochs[f.Current]
		}
		if n.flushErr != nil {
			return fmt.Errorf("%w: %w", ErrHeldFailed, n.flushErr)
		}
		// Behind anything held, so posts keep their order.
		if !ok || n.paused.Load() || len(n.queue) > 0 {
			if len(n.queue) >= MaxQueued {
				return ErrQueueFull
			}
			held = &heldPost{body: append([]byte(nil), body...)}
			n.queue = append(n.queue, held)
			return nil
		}
		return n.write(r, logs, f, key, body)
	})
	if err != nil || held == nil {
		return false, err
	}
	// Do's refresh may have appended it already (or TakeHeld handed it
	// over since, which isn't appending it).
	n.mu.Lock()
	defer n.mu.Unlock()
	return !held.written, nil
}

// heldPost is a post held for publishing; written once a flush appends
// it. mu held.
type heldPost struct {
	body    []byte
	written bool
}

// TakeHeld hands over the posts held for publishing, oldest first (what
// Post queued and a flush hasn't appended), and clears them, with any
// failure appending them: the caller posts them again or drops them. After
// Leave nothing appends them, so a caller taking the roster and logs back
// takes these too. It waits for a running session or Do.
func (n *Node) TakeHeld() [][]byte {
	n.mu.Lock()
	defer n.mu.Unlock()
	h := make([][]byte, len(n.queue))
	for i, p := range n.queue {
		h[i] = p.body
	}
	n.queue, n.flushErr = nil, nil
	return h
}

// write appends body to this member's log under key, f's current epoch
// key; logs must have been given f, and ownLog must have found nothing in
// the way. mu held.
func (n *Node) write(r *roster.Roster, logs *memberlog.Set, f *roster.Result, key keys.EpochKey, body []byte) error {
	var prev *memberlog.Entry
	if l := logs.Log(n.cfg.Me.Public()); l != nil {
		prev = l.Head()
	}
	e, err := memberlog.Write(n.cfg.Me, r.Group(), prev, f.Current, key, memberlog.App, body)
	if err != nil {
		return err
	}
	_, err = logs.Add(e)
	return err
}

// ownLog reports why nothing appended to this member's own log now would
// show: memberlog.ErrForked if it's forked, ErrHidden if it holds entries
// past what shows (under an epoch that stopped counting, say, or past a
// gap: an entry after the head would fork against them); nil if something
// would. logs must have been given the current fold. mu held.
func (n *Node) ownLog(logs *memberlog.Set) error {
	l := logs.Log(n.cfg.Me.Public())
	if l == nil {
		return nil
	}
	if l.Fork() != nil {
		return memberlog.ErrForked
	}
	h, last := l.Head(), l.Last()
	if last != nil && (h == nil || h.ID() != last.ID()) {
		return ErrHidden
	}
	var shown uint64
	if last != nil {
		shown = last.Seq
	}
	if uint64(l.Len()) > shown {
		return ErrHidden // past a gap
	}
	return nil
}

// flush appends the held posts, in order, once publishing may resume,
// against one fold. The logs check entries against the fold they were last
// given, which may predate the epoch (a rekey added through Do), so they
// get this one. A failure leaves the rest held, and is kept for Post, until
// a later flush succeeds. mu held.
func (n *Node) flush() {
	if len(n.queue) == 0 {
		return
	}
	r, logs := n.cfg.Roster, n.cfg.Logs
	f, err := r.Fold()
	if err != nil {
		return
	}
	key, ok := r.Keyring(n.cfg.Me).Epochs[f.Current]
	if !ok {
		return
	}
	if err := logs.Update(f); err != nil {
		n.flushErr = err
		return
	}
	for len(n.queue) > 0 {
		// Each time: a write that didn't show would make the next fork.
		if n.ownLog(logs) != nil {
			return // held until the log can take them; Post says why
		}
		if err := n.write(r, logs, f, key, n.queue[0].body); err != nil {
			n.flushErr = err
			return
		}
		n.queue[0].written = true
		n.queue = n.queue[1:]
	}
	n.flushErr = nil
}

// correct issues the corrective rekey a paused roster calls for, if n's
// member is an owner or admin: a rekey sealed only to the members the fold
// keeps, which lifts the pause once members have it. It's written at most
// once per exposure: depending on every head, it sorts last and counts, so
// the fold after it no longer calls for one. Other nodes, and a roster that
// won't fold, don't claim the group for it.
func (n *Node) correct(ctx context.Context) error {
	if !n.paused.Load() || !n.admin() {
		return nil
	}
	return n.Do(ctx, func(r *roster.Roster, _ *memberlog.Set) error {
		f, err := r.Fold()
		if err != nil || !r.NeedsRekey(f) {
			return nil
		}
		if role := f.Roles[n.cfg.Me.Public()]; role != roster.Owner && role != roster.Admin {
			return nil
		}
		_, err = (&roster.Writer{R: r, Me: n.cfg.Me, Now: n.now}).Rekey()
		return err
	})
}

// admin reports whether n's member was an owner or admin at the last
// refresh.
func (n *Node) admin() bool {
	roles, err := n.view()
	if err != nil {
		return false
	}
	role := roles[n.cfg.Me.Public()]
	return role == roster.Owner || role == roster.Admin
}
