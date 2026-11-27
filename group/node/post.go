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
// order, once it can be: queued reports that it's still held when Post
// returns, and ErrQueueFull a hold past MaxQueued. A mirror or a removed
// member can't post (roster.ErrNotAllowed), nor can a body over
// memberlog.MaxBody be. If held posts failed to append, a post is refused
// with that failure (ErrHeldFailed) until they do or TakeHeld clears them.
func (n *Node) Post(ctx context.Context, body []byte) (queued bool, err error) {
	if len(body) > memberlog.MaxBody {
		return false, fmt.Errorf("node: post of %d bytes is over memberlog.MaxBody", len(body))
	}
	var at uint64 // its place in the queue's history, if held
	held := false
	err = n.Do(ctx, func(r *roster.Roster, logs *memberlog.Set) error {
		if n.flushErr != nil {
			return fmt.Errorf("%w: %w", ErrHeldFailed, n.flushErr)
		}
		f, err := r.Fold()
		if err == nil {
			if role := f.Roles[n.cfg.Me.Public()]; role == roster.None || role == roster.Mirror {
				return roster.ErrNotAllowed
			}
		}
		var key keys.EpochKey
		ok := false
		if err == nil {
			key, ok = r.Keyring(n.cfg.Me).Epochs[f.Current]
		}
		// Behind anything held, so posts keep their order.
		if !ok || n.paused.Load() || len(n.queue) > 0 {
			if len(n.queue) >= MaxQueued {
				return ErrQueueFull
			}
			at, held = n.flushed+uint64(len(n.queue)), true
			n.queue = append(n.queue, append([]byte(nil), body...))
			return nil
		}
		if err := logs.Update(f); err != nil {
			return err
		}
		return n.write(r, logs, f, key, body)
	})
	if err != nil || !held {
		return false, err
	}
	// Do's refresh may have appended it already.
	n.mu.Lock()
	defer n.mu.Unlock()
	return at >= n.flushed, nil
}

// TakeHeld hands over the posts held for publishing, oldest first (what
// Post queued and a flush hasn't appended), and clears them, with any
// failure appending them: the caller posts them again or drops them. After
// Leave nothing appends them, so a caller taking the roster and logs back
// takes these too. It waits for a running session or Do.
func (n *Node) TakeHeld() [][]byte {
	n.mu.Lock()
	defer n.mu.Unlock()
	h := n.queue
	n.flushed += uint64(len(h))
	n.queue, n.flushErr = nil, nil
	return h
}

// write appends body to this member's log under key, f's current epoch
// key; logs must have been given f. It chains from the last entry on the
// log's line, not its head: entries under an epoch that stopped counting
// are still this member's, and one at the head's next number would fork
// the log. mu held.
func (n *Node) write(r *roster.Roster, logs *memberlog.Set, f *roster.Result, key keys.EpochKey, body []byte) error {
	var prev *memberlog.Entry
	if l := logs.Log(n.cfg.Me.Public()); l != nil {
		prev = l.Last()
	}
	e, err := memberlog.Write(n.cfg.Me, r.Group(), prev, f.Current, key, memberlog.App, body)
	if err != nil {
		return err
	}
	_, err = logs.Add(e)
	return err
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
		if err := n.write(r, logs, f, key, n.queue[0]); err != nil {
			n.flushErr = err
			return
		}
		n.queue = n.queue[1:]
		n.flushed++
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
