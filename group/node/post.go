package node

import (
	"context"

	"github.com/getlantern/warren/group/memberlog"
	"github.com/getlantern/warren/group/roster"
)

// Paused reports whether publishing is paused: the roster's current keys
// have reached a key that isn't a member (a removal racing another, say),
// so the node holds its posts until an admin's corrective rekey lands
// (docs/groups-design.md, *Removal*, step 3).
func (n *Node) Paused() bool { return n.paused.Load() }

// Post appends an app entry, body, to this member's own log under the
// current epoch key. While publishing is paused it is held instead, in
// order, and appended once the pause lifts: queued reports that, and
// ErrQueueFull a hold past MaxQueued.
func (n *Node) Post(ctx context.Context, body []byte) (queued bool, err error) {
	err = n.Do(ctx, func(r *roster.Roster, logs *memberlog.Set) error {
		if n.paused.Load() || !n.canWrite(r) {
			if len(n.queue) >= MaxQueued {
				return ErrQueueFull
			}
			n.queue = append(n.queue, append([]byte(nil), body...))
			queued = true
			return nil
		}
		return n.write(r, logs, body)
	})
	return queued, err
}

// canWrite reports whether n holds the current epoch key to write under
// (a member added concurrently with a rekey may not, until a deliver).
// mu held.
func (n *Node) canWrite(r *roster.Roster) bool {
	f, err := r.Fold()
	if err != nil {
		return false
	}
	_, ok := r.Keyring(n.cfg.Me).Epochs[f.Current]
	return ok
}

// write appends body to this member's log under the current epoch key.
// mu held.
func (n *Node) write(r *roster.Roster, logs *memberlog.Set, body []byte) error {
	f, err := r.Fold()
	if err != nil {
		return err
	}
	// The logs check entries against the fold they were last given, which
	// may predate the epoch (a rekey added through Do).
	if err := logs.Update(f); err != nil {
		return err
	}
	var prev *memberlog.Entry
	if l := logs.Log(n.cfg.Me.Public()); l != nil {
		prev = l.Head()
	}
	e, err := memberlog.Write(n.cfg.Me, r.Group(), prev, f.Current, r.Keyring(n.cfg.Me).Epochs[f.Current], memberlog.App, body)
	if err != nil {
		return err
	}
	_, err = logs.Add(e)
	return err
}

// flush appends the held posts, in order, once publishing may resume; a
// failure leaves the rest held for the next refresh. mu held.
func (n *Node) flush() {
	if len(n.queue) == 0 || !n.canWrite(n.cfg.Roster) {
		return
	}
	for len(n.queue) > 0 {
		if n.write(n.cfg.Roster, n.cfg.Logs, n.queue[0]) != nil {
			return
		}
		n.queue = n.queue[1:]
	}
}

// correct issues the corrective rekey a paused roster calls for, if n's
// member is an owner or admin: a rekey sealed only to the members the fold
// keeps, which lifts the pause once members have it. It's written at most
// once per exposure: depending on every head, it sorts last and counts, so
// the fold after it no longer calls for one.
func (n *Node) correct(ctx context.Context) error {
	if !n.paused.Load() {
		return nil
	}
	return n.Do(ctx, func(r *roster.Roster, _ *memberlog.Set) error {
		f, err := r.Fold()
		if err != nil || !r.NeedsRekey(f) {
			return err
		}
		if role := f.Roles[n.cfg.Me.Public()]; role != roster.Owner && role != roster.Admin {
			return nil
		}
		_, err = (&roster.Writer{R: r, Me: n.cfg.Me, Now: n.now}).Rekey()
		return err
	})
}
