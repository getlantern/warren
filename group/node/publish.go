package node

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/getlantern/warren/group/content"
	"github.com/getlantern/warren/group/memberlog"
)

// PublishBlob seals a blob read from r into Config.Store and announces it in
// this member's log, with meta the app's (content.MaxMeta at most). The
// announcement goes the way of a post (Post): appended now, or held while
// publishing is paused (queued), and refused in the same cases; then the
// sealed pieces are deleted, so a refused blob leaves nothing behind (if
// the store can't delete them, the error says so and id names the blob). The
// pieces are sealed first, without holding the group: a large blob takes
// a while. Without a store, PublishBlob refuses (ErrNoStore).
func (n *Node) PublishBlob(ctx context.Context, r io.Reader, meta []byte) (id content.ID, queued bool, err error) {
	store := n.cfg.Store
	if store == nil {
		return id, false, ErrNoStore
	}
	if len(meta) > content.MaxMeta {
		return id, false, fmt.Errorf("node: meta of %d bytes is over content.MaxMeta", len(meta))
	}
	s, err := content.SealTo(store, r, 0)
	if err != nil {
		return id, false, err
	}
	body, err := s.Announce(meta).Encode()
	if err == nil {
		queued, err = n.post(ctx, memberlog.Blob, body)
	}
	if err != nil {
		// Unannounced, its key is gone with s. If it can't be deleted, its
		// ID comes back with the error, for the caller to retry.
		if derr := store.Delete(s.ID); derr != nil {
			return s.ID, false, errors.Join(err, fmt.Errorf("node: deleting the unannounced blob: %w", derr))
		}
		return id, false, err
	}
	return s.ID, queued, nil
}
