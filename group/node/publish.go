package node

import (
	"context"
	"fmt"
	"io"

	"github.com/getlantern/warren/group/content"
	"github.com/getlantern/warren/group/memberlog"
)

// PublishBlob seals a blob read from r into Config.Store and announces it in
// this member's log, with meta the app's (content.MaxMeta at most). The
// announcement goes the way of a post (Post): appended now, or held while
// publishing is paused (queued), and refused in the same cases; then the
// sealed pieces are deleted, so a refused blob leaves nothing behind. The
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
		_ = store.Delete(s.ID) // unannounced: its key is gone with s
		return id, false, err
	}
	return s.ID, queued, nil
}
