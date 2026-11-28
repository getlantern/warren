package node

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/getlantern/warren/group/content"
	"github.com/getlantern/warren/group/keys"
	"github.com/getlantern/warren/group/memberlog"
	"github.com/getlantern/warren/group/roster"
)

// recordingStore is a MemStore noting what's committed and deleted.
type recordingStore struct {
	*content.MemStore
	mu        sync.Mutex
	committed map[content.ID]bool
	created   int
}

func newRecordingStore() *recordingStore {
	return &recordingStore{MemStore: content.NewMemStore(), committed: map[content.ID]bool{}}
}

func (s *recordingStore) Create() (content.BlobWriter, error) {
	s.mu.Lock()
	s.created++
	s.mu.Unlock()
	w, err := s.MemStore.Create()
	return &recordingWriter{BlobWriter: w, s: s}, err
}

func (s *recordingStore) Delete(id content.ID) error {
	s.mu.Lock()
	delete(s.committed, id)
	s.mu.Unlock()
	return s.MemStore.Delete(id)
}

func (s *recordingStore) held() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.committed)
}

type recordingWriter struct {
	content.BlobWriter
	s *recordingStore
}

func (w *recordingWriter) Commit(id content.ID) error {
	w.s.mu.Lock()
	w.s.committed[id] = true
	w.s.mu.Unlock()
	return w.BlobWriter.Commit(id)
}

// entries opens id's visible log entries on n: their kinds and bodies.
func entries(t *testing.T, n *Node, id *keys.Identity) (kinds []memberlog.Kind, bodies [][]byte) {
	t.Helper()
	if err := n.Do(context.Background(), func(r *roster.Roster, logs *memberlog.Set) error {
		l := logs.Log(id.Public())
		if l == nil {
			return nil
		}
		for _, e := range l.Entries() {
			k, b, err := e.Open(r.Keyring(id).Epochs[e.Epoch])
			if err != nil {
				return err
			}
			kinds, bodies = append(kinds, k), append(bodies, b)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return kinds, bodies
}

func blobData(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// TestPublishBlob: a published blob is announced in the member's log and
// reads back from the store by its announcement.
func TestPublishBlob(t *testing.T) {
	x := newGroup(t)
	n := x.join(t, host(t, network(t, 5)), x.m1, x.r)
	data := blobData(t, 3*content.DefaultPieceSize+17)
	id, queued, err := n.PublishBlob(context.Background(), bytes.NewReader(data), []byte("meta"))
	if err != nil || queued {
		t.Fatalf("publish: queued %v, %v", queued, err)
	}
	kinds, bodies := entries(t, n, x.m1)
	if len(kinds) != 1 || kinds[0] != memberlog.Blob {
		t.Fatalf("log kinds %v", kinds)
	}
	a, err := content.DecodeAnnouncement(bodies[0])
	if err != nil || a.ID != id || string(a.Meta) != "meta" {
		t.Fatalf("announcement: %v", err)
	}
	var got bytes.Buffer
	if err := content.Read(n.cfg.Store, a, &got); err != nil || !bytes.Equal(got.Bytes(), data) {
		t.Fatalf("read back: %v", err)
	}
}

// TestPublishBlobPaused: while paused, a blob's announcement is held in
// order with posts, and appended with them after the corrective rekey;
// TakeHeld would hand it over with its kind.
func TestPublishBlobPaused(t *testing.T) {
	x := newGroup(t)
	x.admins(t)
	if err := x.expose(x.r); err != nil {
		t.Fatal(err)
	}
	f, err := x.r.Fold()
	if err != nil {
		t.Fatal(err)
	}
	x.g = x.r.Keyring(x.owner).Secrets[f.Current]
	n := x.join(t, host(t, network(t, 5)), x.m1, x.r)
	ctx := context.Background()
	if _, err := n.Post(ctx, []byte("before")); err != nil {
		t.Fatal(err)
	}
	id, queued, err := n.PublishBlob(ctx, bytes.NewReader(blobData(t, 100)), nil)
	if err != nil || !queued {
		t.Fatalf("a paused publish: queued %v, %v", queued, err)
	}
	if _, err := n.Post(ctx, []byte("after")); err != nil {
		t.Fatal(err)
	}
	n.mu.Lock()
	var held []memberlog.Kind
	for _, p := range n.queue {
		held = append(held, p.kind)
	}
	n.mu.Unlock()
	if len(held) != 3 || held[1] != memberlog.Blob {
		t.Fatalf("held kinds %v", held)
	}
	if err := n.Do(ctx, func(r *roster.Roster, _ *memberlog.Set) error {
		_, err := (&roster.Writer{R: r, Me: x.owner}).Rekey()
		return err
	}); err != nil {
		t.Fatal(err)
	}
	kinds, bodies := entries(t, n, x.m1)
	if len(kinds) != 3 || kinds[0] != memberlog.App || kinds[1] != memberlog.Blob || kinds[2] != memberlog.App {
		t.Fatalf("log kinds after the rekey %v", kinds)
	}
	if a, err := content.DecodeAnnouncement(bodies[1]); err != nil || a.ID != id {
		t.Fatalf("the flushed announcement: %v", err)
	}
}

// TestPublishBlobRefused: a refused announcement deletes the blob's
// pieces; without a store, or with meta over content.MaxMeta, nothing is
// sealed.
func TestPublishBlobRefused(t *testing.T) {
	x := newGroup(t)
	mirror := me(7)
	if _, err := (&roster.Writer{R: x.r, Me: x.owner}).Add(mirror.Public(), "mirror", roster.Mirror, keys.PublicKey{}); err != nil {
		t.Fatal(err)
	}
	seed := network(t, 6)
	mn := x.join(t, host(t, seed), mirror, x.r)
	store := newRecordingStore()
	mn.cfg.Store = store
	if _, _, err := mn.PublishBlob(context.Background(), bytes.NewReader(blobData(t, 100)), nil); !errors.Is(err, roster.ErrNotAllowed) {
		t.Fatalf("a mirror's publish: %v", err)
	}
	if store.held() != 0 {
		t.Fatal("a refused blob's pieces were kept")
	}
	n := x.join(t, host(t, seed), x.m1, x.r)
	n.cfg.Store = store
	if _, _, err := n.PublishBlob(context.Background(), bytes.NewReader(nil), make([]byte, content.MaxMeta+1)); err == nil {
		t.Fatal("meta over MaxMeta")
	}
	store.mu.Lock()
	created := store.created
	store.mu.Unlock()
	if created != 1 { // the mirror's
		t.Fatal("a blob sealed for meta that can't be announced")
	}
	n.cfg.Store = nil
	if _, _, err := n.PublishBlob(context.Background(), bytes.NewReader(nil), nil); !errors.Is(err, ErrNoStore) {
		t.Fatalf("without a store: %v", err)
	}
}

// deleteFails is a store that can't delete.
type deleteFails struct{ *content.MemStore }

func (deleteFails) Delete(content.ID) error { return errors.New("delete failed") }

// TestPublishBlobDeleteError: a refused blob the store can't delete comes
// back named, with both errors.
func TestPublishBlobDeleteError(t *testing.T) {
	x := newGroup(t)
	mirror := me(7)
	if _, err := (&roster.Writer{R: x.r, Me: x.owner}).Add(mirror.Public(), "mirror", roster.Mirror, keys.PublicKey{}); err != nil {
		t.Fatal(err)
	}
	mn := x.join(t, host(t, network(t, 5)), mirror, x.r)
	mn.cfg.Store = deleteFails{content.NewMemStore()}
	id, _, err := mn.PublishBlob(context.Background(), bytes.NewReader(blobData(t, 100)), nil)
	if !errors.Is(err, roster.ErrNotAllowed) || !strings.Contains(err.Error(), "delete failed") || id == (content.ID{}) {
		t.Fatalf("a refused blob that can't be deleted: id %x, %v", id, err)
	}
}
