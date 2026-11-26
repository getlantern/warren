// Package directory is a group's liveness directory (docs/groups-design.md,
// *Discovery*): a hint of which members are online, so a member coming
// back after a long absence spends its signaling on members likely to
// answer. Each period it is one BEP 44 mutable item per shard, signed by
// the period's directory key (every holder of G derives it) under a salt
// only holders of G can compute, its value sealed so only they can read it:
// entries of a member's rendezvous key and when it was last seen.
//
// A BEP 44 compare-and-swap isn't atomic across the nodes storing an item,
// so two members writing a shard at once can each win on some replicas: a
// reader merges every distinct value it finds, and a writer reads back
// after its put and merges again if its entries are missing.
package directory

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"slices"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/getlantern/warren/bencode"
	"github.com/getlantern/warren/dht"
	"github.com/getlantern/warren/group/keys"
)

const (
	entrySize = 32 + 4 // a rendezvous key and a last-seen time, in seconds
	// sealOverhead is the nonce and tag around the entries, and the
	// bencoded string's length prefix.
	sealOverhead = chacha20poly1305.NonceSizeX + chacha20poly1305.Overhead + 5
	// MaxEntries is the entries one shard holds within BEP 44's value
	// limit; when a shard is full its oldest entries are dropped.
	MaxEntries = (dht.MaxValueSize - sealOverhead) / entrySize
	// writeTries bounds a writer's read-merge-put rounds when concurrent
	// writers keep displacing its entries.
	writeTries = 3
)

// ErrMalformed means a shard's value isn't a sealed list of entries.
var ErrMalformed = errors.New("directory: malformed shard")

// Entry is one member's liveness: its rendezvous key for the period and
// when it was last seen.
type Entry struct {
	Key  keys.PublicKey
	Seen time.Time
}

// Store is where shards live: a warren DHT driver (driver.Node) is one.
type Store interface {
	GetMutableAll(ctx context.Context, key [32]byte, salt []byte) ([]dht.MutableItem, error)
	PutMutable(ctx context.Context, m dht.MutableItem, cas *int64) (dht.PutDone, error)
}

// ShardOf is the shard of shards a rendezvous key's entry goes in.
func ShardOf(rendezvous keys.PublicKey, shards uint32) uint32 {
	if shards == 0 {
		return 0
	}
	h := sha256.Sum256(append([]byte("warren/group/v1 directory shard "), rendezvous[:]...))
	return binary.BigEndian.Uint32(h[:4]) % shards
}

// slot is what a sealing authenticates besides its entries, so a shard
// can't be replayed into another period or shard.
func slot(p uint64, shard uint32) []byte {
	b := binary.BigEndian.AppendUint64([]byte("warren/group/v1 directory "), p)
	return binary.BigEndian.AppendUint32(b, shard)
}

// Seal encodes and seals entries for shard in period p, as a BEP 44
// value: at most MaxEntries, the newest kept.
func Seal(g keys.Secret, p uint64, shard uint32, entries []Entry) ([]byte, error) {
	entries = newest(entries)
	pt := make([]byte, 0, len(entries)*entrySize)
	for _, e := range entries {
		pt = append(pt, e.Key[:]...)
		pt = binary.BigEndian.AppendUint32(pt, uint32(e.Seen.Unix()))
	}
	k := g.DirSeal()
	aead, err := chacha20poly1305.NewX(k[:])
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return bencode.AppendBytes(nil, aead.Seal(nonce, nonce, pt, slot(p, shard))), nil
}

// Open is Seal's inverse.
func Open(g keys.Secret, p uint64, shard uint32, v []byte) ([]Entry, error) {
	b, err := bencode.Decode(v)
	if err != nil || b.Kind != bencode.String || len(b.Str) < chacha20poly1305.NonceSizeX {
		return nil, ErrMalformed
	}
	k := g.DirSeal()
	aead, err := chacha20poly1305.NewX(k[:])
	if err != nil {
		return nil, err
	}
	n := chacha20poly1305.NonceSizeX
	pt, err := aead.Open(nil, b.Str[:n], b.Str[n:], slot(p, shard))
	if err != nil || len(pt)%entrySize != 0 || len(pt)/entrySize > MaxEntries {
		return nil, ErrMalformed
	}
	var out []Entry
	for i := 0; i < len(pt); i += entrySize {
		out = append(out, Entry{Key: keys.PublicKey(pt[i : i+32]), Seen: time.Unix(int64(binary.BigEndian.Uint32(pt[i+32:i+entrySize])), 0)})
	}
	return out, nil
}

// merge is the union of entries, one per key with its latest sighting.
func merge(lists ...[]Entry) []Entry {
	latest := map[keys.PublicKey]time.Time{}
	for _, l := range lists {
		for _, e := range l {
			if t, ok := latest[e.Key]; !ok || e.Seen.After(t) {
				latest[e.Key] = e.Seen
			}
		}
	}
	out := make([]Entry, 0, len(latest))
	for k, t := range latest {
		out = append(out, Entry{Key: k, Seen: t})
	}
	return out
}

// newest is entries, latest first, at most MaxEntries: a full shard drops
// its oldest.
func newest(entries []Entry) []Entry {
	entries = slices.Clone(entries)
	slices.SortFunc(entries, func(a, b Entry) int {
		if c := b.Seen.Compare(a.Seen); c != 0 {
			return c
		}
		return slices.Compare(a.Key[:], b.Key[:])
	})
	return entries[:min(len(entries), MaxEntries)]
}

// Directory reads and writes a group's directory.
type Directory struct {
	Group  keys.Secret
	Shards uint32 // from the group's genesis
	Store  Store
}

// readShard returns every entry any replica of shard holds in period p,
// merged, and the highest sequence number seen. Values that don't open
// (not sealed by a holder of G for this slot) are skipped.
func (d *Directory) readShard(ctx context.Context, p uint64, shard uint32) ([]Entry, int64, error) {
	key := d.Group.DirectoryKey(p)
	items, err := d.Store.GetMutableAll(ctx, [32]byte(key.Public().(ed25519.PublicKey)), d.Group.DirectorySalt(p, shard))
	var lists [][]Entry
	var seq int64
	for _, it := range items {
		seq = max(seq, it.Seq)
		if es, oerr := Open(d.Group, p, shard, it.V); oerr == nil {
			lists = append(lists, es)
		}
	}
	return merge(lists...), seq, err
}

// Read returns when each member was last seen in period p, as far as the
// directory says: entries whose key is a member's rendezvous key for p,
// so a holder of G can't list a stranger. A shard that couldn't be read
// is skipped, and its error returned with whatever the rest gave.
func (d *Directory) Read(ctx context.Context, p uint64, members []keys.PublicKey) (map[keys.PublicKey]time.Time, error) {
	byRendezvous := map[keys.PublicKey]keys.PublicKey{}
	for _, m := range members {
		if r, err := keys.Rendezvous(d.Group, p, m); err == nil {
			byRendezvous[r] = m
		}
	}
	out := map[keys.PublicKey]time.Time{}
	var errs []error
	for shard := range max(d.Shards, 1) {
		es, _, err := d.readShard(ctx, p, shard)
		if err != nil {
			errs = append(errs, err)
		}
		for _, e := range es {
			if m, ok := byRendezvous[e.Key]; ok && e.Seen.After(out[m]) {
				out[m] = e.Seen
			}
		}
	}
	return out, errors.Join(errs...)
}

// Write publishes entries (a writer's own, and those of members it's in
// session with) for period p: each shard's current entries are read,
// merged with the new ones, sealed and put, then read back; if a
// concurrent writer displaced any of them, the shard is merged and put
// again, up to writeTries rounds.
func (d *Directory) Write(ctx context.Context, p uint64, entries []Entry) error {
	byShard := map[uint32][]Entry{}
	for _, e := range entries {
		s := ShardOf(e.Key, max(d.Shards, 1))
		byShard[s] = append(byShard[s], e)
	}
	var errs []error
	for _, shard := range sortedShards(byShard) {
		if err := d.writeShard(ctx, p, shard, byShard[shard]); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (d *Directory) writeShard(ctx context.Context, p uint64, shard uint32, mine []Entry) error {
	key := d.Group.DirectoryKey(p)
	salt := d.Group.DirectorySalt(p, shard)
	for range writeTries {
		cur, seq, err := d.readShard(ctx, p, shard)
		if err != nil && len(cur) == 0 && seq == 0 {
			return err
		}
		v, err := Seal(d.Group, p, shard, merge(cur, mine))
		if err != nil {
			return err
		}
		m, err := dht.NewMutable(key, salt, seq+1, v)
		if err != nil {
			return err
		}
		if _, err := d.Store.PutMutable(ctx, m, nil); err != nil {
			return err
		}
		back, _, err := d.readShard(ctx, p, shard)
		if err != nil {
			return err
		}
		if present(back, mine) {
			return nil
		}
	}
	return errors.New("directory: concurrent writers kept displacing this shard's entries")
}

// present reports whether every one of mine is in got, at least as recent
// (or displaced only because the shard is full of newer entries).
func present(got, mine []Entry) bool {
	at := map[keys.PublicKey]time.Time{}
	for _, e := range got {
		at[e.Key] = e.Seen
	}
	var oldest time.Time
	if len(got) >= MaxEntries {
		oldest = newest(got)[len(got)-1].Seen
	}
	for _, e := range mine {
		if t, ok := at[e.Key]; !ok || t.Before(e.Seen) {
			if len(got) < MaxEntries || !e.Seen.Before(oldest) {
				return false
			}
		}
	}
	return true
}

func sortedShards(m map[uint32][]Entry) []uint32 {
	out := make([]uint32, 0, len(m))
	for s := range m {
		out = append(out, s)
	}
	slices.Sort(out)
	return out
}
