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
	"math"
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

var (
	// ErrMalformed means a shard's value isn't a sealed list of entries.
	ErrMalformed = errors.New("directory: malformed shard")
	// ErrTime means a last-seen time outside what a shard can hold: from
	// the Unix epoch to 2106, in whole seconds.
	ErrTime = errors.New("directory: last-seen time out of range")
	// ErrPinned means a shard's sequence number is at its maximum (a
	// holder of G signed one there), so no newer value can replace it
	// this period; the next period's directory key gives a fresh slot.
	ErrPinned = errors.New("directory: shard pinned at the highest sequence number")
)

// errDisplaced means concurrent writers kept displacing a writer's
// entries for every round it tried.
var errDisplaced = errors.New("directory: concurrent writers kept displacing this shard's entries")

// maxSkew is how far past a reader's or writer's clock a last-seen time
// may be, so a holder of G can't fill a shard with far-future entries
// that outlast every honest one.
const maxSkew = 5 * time.Minute

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
	for _, e := range entries {
		if !inRange(e.Seen) {
			return nil, ErrTime
		}
	}
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

// inRange reports whether t fits a shard's 4-byte time: after the epoch
// (an unset time.Time isn't) and before 2106.
func inRange(t time.Time) bool {
	u := t.Unix()
	return u > 0 && u <= math.MaxUint32
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
	// Now is the clock last-seen times are checked against; nil means
	// time.Now.
	Now func() time.Time
}

func (d *Directory) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// valid is entries whose key is a member's rendezvous key for period p
// (byRendezvous) and whose last-seen time isn't past the clock by more
// than maxSkew, at the wire's precision (whole seconds). Both paths
// apply it: a reader so a holder of G can't list strangers, a writer so
// it doesn't keep and republish what a holder of G planted.
//
// For shard (shard >= 0) it also keeps only entries that belong there, so
// a holder of G can't fill one shard with members from the others,
// evicting the members assigned to it.
func (d *Directory) valid(entries []Entry, byRendezvous map[keys.PublicKey]keys.PublicKey, shard int64) []Entry {
	limit := d.now().Add(maxSkew)
	var out []Entry
	for _, e := range entries {
		e.Seen = time.Unix(e.Seen.Unix(), 0)
		if _, ok := byRendezvous[e.Key]; !ok || e.Seen.After(limit) || !inRange(e.Seen) {
			continue
		}
		if shard >= 0 && int64(ShardOf(e.Key, max(d.Shards, 1))) != shard {
			continue
		}
		out = append(out, e)
	}
	return out
}

// rendezvousOf maps each member's rendezvous key for period p to it.
func (d *Directory) rendezvousOf(p uint64, members []keys.PublicKey) map[keys.PublicKey]keys.PublicKey {
	m := map[keys.PublicKey]keys.PublicKey{}
	for _, k := range members {
		if r, err := keys.Rendezvous(d.Group, p, k); err == nil {
			m[r] = k
		}
	}
	return m
}

// readShard returns every valid entry any replica of shard holds in
// period p, merged, and the highest sequence number seen. Each replica's
// entries are validated before the merge, so a planted entry (a future
// time) can't displace a member's valid sighting from another replica.
// Values that don't open (not sealed by a holder of G for this slot) are
// skipped.
func (d *Directory) readShard(ctx context.Context, p uint64, shard uint32, byRendezvous map[keys.PublicKey]keys.PublicKey) ([]Entry, int64, error) {
	key := d.Group.DirectoryKey(p)
	items, err := d.Store.GetMutableAll(ctx, [32]byte(key.Public().(ed25519.PublicKey)), d.Group.DirectorySalt(p, shard))
	var lists [][]Entry
	var seq int64
	for _, it := range items {
		seq = max(seq, it.Seq)
		if es, oerr := Open(d.Group, p, shard, it.V); oerr == nil {
			lists = append(lists, d.valid(es, byRendezvous, int64(shard)))
		}
	}
	return merge(lists...), seq, err
}

// Read returns when each member was last seen in period p, as far as the
// directory says: entries whose key is a member's rendezvous key for p,
// so a holder of G can't list a stranger. A shard that couldn't be read
// is skipped, and its error returned with whatever the rest gave.
func (d *Directory) Read(ctx context.Context, p uint64, members []keys.PublicKey) (map[keys.PublicKey]time.Time, error) {
	byRendezvous := d.rendezvousOf(p, members)
	out := map[keys.PublicKey]time.Time{}
	var errs []error
	for shard := range max(d.Shards, 1) {
		es, _, err := d.readShard(ctx, p, shard, byRendezvous)
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
// those not valid for members dropped, merged with the new ones, sealed
// and put, then read back; if a concurrent writer displaced any of them,
// the shard is merged and put again, up to writeTries rounds.
func (d *Directory) Write(ctx context.Context, p uint64, members []keys.PublicKey, entries []Entry) error {
	byRendezvous := d.rendezvousOf(p, members)
	byShard := map[uint32][]Entry{}
	for _, e := range d.valid(entries, byRendezvous, -1) { // each goes to its own shard below
		s := ShardOf(e.Key, max(d.Shards, 1))
		byShard[s] = append(byShard[s], e)
	}
	var errs []error
	for _, shard := range sortedShards(byShard) {
		if err := d.writeShard(ctx, p, shard, byShard[shard], byRendezvous); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (d *Directory) writeShard(ctx context.Context, p uint64, shard uint32, mine []Entry, byRendezvous map[keys.PublicKey]keys.PublicKey) error {
	key := d.Group.DirectoryKey(p)
	salt := d.Group.DirectorySalt(p, shard)
	// known is everything read across rounds, and hi the highest sequence
	// number seen (read-backs included): a retry repairs what a
	// concurrent writer dropped, and puts above the newest value seen even
	// when its next read reaches only stale replicas.
	var known []Entry
	var hi int64
	for range writeTries {
		cur, seq, err := d.readShard(ctx, p, shard, byRendezvous)
		if err != nil && len(cur) == 0 && seq == 0 && hi == 0 {
			return err
		}
		if hi = max(hi, seq); hi == math.MaxInt64 {
			return ErrPinned
		}
		known = merge(known, cur)
		v, err := Seal(d.Group, p, shard, merge(known, mine))
		if err != nil {
			return err
		}
		m, err := dht.NewMutable(key, salt, hi+1, v)
		if err != nil {
			return err
		}
		if _, err := d.Store.PutMutable(ctx, m, nil); err != nil {
			return err
		}
		hi = m.Seq // replicas that took this put refuse another value at its number
		back, backSeq, err := d.readShard(ctx, p, shard, byRendezvous)
		if err != nil {
			return err
		}
		known, hi = merge(known, back), max(hi, backSeq)
		if present(back, mine, known) {
			return nil
		}
	}
	return errDisplaced
}

// present reports whether every one of mine is in got, at least as
// recent, unless Seal's own capacity policy (newest first, by time then
// key) would leave it out of a shard holding everything known (read so
// far, got included) and mine: a displaced entry means a concurrent
// writer, an evicted one doesn't, even when a stale read-back shows less.
func present(got, mine, known []Entry) bool {
	at := map[keys.PublicKey]time.Time{}
	for _, e := range got {
		at[e.Key] = e.Seen
	}
	kept := map[keys.PublicKey]bool{}
	for _, e := range newest(merge(known, got, mine)) {
		kept[e.Key] = true
	}
	for _, e := range mine {
		if t, ok := at[e.Key]; (!ok || t.Before(e.Seen)) && kept[e.Key] {
			return false
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
