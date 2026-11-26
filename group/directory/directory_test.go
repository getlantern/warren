package directory

import (
	"context"
	"errors"
	"math"
	"slices"
	"testing"
	"time"

	"github.com/getlantern/warren/dht"
	"github.com/getlantern/warren/driver"
	"github.com/getlantern/warren/group/keys"
)

var (
	now = time.Unix(1_800_000_000, 0)
	p   = keys.PeriodOf(now)
	g   = keys.Secret{7}
)

// The warren DHT driver is a Store.
var _ Store = (*driver.Node)(nil)

func clock() time.Time { return now }

func members(ids ...*keys.Identity) []keys.PublicKey {
	var out []keys.PublicKey
	for _, id := range ids {
		out = append(out, id.Public())
	}
	return out
}

func member(b byte) *keys.Identity { return keys.IdentityFromSeed([32]byte{b}) }

func rendezvous(m *keys.Identity, period uint64) keys.PublicKey {
	return m.Rendezvous(g, period).Public()
}

// replicas is a fake DHT: n replicas each holding at most one item per
// target, taking a put only for a higher sequence number (BEP 44), and a
// put landing on the replicas puts chooses (all, by default): a non-atomic
// compare-and-swap.
type replicas struct {
	n     int
	held  []map[string]dht.MutableItem
	puts  func() []int
	after func() // runs after each put: a concurrent writer
}

func newReplicas(n int) *replicas {
	r := &replicas{n: n}
	for range n {
		r.held = append(r.held, map[string]dht.MutableItem{})
	}
	return r
}

func target(key [32]byte, salt []byte) string { return string(key[:]) + string(salt) }

func (r *replicas) GetMutableAll(_ context.Context, key [32]byte, salt []byte) ([]dht.MutableItem, error) {
	var out []dht.MutableItem
	for _, h := range r.held {
		if it, ok := h[target(key, salt)]; ok && !slices.ContainsFunc(out, func(x dht.MutableItem) bool { return x.Sig == it.Sig }) {
			out = append(out, it)
		}
	}
	dht.SortItems(out)
	return out, nil
}

func (r *replicas) PutMutable(_ context.Context, m dht.MutableItem, _ *int64) (dht.PutDone, error) {
	if !m.Verify() {
		return dht.PutDone{}, errors.New("bad item")
	}
	idx := make([]int, r.n)
	for i := range idx {
		idx[i] = i
	}
	if r.puts != nil {
		idx = r.puts()
	}
	t := target(m.Key, m.Salt)
	for _, i := range idx {
		if cur, ok := r.held[i][t]; !ok || m.Seq > cur.Seq {
			r.held[i][t] = m
		}
	}
	if f := r.after; f != nil {
		r.after = nil
		f()
	}
	return dht.PutDone{Stored: len(idx)}, nil
}

func TestSealRoundTrip(t *testing.T) {
	es := []Entry{{Key: keys.PublicKey{1}, Seen: now}, {Key: keys.PublicKey{2}, Seen: now.Add(-time.Minute)}}
	v, err := Seal(g, p, 3, es)
	if err != nil {
		t.Fatal(err)
	}
	if len(v) > dht.MaxValueSize {
		t.Fatalf("%d-byte value", len(v))
	}
	got, err := Open(g, p, 3, v)
	if err != nil || len(got) != 2 || got[0] != es[0] || got[1] != es[1] {
		t.Fatalf("round trip: %v %+v", err, got)
	}
	for name, open := range map[string]func() error{
		"another shard":  func() error { _, err := Open(g, p, 4, v); return err },
		"another period": func() error { _, err := Open(g, p+1, 3, v); return err },
		"another group":  func() error { _, err := Open(keys.Secret{8}, p, 3, v); return err },
	} {
		if !errors.Is(open(), ErrMalformed) {
			t.Fatalf("opened under %s", name)
		}
	}
}

// TestShardHoldsMaxEntries: a full shard fits BEP 44's value limit, and
// past it the oldest entries go.
func TestShardHoldsMaxEntries(t *testing.T) {
	if MaxEntries < 25 {
		t.Fatalf("a shard holds only %d entries", MaxEntries)
	}
	var es []Entry
	for i := range MaxEntries + 5 {
		es = append(es, Entry{Key: keys.PublicKey{byte(i), 1}, Seen: now.Add(time.Duration(i) * time.Second)})
	}
	v, err := Seal(g, p, 0, es)
	if err != nil {
		t.Fatal(err)
	}
	if len(v) > dht.MaxValueSize {
		t.Fatalf("a full shard is %d bytes", len(v))
	}
	got, _ := Open(g, p, 0, v)
	if len(got) != MaxEntries || got[len(got)-1].Seen != es[5].Seen {
		t.Fatalf("kept %d, oldest %v; want the newest %d", len(got), got[len(got)-1].Seen, MaxEntries)
	}
}

func TestWriteThenRead(t *testing.T) {
	r := newReplicas(4)
	d := &Directory{Group: g, Shards: 3, Store: r, Now: clock}
	a, b := member(1), member(2)
	if err := d.Write(context.Background(), p, []keys.PublicKey{a.Public(), b.Public()}, []Entry{{Key: rendezvous(a, p), Seen: now}, {Key: rendezvous(b, p), Seen: now.Add(-time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	got, err := d.Read(context.Background(), p, []keys.PublicKey{a.Public(), b.Public()})
	if err != nil || !got[a.Public()].Equal(now) || !got[b.Public()].Equal(now.Add(-time.Hour)) {
		t.Fatalf("read back %v %v", err, got)
	}
}

// TestReadKeepsOnlyMembers: an entry whose key isn't a member's rendezvous
// key for the period (a stranger's, or a member's for another period) is
// left out.
func TestReadKeepsOnlyMembers(t *testing.T) {
	r := newReplicas(2)
	d := &Directory{Group: g, Shards: 1, Store: r, Now: clock}
	a, stranger := member(1), member(9)
	// Planted directly, as a holder of G could: a member's key for another
	// period, and a stranger's.
	v, _ := Seal(g, p, 0, []Entry{{Key: rendezvous(a, p+1), Seen: now}, {Key: rendezvous(stranger, p), Seen: now}})
	m, _ := dht.NewMutable(g.DirectoryKey(p), g.DirectorySalt(p, 0), 1, v)
	r.PutMutable(context.Background(), m, nil)
	got, _ := d.Read(context.Background(), p, []keys.PublicKey{a.Public()})
	if len(got) != 0 {
		t.Fatalf("read %d entries; none is a member's for this period", len(got))
	}
}

// TestConcurrentWritersBothRead: two writers putting one shard at once,
// each winning on some replicas, are both read.
func TestConcurrentWritersBothRead(t *testing.T) {
	r := newReplicas(4)
	d := &Directory{Group: g, Shards: 1, Store: r, Now: clock}
	a, b := member(1), member(2)
	r.puts = func() []int { return []int{0, 1} }
	d.Write(context.Background(), p, members(a, b), []Entry{{Key: rendezvous(a, p), Seen: now}})
	// b read before a's put landed: its put is at the same sequence number.
	r.held[2], r.held[3] = map[string]dht.MutableItem{}, map[string]dht.MutableItem{}
	r.puts = func() []int { return []int{2, 3} }
	bOnly := &replicas{n: 4, held: []map[string]dht.MutableItem{{}, {}, r.held[2], r.held[3]}, puts: r.puts}
	(&Directory{Group: g, Shards: 1, Store: bOnly, Now: clock}).Write(context.Background(), p, members(a, b), []Entry{{Key: rendezvous(b, p), Seen: now}})
	got, _ := d.Read(context.Background(), p, []keys.PublicKey{a.Public(), b.Public()})
	if len(got) != 2 {
		t.Fatalf("read %d of 2 concurrent writers' entries", len(got))
	}
}

// TestWriterMergesAgain: a concurrent writer replacing the shard right
// after this writer's put, without its entry, makes it merge and put
// again.
func TestWriterMergesAgain(t *testing.T) {
	r := newReplicas(3)
	d := &Directory{Group: g, Shards: 1, Store: r, Now: clock}
	a, b := member(1), member(2)
	r.after = func() {
		// b, unaware of a's entry, writes a higher sequence number.
		v, _ := Seal(g, p, 0, []Entry{{Key: rendezvous(b, p), Seen: now}})
		m, _ := dht.NewMutable(g.DirectoryKey(p), g.DirectorySalt(p, 0), 100, v)
		for _, h := range r.held {
			h[target(m.Key, m.Salt)] = m
		}
	}
	if err := d.Write(context.Background(), p, members(a, b), []Entry{{Key: rendezvous(a, p), Seen: now}}); err != nil {
		t.Fatal(err)
	}
	got, _ := d.Read(context.Background(), p, []keys.PublicKey{a.Public(), b.Public()})
	if len(got) != 2 {
		t.Fatalf("read %d entries; the writer should have merged b's and put its own again", len(got))
	}
}

func TestShardOfSpreads(t *testing.T) {
	seen := map[uint32]bool{}
	for i := range 64 {
		seen[ShardOf(rendezvous(member(byte(i+1)), p), 3)] = true
	}
	if len(seen) != 3 {
		t.Fatalf("64 members landed in %d of 3 shards", len(seen))
	}
}

// TestSubsecondTimesWriteOnce: a last-seen time with nanoseconds (any
// time.Now) is stored at whole seconds, and the read-back accepts it
// without putting again.
func TestSubsecondTimesWriteOnce(t *testing.T) {
	r := newReplicas(2)
	puts := 0
	r.puts = func() []int { puts++; return []int{0, 1} }
	d := &Directory{Group: g, Shards: 1, Store: r, Now: clock}
	a := member(1)
	if err := d.Write(context.Background(), p, members(a), []Entry{{Key: rendezvous(a, p), Seen: now.Add(123456789)}}); err != nil {
		t.Fatal(err)
	}
	if puts != 1 {
		t.Fatalf("%d puts for one uncontested write", puts)
	}
}

// fullShard is a shard of MaxEntries members' entries.
func fullShard(first byte) ([]*keys.Identity, []Entry) {
	var ids []*keys.Identity
	var es []Entry
	for i := range MaxEntries {
		id := member(first + byte(i))
		ids = append(ids, id)
		es = append(es, Entry{Key: rendezvous(id, p), Seen: now.Add(-time.Duration(i) * time.Second)})
	}
	return ids, es
}

// TestOversizedUnionNoPanic: replicas holding different full shards make
// a read-back union larger than a shard; the write still completes.
func TestOversizedUnionNoPanic(t *testing.T) {
	r := newReplicas(4)
	idsA, esA := fullShard(10)
	idsB, esB := fullShard(100)
	for i, es := range [][]Entry{esA, esB} {
		v, _ := Seal(g, p, 0, es)
		m, _ := dht.NewMutable(g.DirectoryKey(p), g.DirectorySalt(p, 0), 5, v)
		for _, j := range []int{2 * i, 2*i + 1} {
			r.held[j][target(m.Key, m.Salt)] = m
		}
	}
	r.puts = func() []int { return []int{0} } // a put that reaches one replica
	d := &Directory{Group: g, Shards: 1, Store: r, Now: clock}
	w := member(250)
	all := append(append(members(idsA...), members(idsB...)...), w.Public())
	if err := d.Write(context.Background(), p, all, []Entry{{Key: rendezvous(w, p), Seen: now}}); err != nil && !errors.Is(err, errDisplaced) {
		t.Fatal(err)
	}
}

// TestPoisonedShardRepaired: a holder of G filling a shard with
// strangers' far-future entries doesn't keep an honest member out: the
// writer drops what isn't a member's, and its own entry is read.
func TestPoisonedShardRepaired(t *testing.T) {
	r := newReplicas(2)
	var junk []Entry
	for i := range MaxEntries {
		junk = append(junk, Entry{Key: rendezvous(member(byte(200+i)), p), Seen: now.Add(1000 * time.Hour)})
	}
	v, _ := Seal(g, p, 0, junk)
	m, _ := dht.NewMutable(g.DirectoryKey(p), g.DirectorySalt(p, 0), 1, v)
	r.PutMutable(context.Background(), m, nil)
	d := &Directory{Group: g, Shards: 1, Store: r, Now: clock}
	a := member(1)
	if err := d.Write(context.Background(), p, members(a), []Entry{{Key: rendezvous(a, p), Seen: now}}); err != nil {
		t.Fatal(err)
	}
	got, _ := d.Read(context.Background(), p, members(a))
	if !got[a.Public()].Equal(now) {
		t.Fatal("a member's entry didn't survive a poisoned shard")
	}
}

// TestFutureTimesIgnored: a member's entry dated past the clock (beyond
// maxSkew) isn't read.
func TestFutureTimesIgnored(t *testing.T) {
	r := newReplicas(1)
	a := member(1)
	v, _ := Seal(g, p, 0, []Entry{{Key: rendezvous(a, p), Seen: now.Add(time.Hour)}})
	m, _ := dht.NewMutable(g.DirectoryKey(p), g.DirectorySalt(p, 0), 1, v)
	r.PutMutable(context.Background(), m, nil)
	got, _ := (&Directory{Group: g, Shards: 1, Store: r, Now: clock}).Read(context.Background(), p, members(a))
	if len(got) != 0 {
		t.Fatal("an entry an hour in the future was read")
	}
}

// TestPinnedShard: a shard at the highest sequence number can't be
// replaced; the writer says so rather than wrap around.
func TestPinnedShard(t *testing.T) {
	r := newReplicas(1)
	v, _ := Seal(g, p, 0, nil)
	m, _ := dht.NewMutable(g.DirectoryKey(p), g.DirectorySalt(p, 0), math.MaxInt64, v)
	r.PutMutable(context.Background(), m, nil)
	a := member(1)
	err := (&Directory{Group: g, Shards: 1, Store: r, Now: clock}).Write(context.Background(), p, members(a), []Entry{{Key: rendezvous(a, p), Seen: now}})
	if !errors.Is(err, ErrPinned) {
		t.Fatalf("writing a pinned shard: %v", err)
	}
}

// TestPlantedFutureDoesntHideValid: a member's valid sighting on one
// replica survives a planted future one for the same key on another.
func TestPlantedFutureDoesntHideValid(t *testing.T) {
	r := newReplicas(2)
	a := member(1)
	for i, seen := range []time.Time{now, now.Add(time.Hour)} {
		v, _ := Seal(g, p, 0, []Entry{{Key: rendezvous(a, p), Seen: seen}})
		m, _ := dht.NewMutable(g.DirectoryKey(p), g.DirectorySalt(p, 0), 1, v)
		r.held[i][target(m.Key, m.Salt)] = m
	}
	got, _ := (&Directory{Group: g, Shards: 1, Store: r, Now: clock}).Read(context.Background(), p, members(a))
	if !got[a.Public()].Equal(now) {
		t.Fatal("a planted future sighting hid a valid one")
	}
}

// TestOverflowAtOneSecondWritesOnce: more entries than a shard holds, all
// at one second, are evicted by key as Seal does, and the write doesn't
// mistake that for a concurrent writer.
func TestOverflowAtOneSecondWritesOnce(t *testing.T) {
	r := newReplicas(1)
	puts := 0
	r.puts = func() []int { puts++; return []int{0} }
	d := &Directory{Group: g, Shards: 1, Store: r, Now: clock}
	var ids []*keys.Identity
	var es []Entry
	for i := range MaxEntries + 4 {
		id := member(byte(i + 1))
		ids = append(ids, id)
		es = append(es, Entry{Key: rendezvous(id, p), Seen: now})
	}
	if err := d.Write(context.Background(), p, members(ids...), es); err != nil {
		t.Fatal(err)
	}
	if puts != 1 {
		t.Fatalf("%d puts for one uncontested write", puts)
	}
}
