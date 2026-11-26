package directory

import (
	"context"
	"errors"
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
	d := &Directory{Group: g, Shards: 3, Store: r}
	a, b := member(1), member(2)
	if err := d.Write(context.Background(), p, []Entry{{Key: rendezvous(a, p), Seen: now}, {Key: rendezvous(b, p), Seen: now.Add(-time.Hour)}}); err != nil {
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
	d := &Directory{Group: g, Shards: 1, Store: r}
	a, stranger := member(1), member(9)
	d.Write(context.Background(), p, []Entry{
		{Key: rendezvous(a, p+1), Seen: now},
		{Key: rendezvous(stranger, p), Seen: now},
	})
	got, _ := d.Read(context.Background(), p, []keys.PublicKey{a.Public()})
	if len(got) != 0 {
		t.Fatalf("read %d entries; none is a member's for this period", len(got))
	}
}

// TestConcurrentWritersBothRead: two writers putting one shard at once,
// each winning on some replicas, are both read.
func TestConcurrentWritersBothRead(t *testing.T) {
	r := newReplicas(4)
	d := &Directory{Group: g, Shards: 1, Store: r}
	a, b := member(1), member(2)
	r.puts = func() []int { return []int{0, 1} }
	d.Write(context.Background(), p, []Entry{{Key: rendezvous(a, p), Seen: now}})
	// b read before a's put landed: its put is at the same sequence number.
	r.held[2], r.held[3] = map[string]dht.MutableItem{}, map[string]dht.MutableItem{}
	r.puts = func() []int { return []int{2, 3} }
	bOnly := &replicas{n: 4, held: []map[string]dht.MutableItem{{}, {}, r.held[2], r.held[3]}, puts: r.puts}
	(&Directory{Group: g, Shards: 1, Store: bOnly}).Write(context.Background(), p, []Entry{{Key: rendezvous(b, p), Seen: now}})
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
	d := &Directory{Group: g, Shards: 1, Store: r}
	a, b := member(1), member(2)
	r.after = func() {
		// b, unaware of a's entry, writes a higher sequence number.
		v, _ := Seal(g, p, 0, []Entry{{Key: rendezvous(b, p), Seen: now}})
		m, _ := dht.NewMutable(g.DirectoryKey(p), g.DirectorySalt(p, 0), 100, v)
		for _, h := range r.held {
			h[target(m.Key, m.Salt)] = m
		}
	}
	if err := d.Write(context.Background(), p, []Entry{{Key: rendezvous(a, p), Seen: now}}); err != nil {
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
