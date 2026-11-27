package join

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/getlantern/warren/group/keys"
	"github.com/getlantern/warren/group/roster"
)

var now = time.Unix(1_800_000_000, 0)

func clock() time.Time { return now }

func me(b byte) *keys.Identity { return keys.IdentityFromSeed([32]byte{b}) }

type fixture struct {
	r                    *roster.Roster
	owner, admin, member *keys.Identity
	issued               *Issued
}

// group is a roster with an owner, an admin and a member, and an invite the
// admin issued with uses.
func group(t *testing.T, uses uint32) *fixture {
	t.Helper()
	x := &fixture{owner: me(1), admin: me(2), member: me(3)}
	r, err := roster.Found(x.owner, "family", 3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&roster.Writer{R: r, Me: x.owner}).Add(x.admin.Public(), "admin", roster.Admin, keys.PublicKey{}); err != nil {
		t.Fatal(err)
	}
	if _, err := (&roster.Writer{R: r, Me: x.admin}).Add(x.member.Public(), "member", roster.Member, keys.PublicKey{}); err != nil {
		t.Fatal(err)
	}
	x.r = r
	x.issued, _, err = Issue(&roster.Writer{R: r, Me: x.admin, Now: clock}, uses, time.Hour,
		[]netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:6881")}, bytes.NewReader(bytes.Repeat([]byte{7}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	return x
}

var secret = []byte("0123456789abcdef0123456789abcdef")

// run has id ask to join (or rejoin) over a pipe, against admin serving x's
// invite; adminCfg and joinCfg adjust the defaults.
func (x *fixture) run(t *testing.T, id *keys.Identity, rejoin bool, adjust func(*AdminConfig, *JoinConfig)) (*roster.Roster, Request, *roster.Op, error, error) {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	ac := AdminConfig{Roster: x.r, Me: x.admin, Invite: x.issued.Invite, Secret: secret, Now: clock}
	jc := JoinConfig{Invite: x.issued.Invite, Me: id, Name: "new", Rejoin: rejoin, Secret: secret}
	if adjust != nil {
		adjust(&ac, &jc)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	type res struct {
		req Request
		op  *roster.Op
		err error
	}
	done := make(chan res, 1)
	go func() {
		req, op, err := Serve(ctx, b, ac)
		if err != nil {
			b.Close()
		}
		done <- res{req, op, err}
	}()
	r, jerr := Join(ctx, a, jc)
	a.Close()
	s := <-done
	return r, s.req, s.op, jerr, s.err
}

func TestJoin(t *testing.T) {
	x := group(t, 1)
	newcomer := me(9)
	r, req, op, jerr, serr := x.run(t, newcomer, false, nil)
	if jerr != nil || serr != nil {
		t.Fatalf("join: %v / %v", jerr, serr)
	}
	if req.Member != newcomer.Public() || req.Name != "new" || req.Rejoin {
		t.Fatalf("the admin saw %+v", req)
	}
	if op == nil || op.Kind != roster.Add || op.Target != newcomer.Public() || op.Invite != x.issued.Invite.Key {
		t.Fatal("the admin didn't write an add naming the invite")
	}
	f, err := r.Fold()
	if err != nil {
		t.Fatal(err)
	}
	if f.Roles[newcomer.Public()] != roster.Member {
		t.Fatal("the joiner's roster doesn't admit it")
	}
	if _, ok := r.Keyring(newcomer).Secrets[f.Current]; !ok {
		t.Fatal("the joiner can't open G")
	}
	if g, _ := x.r.Fold(); g.Invites[x.issued.Invite.Key].Usable(now) {
		t.Fatal("the single-use invite wasn't spent")
	}
}

// TestRejoin: an existing member that missed keys gets a deliver naming the
// invite; one holding every key gets the roster, spending nothing.
func TestRejoin(t *testing.T) {
	x := group(t, 2)
	// The member holds every key: no deliver, nothing spent.
	r, _, op, jerr, serr := x.run(t, x.member, true, nil)
	if jerr != nil || serr != nil {
		t.Fatalf("rejoin: %v / %v", jerr, serr)
	}
	if op != nil {
		t.Fatal("a member holding every key was delivered to")
	}
	if r == nil {
		t.Fatal("no roster")
	}
	if g, _ := x.r.Fold(); g.Invites[x.issued.Invite.Key].Used != 0 {
		t.Fatal("a rejoin with nothing to deliver spent the invite")
	}
	rk := x.missRekey(t)
	r, _, op, jerr, serr = x.run(t, x.member, true, nil)
	if jerr != nil || serr != nil {
		t.Fatalf("rejoin after a missed rekey: %v / %v", jerr, serr)
	}
	if op == nil || op.Kind != roster.Deliver || op.Invite != x.issued.Invite.Key {
		t.Fatal("the admin didn't deliver naming the invite")
	}
	g, _ := r.Fold()
	if _, ok := r.Keyring(x.member).Epochs[rk.ID()]; !ok || g.Current != rk.ID() {
		t.Fatal("the rejoiner didn't get the keys it missed")
	}
}

func TestRefusals(t *testing.T) {
	for name, c := range map[string]struct {
		rejoin bool
		id     func(x *fixture) *keys.Identity
		adjust func(x *fixture) func(*AdminConfig, *JoinConfig)
		want   error
	}{
		"a wrong invite secret": {id: func(*fixture) *keys.Identity { return me(9) },
			adjust: func(*fixture) func(*AdminConfig, *JoinConfig) {
				return func(_ *AdminConfig, j *JoinConfig) { j.Invite.Secret[0] ^= 1 }
			}, want: ErrBadProof},
		"another connection's secret": {id: func(*fixture) *keys.Identity { return me(9) },
			adjust: func(*fixture) func(*AdminConfig, *JoinConfig) {
				return func(_ *AdminConfig, j *JoinConfig) { j.Secret = []byte("another connection") }
			}, want: ErrBadProof},
		"declined": {id: func(*fixture) *keys.Identity { return me(9) },
			adjust: func(*fixture) func(*AdminConfig, *JoinConfig) {
				return func(a *AdminConfig, _ *JoinConfig) { a.Approve = func(Request) bool { return false } }
			}, want: ErrNotApproved},
		"expired": {id: func(*fixture) *keys.Identity { return me(9) },
			adjust: func(*fixture) func(*AdminConfig, *JoinConfig) {
				return func(a *AdminConfig, _ *JoinConfig) { a.Now = func() time.Time { return now.Add(time.Hour) } }
			}, want: ErrInviteUnusable},
		"an unrecorded invite": {id: func(*fixture) *keys.Identity { return me(9) },
			adjust: func(*fixture) func(*AdminConfig, *JoinConfig) {
				return func(a *AdminConfig, j *JoinConfig) {
					a.Invite.Key, j.Invite.Key = me(40).Public(), me(40).Public()
				}
			}, want: ErrInviteUnusable},
		"joining as a member":     {id: func(x *fixture) *keys.Identity { return x.member }, want: ErrAlreadyMember},
		"rejoining as a stranger": {rejoin: true, id: func(*fixture) *keys.Identity { return me(9) }, want: ErrNotMember},
		"served by a member": {id: func(*fixture) *keys.Identity { return me(9) },
			adjust: func(x *fixture) func(*AdminConfig, *JoinConfig) {
				return func(a *AdminConfig, _ *JoinConfig) { a.Me = x.member }
			}, want: ErrNotAdmin},
	} {
		t.Run(name, func(t *testing.T) {
			x := group(t, 1)
			var adj func(*AdminConfig, *JoinConfig)
			if c.adjust != nil {
				adj = c.adjust(x)
			}
			before := len(x.r.IDs())
			_, _, op, jerr, serr := x.run(t, c.id(x), c.rejoin, adj)
			if !errors.Is(jerr, c.want) || !errors.Is(serr, c.want) {
				t.Fatalf("got %v / %v, want %v", jerr, serr, c.want)
			}
			if op != nil || len(x.r.IDs()) != before {
				t.Fatal("a refused request wrote to the roster")
			}
		})
	}
}

// TestSpentAndDead: a spent invite admits no more, and a removal kills it.
func TestSpentAndDead(t *testing.T) {
	x := group(t, 1)
	if _, _, _, jerr, serr := x.run(t, me(9), false, nil); jerr != nil || serr != nil {
		t.Fatalf("first join: %v / %v", jerr, serr)
	}
	if _, _, _, jerr, _ := x.run(t, me(10), false, nil); !errors.Is(jerr, ErrInviteUnusable) {
		t.Fatalf("a spent invite admitted another: %v", jerr)
	}
	y := group(t, 5)
	if _, err := (&roster.Writer{R: y.r, Me: y.owner}).Remove(y.member.Public(), 0, [32]byte{}); err != nil {
		t.Fatal(err)
	}
	if _, _, _, jerr, _ := y.run(t, me(9), false, nil); !errors.Is(jerr, ErrInviteUnusable) {
		t.Fatalf("a dead invite admitted: %v", jerr)
	}
	// The removed member can't rejoin, even with a fresh invite.
	fresh, _, err := Issue(&roster.Writer{R: y.r, Me: y.admin, Now: clock}, 1, time.Hour, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	y.issued = fresh
	if _, _, _, jerr, _ := y.run(t, y.member, true, nil); !errors.Is(jerr, ErrNotMember) {
		t.Fatalf("a removed member rejoined: %v", jerr)
	}
}

// TestProofOfMemberKey: a request signed by a key other than the one it
// names is refused, so no one can get another's key added.
func TestProofOfMemberKey(t *testing.T) {
	x := group(t, 1)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	iv := x.issued.Invite
	victim := me(20)
	req := Request{Member: victim.Public(), Name: "v"}
	go func() {
		_ = writeFrame(a, frameRequest, encodeRequest(req, macOf(iv, secret, req), me(21).Sign(proofOf(iv, secret, req))))
		_, _ = readAnswer(a)
	}()
	_, op, err := Serve(context.Background(), b, AdminConfig{Roster: x.r, Me: x.admin, Invite: iv, Secret: secret, Now: clock})
	if !errors.Is(err, ErrBadProof) || op != nil {
		t.Fatalf("got %v, want ErrBadProof", err)
	}
}

// TestForgedAnswer: an answer whose roster doesn't admit the joiner, or
// doesn't record its invite, is refused.
func TestForgedAnswer(t *testing.T) {
	x := group(t, 1)
	f, _ := x.r.Fold()
	cfg := JoinConfig{Invite: x.issued.Invite, Me: me(9), Secret: secret}
	if _, err := check(cfg, f.Order); !errors.Is(err, ErrBadAnswer) {
		t.Fatalf("a roster without the joiner: %v", err)
	}
	cfg.Me = x.member
	if _, err := check(cfg, f.Order[:3]); !errors.Is(err, ErrBadAnswer) {
		t.Fatalf("a roster without the invite: %v", err)
	}
	if _, err := check(cfg, nil); !errors.Is(err, ErrBadAnswer) {
		t.Fatalf("an empty answer: %v", err)
	}
	if _, err := check(cfg, f.Order); err != nil {
		t.Fatalf("the real roster, for a member: %v", err)
	}
}

func TestLinkRoundTrip(t *testing.T) {
	x := group(t, 1)
	iv := x.issued.Invite
	got, err := ParseLink(iv.Link())
	if err != nil {
		t.Fatal(err)
	}
	if got.Key != iv.Key || got.Secret != iv.Secret || got.Expires != iv.Expires || got.Name != "family" ||
		len(got.Hints) != 1 || got.Hints[0] != iv.Hints[0] {
		t.Fatalf("round trip: %+v", got)
	}
	for _, bad := range []string{"", "warren-invite:1:", "warren-invite:2:" + iv.Link()[16:], iv.Link() + "x", "https://example.com"} {
		if _, err := ParseLink(bad); !errors.Is(err, ErrBadLink) {
			t.Errorf("%q parsed: %v", bad, err)
		}
	}
}

// TestListenerKeysMatch: the key a joiner computes from the link is the
// one the admin listens under, and it changes each period.
func TestListenerKeysMatch(t *testing.T) {
	x := group(t, 1)
	p := keys.PeriodOf(now)
	for _, q := range []uint64{p, p + 1} {
		got, err := x.issued.Invite.Listener(q)
		if err != nil {
			t.Fatal(err)
		}
		if got != x.issued.Listener(q).Public() {
			t.Fatalf("period %d: the joiner's key isn't the admin's", q)
		}
		if got == x.issued.Invite.Key {
			t.Fatal("the listener key is the invite key itself")
		}
	}
	a, _ := x.issued.Invite.Listener(p)
	b, _ := x.issued.Invite.Listener(p + 1)
	if a == b {
		t.Fatal("the listener key didn't change with the period")
	}
}

func TestIssueRefuses(t *testing.T) {
	x := group(t, 1)
	if _, _, err := Issue(&roster.Writer{R: x.r, Me: x.member}, 1, time.Hour, nil, nil); !errors.Is(err, roster.ErrNotAllowed) {
		t.Fatalf("a member issued an invite: %v", err)
	}
	if _, _, err := Issue(&roster.Writer{R: x.r, Me: x.admin}, 1, 0, nil, nil); !errors.Is(err, roster.ErrNotAllowed) {
		t.Fatalf("an invite with no time to run: %v", err)
	}
}

// missRekey has the owner rekey in a copy that hasn't seen the member's
// add, so the member lacks the new keys once x.r takes the rekey.
func (x *fixture) missRekey(t *testing.T) *roster.Op {
	t.Helper()
	stale, err := roster.New(x.r.Op(x.r.Group()))
	if err != nil {
		t.Fatal(err)
	}
	f, _ := x.r.Fold()
	for _, o := range f.Order[1:] {
		if o.Kind == roster.Add && o.Target == x.admin.Public() {
			if _, err := stale.Add(o); err != nil {
				t.Fatal(err)
			}
		}
	}
	rk, err := (&roster.Writer{R: stale, Me: x.owner}).Rekey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x.r.Add(rk); err != nil {
		t.Fatal(err)
	}
	return rk
}

// TestMacBindsConnection: a request whose member-key proof is good but
// whose MAC was made for another connection is refused.
func TestMacBindsConnection(t *testing.T) {
	x := group(t, 1)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	iv := x.issued.Invite
	id := me(9)
	req := Request{Member: id.Public(), Name: "n"}
	go func() {
		_ = writeFrame(a, frameRequest, encodeRequest(req, macOf(iv, []byte("another connection"), req), id.Sign(proofOf(iv, secret, req))))
		_, _ = readAnswer(a)
	}()
	_, op, err := Serve(context.Background(), b, AdminConfig{Roster: x.r, Me: x.admin, Invite: iv, Secret: secret, Now: clock})
	if !errors.Is(err, ErrBadProof) || op != nil {
		t.Fatalf("got %v, want ErrBadProof", err)
	}
}

// TestRemovedKeyCantJoin: a removed member can't come back as a new joiner
// under its old key, even with an invite issued after its removal.
func TestRemovedKeyCantJoin(t *testing.T) {
	x := group(t, 1)
	if _, err := (&roster.Writer{R: x.r, Me: x.owner}).Remove(x.member.Public(), 0, [32]byte{}); err != nil {
		t.Fatal(err)
	}
	fresh, _, err := Issue(&roster.Writer{R: x.r, Me: x.admin, Now: clock}, 1, time.Hour, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	x.issued = fresh
	if _, _, _, jerr, _ := x.run(t, x.member, false, nil); !errors.Is(jerr, ErrAlreadyMember) {
		t.Fatalf("a removed key joined: %v", jerr)
	}
}

// TestAnswerWithoutKeys: a roster that admits the joiner but doesn't give
// it the current group secret is refused.
func TestAnswerWithoutKeys(t *testing.T) {
	x := group(t, 1)
	x.missRekey(t)
	f, _ := x.r.Fold()
	if _, err := check(JoinConfig{Invite: x.issued.Invite, Me: x.member, Secret: secret}, f.Order); !errors.Is(err, ErrBadAnswer) {
		t.Fatalf("a roster without the joiner's keys: %v", err)
	}
}

// TestAnswerCountChecked: an end frame that miscounts the operations is
// refused.
func TestAnswerCountChecked(t *testing.T) {
	x := group(t, 1)
	f, _ := x.r.Fold()
	var buf bytes.Buffer
	if err := writeAnswer(&buf, 0, f.Order); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	b[len(b)-2]++ // the end frame's count, a one-digit bencode integer
	if _, err := readAnswer(bytes.NewReader(b)); !errors.Is(err, ErrFrame) {
		t.Fatalf("a miscounted answer: %v", err)
	}
}

func TestLinkRejectsBadKey(t *testing.T) {
	x := group(t, 1)
	iv := x.issued.Invite
	iv.Key = keys.PublicKey{} // not a usable key
	if _, err := ParseLink(iv.Link()); !errors.Is(err, ErrBadLink) {
		t.Fatalf("a link with an unusable key parsed: %v", err)
	}
}

// TestExpiresDuringApproval: an invite that expires while Approve decides is
// refused, a rejoin with nothing to deliver included.
func TestExpiresDuringApproval(t *testing.T) {
	for _, rejoin := range []bool{false, true} {
		x := group(t, 1)
		clockNow := now
		id := me(9)
		if rejoin {
			id = x.member
		}
		_, _, op, jerr, serr := x.run(t, id, rejoin, func(a *AdminConfig, _ *JoinConfig) {
			a.Now = func() time.Time { return clockNow }
			a.Approve = func(Request) bool { clockNow = now.Add(time.Hour); return true }
		})
		if !errors.Is(jerr, ErrInviteUnusable) || !errors.Is(serr, ErrInviteUnusable) || op != nil {
			t.Fatalf("rejoin=%v: got %v / %v, want ErrInviteUnusable", rejoin, jerr, serr)
		}
	}
}

func TestIssueRefusesBadHints(t *testing.T) {
	x := group(t, 1)
	before := len(x.r.IDs())
	if _, _, err := Issue(&roster.Writer{R: x.r, Me: x.admin}, 1, time.Hour, []netip.AddrPort{{}}, nil); !errors.Is(err, roster.ErrNotAllowed) {
		t.Fatalf("an invalid hint was issued: %v", err)
	}
	if len(x.r.IDs()) != before {
		t.Fatal("a refused invite was recorded")
	}
}

// TestCancelUnblocks: cancelling either side's context ends a session
// blocked on a silent peer, and cancelling after it returns doesn't close
// the connection.
func TestCancelUnblocks(t *testing.T) {
	x := group(t, 1)
	for name, run := range map[string]func(ctx context.Context, c net.Conn) error{
		"Join": func(ctx context.Context, c net.Conn) error {
			_, err := Join(ctx, c, JoinConfig{Invite: x.issued.Invite, Me: me(9), Secret: secret})
			return err
		},
		"Serve": func(ctx context.Context, c net.Conn) error {
			_, _, err := Serve(ctx, c, AdminConfig{Roster: x.r, Me: x.admin, Invite: x.issued.Invite, Secret: secret})
			return err
		},
	} {
		a, b := net.Pipe()
		go func() { _, _ = io.Copy(io.Discard, b) }() // reads, never answers
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- run(ctx, a) }()
		time.Sleep(100 * time.Millisecond)
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: cancelling didn't unblock it", name)
		}
		a.Close()
		b.Close()
	}
	// A completed session, then a cancel: the connection stays open.
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() {
		_, _, err := Serve(ctx, b, AdminConfig{Roster: x.r, Me: x.admin, Invite: x.issued.Invite, Secret: secret, Now: clock})
		served <- err
	}()
	if _, err := Join(ctx, a, JoinConfig{Invite: x.issued.Invite, Me: me(9), Secret: secret}); err != nil {
		t.Fatal(err)
	}
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	cancel()
	time.Sleep(50 * time.Millisecond)
	go func() { _, _ = b.Write([]byte{1}) }()
	if _, err := io.ReadFull(a, make([]byte, 1)); err != nil {
		t.Fatalf("a cancel after the session closed the connection: %v", err)
	}
}

// TestAnswerLimits: a roster spanning several frames round-trips, and an
// answer past each receive limit is refused.
func TestAnswerLimits(t *testing.T) {
	x := group(t, 1)
	f, _ := x.r.Fold()
	restore := func(c, o, b int, fr uint32) func() {
		return func() { opsChunk, maxOps, maxOpsBytes, maxFrame = c, o, b, fr }
	}
	defer restore(opsChunk, maxOps, maxOpsBytes, maxFrame)()
	answer := func() []byte {
		var buf bytes.Buffer
		if err := writeAnswer(&buf, 0, f.Order); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	opsChunk = 1 // a frame per operation
	b := answer()
	frames := 0
	for rd := bytes.NewReader(b); ; {
		kind, _, err := readFrame(rd)
		if err != nil {
			break
		}
		if kind == frameOps {
			frames++
		}
	}
	if frames != len(f.Order) {
		t.Fatalf("%d op frames for %d operations, one each", frames, len(f.Order))
	}
	got, err := readAnswer(bytes.NewReader(b))
	if err != nil || len(got) != len(f.Order) {
		t.Fatalf("a multi-frame answer: %d ops, %v", len(got), err)
	}
	for i, o := range got {
		if o.ID() != f.Order[i].ID() {
			t.Fatal("the operations came back out of order")
		}
	}
	maxOps = len(f.Order) - 1
	if _, err := readAnswer(bytes.NewReader(b)); !errors.Is(err, ErrFrame) {
		t.Fatalf("too many operations: %v", err)
	}
	maxOps = 1 << 16
	maxOpsBytes = 100
	if _, err := readAnswer(bytes.NewReader(b)); !errors.Is(err, ErrFrame) {
		t.Fatalf("too many bytes of operations: %v", err)
	}
	maxOpsBytes = 16 << 20
	maxFrame = 64
	if _, err := readAnswer(bytes.NewReader(b)); !errors.Is(err, ErrFrame) {
		t.Fatalf("an oversized frame: %v", err)
	}
}
