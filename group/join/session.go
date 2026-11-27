package join

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/getlantern/warren/bencode"
	"github.com/getlantern/warren/group/keys"
	"github.com/getlantern/warren/group/roster"
)

var (
	// ErrBadProof means the joiner's proof of the invite secret, or of its
	// member key, doesn't verify.
	ErrBadProof = errors.New("join: bad proof")
	// ErrInviteUnusable means the invite isn't recorded, or is spent, dead
	// or expired.
	ErrInviteUnusable = errors.New("join: invite not usable")
	// ErrNotApproved means the admin declined the request.
	ErrNotApproved = errors.New("join: not approved")
	// ErrNotMember means a rejoining key isn't on the admin's roster (it
	// was removed, or never added).
	ErrNotMember = errors.New("join: not a member")
	// ErrAlreadyMember means a joining key is already on the roster, or was
	// removed from it.
	ErrAlreadyMember = errors.New("join: already a member")
	// ErrNotAdmin means the side serving the invite can't approve: it isn't
	// an owner or admin.
	ErrNotAdmin = errors.New("join: not an admin")
	// ErrNoKeys means the admin doesn't hold the current group secret, so
	// it can't give a joiner one.
	ErrNoKeys = errors.New("join: admin lacks the current keys")
	// ErrTooLarge means the roster wouldn't fit in an answer the joiner
	// takes.
	ErrTooLarge = errors.New("join: roster too large to answer")
	// ErrAdminBehind means the admin's runtime isn't on the group's current
	// secret yet, so it can't give a joiner one it can reach it with.
	ErrAdminBehind = errors.New("join: admin not on the current group secret")
	// ErrFrame means a malformed or oversized frame.
	ErrFrame = errors.New("join: malformed frame")
	// ErrBadAnswer means the admin's answer doesn't hold this joiner's
	// admission, or the keys it needs.
	ErrBadAnswer = errors.New("join: answer doesn't admit this member")
)

// Limits on an answer; tests lower them.
var (
	// maxOpsBytes and maxOps bound the roster an answer carries, as
	// group/session bounds an add chain.
	maxOpsBytes = 16 << 20
	maxOps      = 1 << 16
	// maxFrame bounds a frame.
	maxFrame = uint32(roster.MaxOpBytes + 64)
	// opsChunk is the bytes of operations a sender puts in one frame.
	opsChunk = 256 << 10
)

const (
	frameRequest = 'q'
	frameAnswer  = 'a'
	frameOps     = 'o'
	frameEnd     = 'e'
)

// Refusal codes in an answer, each an error a joiner gets back.
var codes = []error{nil, ErrBadProof, ErrInviteUnusable, ErrNotApproved, ErrNotMember, ErrAlreadyMember, ErrNotAdmin, ErrNoKeys, ErrTooLarge, ErrAdminBehind}

func codeOf(err error) int64 {
	for i, e := range codes {
		if i > 0 && errors.Is(err, e) {
			return int64(i)
		}
	}
	return int64(len(codes)) // something else went wrong
}

// Request is what a joiner asks for: to join with a new member key, or to
// rejoin with an existing one.
type Request struct {
	Member keys.PublicKey
	Name   string
	Rejoin bool
}

// macOf is the joiner's proof that it holds the invite secret, bound to the
// connection, the invite, and everything it asks.
func macOf(iv Invite, secret []byte, r Request) []byte {
	m := hmac.New(sha256.New, iv.Secret[:])
	m.Write([]byte("warren/group/v1 join mac "))
	m.Write(iv.Key[:])
	writeBytes(m, secret)
	m.Write(r.Member[:])
	writeBytes(m, []byte(r.Name))
	m.Write([]byte{boolByte(r.Rejoin)})
	return m.Sum(nil)
}

// proofOf is the message the joiner signs with its member key, so the admin
// knows it holds that key: no one can get another's key added or delivered
// to.
func proofOf(iv Invite, secret []byte, r Request) []byte {
	b := []byte("warren/group/v1 join proof ")
	b = append(b, iv.Key[:]...)
	b = binary.BigEndian.AppendUint32(b, uint32(len(secret)))
	b = append(b, secret...)
	return append(b, boolByte(r.Rejoin))
}

func writeBytes(w io.Writer, b []byte) {
	_, _ = w.Write(binary.BigEndian.AppendUint32(nil, uint32(len(b))))
	_, _ = w.Write(b)
}

func boolByte(b bool) byte {
	if b {
		return 1
	}
	return 0
}

// AdminConfig is the side that issued the invite.
type AdminConfig struct {
	Roster *roster.Roster
	Me     *keys.Identity
	// Invite is the invite this listener serves (its key and secret).
	Invite Invite
	// Secret is the connection's shared secret (endpoint.Conn.Secret).
	Secret []byte
	// Approve decides a request whose proofs check out; nil approves all.
	// It is given the session's context, and should return when that
	// ends: nothing is committed once it has, whatever it returns.
	Approve func(context.Context, Request) bool
	// Answered, if set, remembers the rejoiners this invite answered with
	// the roster alone (Issued.Answered), so their retries are answered
	// again: such an answer leaves no trace in the roster.
	Answered *Answered
	// Now is the clock the invite's expiry is checked against; nil means
	// time.Now.
	Now func() time.Time
}

// Serve answers one join or rejoin request on conn. On approval it writes
// the add (a join) or deliver (a rejoin) to cfg.Roster, then sends the
// joiner the roster's operations; a rejoiner holding every key already gets
// the roster and no deliver, spending nothing. It returns the request and
// the operation written, if any, for the caller to share with members. It
// closes conn if ctx ends.
func Serve(ctx context.Context, conn io.ReadWriteCloser, cfg AdminConfig) (Request, *roster.Op, error) {
	req, err := Verify(ctx, conn, cfg.Invite, cfg.Secret)
	if err != nil {
		return req, nil, err
	}
	op, err := Answer(ctx, conn, cfg, req)
	return req, op, err
}

// Verify reads a join request on conn and checks its proofs (the MAC with
// the invite secret, and the member-key signature), refusing a bad one. It
// touches no roster, so a caller can bound it and run it before taking
// the roster for Answer: a caller that can't prove the invite secret never
// gets that far. It closes conn if ctx ends.
func Verify(ctx context.Context, conn io.ReadWriteCloser, iv Invite, secret []byte) (Request, error) {
	defer watch(ctx, conn)()
	kind, b, err := readFrame(conn)
	if err != nil {
		return Request{}, err
	}
	if kind != frameRequest {
		return Request{}, ErrFrame
	}
	req, mac, sig, err := decodeRequest(b)
	if err != nil {
		return Request{}, err
	}
	if !hmac.Equal(mac, macOf(iv, secret, req)) || !req.Member.Verify(proofOf(iv, secret, req), sig) {
		_ = writeAnswer(conn, codeOf(ErrBadProof), nil)
		return req, ErrBadProof
	}
	return req, nil
}

// Answer decides a request Verify passed and answers it on conn, as Serve
// describes. It closes conn if ctx ends.
func Answer(ctx context.Context, conn io.ReadWriteCloser, cfg AdminConfig, req Request) (*roster.Op, error) {
	defer watch(ctx, conn)()
	now := time.Now
	if cfg.Now != nil {
		now = cfg.Now
	}
	op, err := decide(ctx, cfg, now, req)
	if err != nil {
		_ = writeAnswer(conn, codeOf(err), nil)
		return nil, err
	}
	f, err := cfg.Roster.Fold()
	if err != nil {
		return op, err
	}
	return op, writeAnswer(conn, 0, f.Order)
}

// NeedsApproval reports whether Answer would put req to Approve: it passes
// the roster's checks now and isn't a retry. A caller deciding approval
// itself, outside whatever holds the roster, asks this first (holding it
// briefly), decides, then calls Answer with no Approve, which checks
// everything again.
func NeedsApproval(cfg AdminConfig, req Request) bool {
	now := time.Now
	if cfg.Now != nil {
		now = cfg.Now
	}
	replay, err := admit(cfg, req, now())
	if err != nil || replay {
		return false
	}
	f, err := cfg.Roster.Fold()
	return err == nil && fits(f.Order)
}

// Refuse answers a request Verify passed with err's refusal code (say,
// ErrNotApproved, for a caller that decided approval itself).
func Refuse(ctx context.Context, conn io.ReadWriteCloser, err error) error {
	defer watch(ctx, conn)()
	return writeAnswer(conn, codeOf(err), nil)
}

// decide checks a request whose proofs Verify passed and, if it is
// approved, writes its operation.
func decide(ctx context.Context, cfg AdminConfig, now func() time.Time, req Request) (*roster.Op, error) {
	replay, err := admit(cfg, req, now())
	if err != nil {
		return nil, err
	}
	if replay {
		return redeliver(cfg, req, now())
	}
	if f, err := cfg.Roster.Fold(); err != nil || !fits(f.Order) {
		// Even without the op it would write, the answer couldn't be
		// sent: don't ask Approve.
		return nil, ErrTooLarge
	}
	if cfg.Approve != nil && !cfg.Approve(ctx, req) {
		return nil, ErrNotApproved
	}
	if err := ctx.Err(); err != nil {
		return nil, err // the session ended while Approve decided
	}
	// Approve may have taken a while, or changed the roster: check again,
	// on a fresh fold and at the one instant the writer then uses too.
	t := now()
	if replay, err = admit(cfg, req, t); err != nil {
		return nil, err
	}
	if replay {
		return redeliver(cfg, req, t)
	}
	if !req.Rejoin {
		return stage(cfg, t, func(w *roster.Writer) (*roster.Op, error) {
			return w.Add(req.Member, req.Name, roster.Member, cfg.Invite.Key)
		})
	}
	op, err := stage(cfg, t, func(w *roster.Writer) (*roster.Op, error) {
		op, err := w.Deliver(req.Member, cfg.Invite.Key)
		if errors.Is(err, roster.ErrNotAllowed) {
			// Everything else Deliver checks was just checked, against the
			// same roster and instant: the roster holds every key sealed to
			// the rejoiner already, so it needs only the roster (which
			// carries those seals: it may lack them locally, having been
			// away), and the invite isn't spent.
			return nil, nil
		}
		return op, err
	})
	if err == nil && op == nil {
		cfg.Answered.add(req.Member)
	}
	return op, err
}

// Answered is the rejoiners an invite answered with the roster alone. Such
// an answer writes nothing, so if it is lost the roster can't show the
// rejoiner was approved; the admin remembers it instead, for as long as it
// serves the invite. Safe for concurrent use; the zero value is empty.
type Answered struct {
	mu   sync.Mutex
	keys map[keys.PublicKey]bool
}

func (a *Answered) add(k keys.PublicKey) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.keys == nil {
		a.keys = map[keys.PublicKey]bool{}
	}
	a.keys[k] = true
}

func (a *Answered) has(k keys.PublicKey) bool {
	if a == nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.keys[k]
}

// stage writes an answer's operation, if any, on a copy of the roster at
// t, and commits it only if the answer it makes fits what the joiner
// takes: an approval committed that can't be sent would spend the invite
// for nothing.
func stage(cfg AdminConfig, t time.Time, write func(*roster.Writer) (*roster.Op, error)) (*roster.Op, error) {
	c := cfg.Roster.Clone()
	op, err := write(&roster.Writer{R: c, Me: cfg.Me, Now: func() time.Time { return t }})
	if err != nil {
		return nil, err
	}
	f, err := c.Fold()
	if err != nil {
		return nil, err
	}
	if !fits(f.Order) {
		return nil, ErrTooLarge
	}
	if op != nil {
		if _, err := cfg.Roster.Add(op); err != nil {
			return nil, err
		}
	}
	return op, nil
}

// fits reports whether an answer carrying ops is within what readAnswer
// takes, measured as writeAnswer frames it.
func fits(ops []*roster.Op) bool {
	total := 0
	for _, b := range opsFrames(ops) {
		total += len(b)
	}
	return total <= maxOpsBytes && len(ops) <= maxOps
}

// admit checks a request against the roster at t. replay reports a request
// an approver already answered under this invite for this key, still a
// member: its answer was lost, and it is answered again (redeliver)
// whether or not the invite is still usable, so a spent or expired invite
// can't strand it. The request's proofs bind it to that key and invite.
func admit(cfg AdminConfig, req Request, t time.Time) (replay bool, err error) {
	f, err := cfg.Roster.Fold()
	if err != nil {
		return false, err
	}
	if a := f.Roles[cfg.Me.Public()]; a != roster.Owner && a != roster.Admin {
		return false, ErrNotAdmin
	}
	// It must hold the current G to give one: otherwise Deliver could send
	// only older keys, or nothing, and an empty delivery wouldn't mean the
	// rejoiner holds every key.
	if _, ok := cfg.Roster.Keyring(cfg.Me).Secrets[f.Current]; !ok {
		return false, ErrNoKeys
	}
	member := f.Roles[req.Member] != roster.None
	if member && (answered(f, cfg.Invite.Key, req.Member) || cfg.Answered.has(req.Member)) {
		return true, nil
	}
	if s := f.Invites[cfg.Invite.Key]; s == nil || !s.Usable(t) {
		return false, ErrInviteUnusable
	}
	switch {
	case req.Rejoin && (!member || req.Member == cfg.Me.Public()):
		return false, ErrNotMember
	case !req.Rejoin && (member || f.Removed[req.Member] != roster.ID{}):
		return false, ErrAlreadyMember
	}
	return false, nil
}

// answered reports whether an approver answered invite for member: one of
// the operations that spent it, as the fold counts them (an owner's or
// admin's add, counting or not, or rejoin's deliver), was to member. A
// member's own deliver naming an invite spends nothing and is no approval.
func answered(f *roster.Result, invite, member keys.PublicKey) bool {
	s := f.Invites[invite]
	if s == nil {
		return false
	}
	for _, a := range s.Approvals {
		if a.Target == member {
			return true
		}
	}
	return false
}

// redeliver answers a replayed request: the roster, with a deliver of any
// keys the member has since come to lack (a rekey made without it, say).
// That deliver names no invite, so it spends nothing and needs no usable
// invite; any member may be delivered to.
func redeliver(cfg AdminConfig, req Request, t time.Time) (*roster.Op, error) {
	return stage(cfg, t, func(w *roster.Writer) (*roster.Op, error) {
		op, err := w.Deliver(req.Member, keys.PublicKey{})
		if errors.Is(err, roster.ErrNotAllowed) {
			return nil, nil // it holds every key
		}
		return op, err
	})
}

// JoinConfig is the joining side.
type JoinConfig struct {
	Invite Invite
	// Me is the member key: a fresh one to join, the existing one to
	// rejoin.
	Me     *keys.Identity
	Name   string
	Rejoin bool
	// Secret is the connection's shared secret (endpoint.Conn.Secret).
	Secret []byte
}

// Join asks to join (or rejoin) on conn, and returns the roster the admin
// answers with, once it holds cfg.Me as a member with the current group
// secret. A refusal comes back as its error (ErrNotApproved and so on). It
// closes conn if ctx ends.
func Join(ctx context.Context, conn io.ReadWriteCloser, cfg JoinConfig) (*roster.Roster, error) {
	defer watch(ctx, conn)()
	req := Request{Member: cfg.Me.Public(), Name: cfg.Name, Rejoin: cfg.Rejoin}
	if len(req.Name) > roster.MaxName {
		return nil, roster.ErrNotAllowed
	}
	mac := macOf(cfg.Invite, cfg.Secret, req)
	sig := cfg.Me.Sign(proofOf(cfg.Invite, cfg.Secret, req))
	if err := writeFrame(conn, frameRequest, encodeRequest(req, mac, sig)); err != nil {
		return nil, err
	}
	ops, err := readAnswer(conn)
	if err != nil {
		return nil, err
	}
	return check(cfg, ops)
}

// check builds the roster from an answer's operations and checks it admits
// cfg.Me with the current group secret, under cfg's invite.
func check(cfg JoinConfig, ops []*roster.Op) (*roster.Roster, error) {
	if len(ops) == 0 {
		return nil, ErrBadAnswer
	}
	r, err := roster.New(ops[0])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadAnswer, err)
	}
	for _, o := range ops[1:] {
		if _, err := r.Add(o); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrBadAnswer, err)
		}
	}
	f, err := r.Fold()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadAnswer, err)
	}
	if f.Invites[cfg.Invite.Key] == nil || f.Roles[cfg.Me.Public()] == roster.None {
		return nil, ErrBadAnswer
	}
	if _, ok := r.Keyring(cfg.Me).Secrets[f.Current]; !ok {
		return nil, ErrBadAnswer
	}
	return r, nil
}

// watch closes conn if ctx ends before the returned stop is called, and
// stop waits for the watcher, so a ctx cancelled afterwards can't close
// conn.
func watch(ctx context.Context, conn io.Closer) func() {
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-stop:
		}
	}()
	return func() {
		close(stop)
		<-done
	}
}

func writeFrame(w io.Writer, kind byte, body []byte) error {
	b := binary.BigEndian.AppendUint32(nil, uint32(len(body)+1))
	b = append(append(b, kind), body...)
	_, err := w.Write(b)
	return err
}

func readFrame(r io.Reader) (byte, []byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n < 1 || n > maxFrame {
		return 0, nil, ErrFrame
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return 0, nil, err
	}
	return b[0], b[1:], nil
}

func encodeRequest(r Request, mac, sig []byte) []byte {
	str := func(b []byte) bencode.Value { return bencode.Value{Kind: bencode.String, Str: b} }
	return bencode.Append(nil, bencode.Value{Kind: bencode.Dict, Dict: []bencode.Pair{
		{Key: []byte("k"), Value: str(r.Member[:])},
		{Key: []byte("m"), Value: str(mac)},
		{Key: []byte("n"), Value: str([]byte(r.Name))},
		{Key: []byte("r"), Value: bencode.Value{Kind: bencode.Int, Int: int64(boolByte(r.Rejoin))}},
		{Key: []byte("z"), Value: str(sig)},
	}})
}

func decodeRequest(b []byte) (Request, []byte, []byte, error) {
	var r Request
	v, err := bencode.DecodeLimit(b, 16)
	if err != nil || v.Kind != bencode.Dict || len(v.Dict) != 5 {
		return r, nil, nil, ErrFrame
	}
	k, okK := v.Get("k")
	m, okM := v.Get("m")
	n, okN := v.Get("n")
	rj, okR := v.Get("r")
	z, okZ := v.Get("z")
	if !okK || !okM || !okN || !okR || !okZ || k.Kind != bencode.String || len(k.Str) != 32 ||
		m.Kind != bencode.String || n.Kind != bencode.String || len(n.Str) > roster.MaxName ||
		rj.Kind != bencode.Int || (rj.Int != 0 && rj.Int != 1) || z.Kind != bencode.String {
		return r, nil, nil, ErrFrame
	}
	copy(r.Member[:], k.Str)
	if r.Member.Valid() != nil {
		return r, nil, nil, ErrFrame
	}
	r.Name, r.Rejoin = string(n.Str), rj.Int == 1
	return r, m.Str, z.Str, nil
}

// writeAnswer sends a refusal code, or, with code 0, ops in frames of up to
// opsChunk bytes and an end frame counting them.
func writeAnswer(w io.Writer, code int64, ops []*roster.Op) error {
	if err := writeFrame(w, frameAnswer, bencode.AppendInt(nil, code)); err != nil || code != 0 {
		return err
	}
	for _, b := range opsFrames(ops) {
		if err := writeFrame(w, frameOps, b); err != nil {
			return err
		}
	}
	return writeFrame(w, frameEnd, bencode.AppendInt(nil, int64(len(ops))))
}

// opsFrames is the bodies of the frames an answer carries ops in, up to
// opsChunk bytes of operations each.
func opsFrames(ops []*roster.Op) [][]byte {
	var out [][]byte
	var cur []bencode.Value
	size := 0
	flush := func() {
		if len(cur) > 0 {
			out = append(out, bencode.Append(nil, bencode.Value{Kind: bencode.List, List: cur}))
			cur, size = nil, 0
		}
	}
	for _, o := range ops {
		b := o.Encode()
		if size+len(b) > opsChunk && len(cur) > 0 {
			flush()
		}
		cur = append(cur, bencode.Value{Kind: bencode.String, Str: b})
		size += len(b) + 16
	}
	flush()
	return out
}

// readAnswer reads an answer: a refusal's error, or the operations.
func readAnswer(r io.Reader) ([]*roster.Op, error) {
	kind, b, err := readFrame(r)
	if err != nil {
		return nil, err
	}
	if kind != frameAnswer {
		return nil, ErrFrame
	}
	v, err := bencode.Decode(b)
	if err != nil || v.Kind != bencode.Int || v.Int < 0 {
		return nil, ErrFrame
	}
	if v.Int != 0 {
		if v.Int < int64(len(codes)) {
			return nil, codes[v.Int]
		}
		return nil, errors.New("join: refused")
	}
	var ops []*roster.Op
	total := 0
	for {
		kind, b, err := readFrame(r)
		if err != nil {
			return nil, err
		}
		switch kind {
		case frameOps:
			if total += len(b); total > maxOpsBytes {
				return nil, ErrFrame
			}
			l, err := bencode.DecodeLimit(b, maxOps+1)
			if err != nil || l.Kind != bencode.List {
				return nil, ErrFrame
			}
			for _, x := range l.List {
				if x.Kind != bencode.String {
					return nil, ErrFrame
				}
				o, err := roster.Decode(x.Str)
				if err != nil {
					return nil, fmt.Errorf("%w: %w", ErrFrame, err)
				}
				if ops = append(ops, o); len(ops) > maxOps {
					return nil, ErrFrame
				}
			}
		case frameEnd:
			n, err := bencode.Decode(b)
			if err != nil || n.Kind != bencode.Int || n.Int != int64(len(ops)) {
				return nil, ErrFrame
			}
			return ops, nil
		default:
			return nil, ErrFrame
		}
	}
}
