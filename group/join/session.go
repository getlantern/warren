package join

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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
	// ErrFrame means a malformed or oversized frame.
	ErrFrame = errors.New("join: malformed frame")
	// ErrBadAnswer means the admin's answer doesn't hold this joiner's
	// admission, or the keys it needs.
	ErrBadAnswer = errors.New("join: answer doesn't admit this member")
)

const (
	// maxOpsBytes and maxOps bound the roster an answer carries, as
	// group/session bounds an add chain.
	maxOpsBytes = 16 << 20
	maxOps      = 1 << 16
	// maxFrame bounds a frame.
	maxFrame = roster.MaxOpBytes + 64
	// opsChunk is the bytes of operations a sender puts in one frame.
	opsChunk = 256 << 10

	frameRequest = 'q'
	frameAnswer  = 'a'
	frameOps     = 'o'
	frameEnd     = 'e'
)

// Refusal codes in an answer, each an error a joiner gets back.
var codes = []error{nil, ErrBadProof, ErrInviteUnusable, ErrNotApproved, ErrNotMember, ErrAlreadyMember, ErrNotAdmin}

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
	Approve func(Request) bool
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
	defer watch(ctx, conn)()
	now := time.Now
	if cfg.Now != nil {
		now = cfg.Now
	}
	kind, b, err := readFrame(conn)
	if err != nil {
		return Request{}, nil, err
	}
	if kind != frameRequest {
		return Request{}, nil, ErrFrame
	}
	req, mac, sig, err := decodeRequest(b)
	if err != nil {
		return Request{}, nil, err
	}
	op, err := decide(cfg, now, req, mac, sig)
	if err != nil {
		_ = writeAnswer(conn, codeOf(err), nil)
		return req, nil, err
	}
	f, err := cfg.Roster.Fold()
	if err != nil {
		return req, op, err
	}
	return req, op, writeAnswer(conn, 0, f.Order)
}

// decide checks a request and, if it is approved, writes its operation.
func decide(cfg AdminConfig, now func() time.Time, req Request, mac, sig []byte) (*roster.Op, error) {
	if !hmac.Equal(mac, macOf(cfg.Invite, cfg.Secret, req)) || !req.Member.Verify(proofOf(cfg.Invite, cfg.Secret, req), sig) {
		return nil, ErrBadProof
	}
	f, err := cfg.Roster.Fold()
	if err != nil {
		return nil, err
	}
	if a := f.Roles[cfg.Me.Public()]; a != roster.Owner && a != roster.Admin {
		return nil, ErrNotAdmin
	}
	if s := f.Invites[cfg.Invite.Key]; s == nil || !s.Usable(now()) {
		return nil, ErrInviteUnusable
	}
	member := f.Roles[req.Member] != roster.None
	switch {
	case req.Rejoin && (!member || req.Member == cfg.Me.Public()):
		return nil, ErrNotMember
	case !req.Rejoin && (member || f.Removed[req.Member] != roster.ID{}):
		return nil, ErrAlreadyMember
	}
	if cfg.Approve != nil && !cfg.Approve(req) {
		return nil, ErrNotApproved
	}
	w := &roster.Writer{R: cfg.Roster, Me: cfg.Me, Now: now}
	if !req.Rejoin {
		return w.Add(req.Member, req.Name, roster.Member, cfg.Invite.Key)
	}
	op, err := w.Deliver(req.Member, cfg.Invite.Key)
	if errors.Is(err, roster.ErrNotAllowed) {
		// Everything else Deliver checks was checked above: the rejoiner
		// holds every key already, so it needs only the roster.
		return nil, nil
	}
	return op, err
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
	var cur []bencode.Value
	size := 0
	flush := func() error {
		if len(cur) == 0 {
			return nil
		}
		err := writeFrame(w, frameOps, bencode.Append(nil, bencode.Value{Kind: bencode.List, List: cur}))
		cur, size = nil, 0
		return err
	}
	for _, o := range ops {
		b := o.Encode()
		if size+len(b) > opsChunk && len(cur) > 0 {
			if err := flush(); err != nil {
				return err
			}
		}
		cur = append(cur, bencode.Value{Kind: bencode.String, Str: b})
		size += len(b) + 16
	}
	if err := flush(); err != nil {
		return err
	}
	return writeFrame(w, frameEnd, bencode.AppendInt(nil, int64(len(ops))))
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
