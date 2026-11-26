// Package session is a group member session over one connection
// (docs/groups-design.md, *Sessions*): admission first, each side proving
// its member key over the connection's shared secret and checking the
// other's against its roster, then the exchange of group/sync until both
// sides are finished. It runs over any reliable byte stream; a member's
// runtime opens one over a hysteria2 stream on an endpoint.Conn.
package session

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/getlantern/warren/bencode"
	"github.com/getlantern/warren/group/keys"
	"github.com/getlantern/warren/group/memberlog"
	"github.com/getlantern/warren/group/roster"
	gsync "github.com/getlantern/warren/group/sync"
)

var (
	// ErrNotMember means the peer's member key isn't on this side's roster,
	// even after any add chain it presented.
	ErrNotMember = errors.New("session: peer is not a member")
	// ErrBadProof means the peer's signature over the session doesn't verify
	// under the member key it named.
	ErrBadProof = errors.New("session: bad member-key proof")
	// ErrTransportKey means the key the peer called or listened under isn't
	// that member's rendezvous key (or a sync key) for any nearby period.
	ErrTransportKey = errors.New("session: transport key doesn't match the member")
	// ErrFrame means a malformed or oversized frame.
	ErrFrame = errors.New("session: malformed frame")
)

const (
	// maxFrame bounds a frame: a sync message, or a hello carrying an add
	// chain.
	maxFrame = gsync.MaxMessage + 1
	// maxChainOps bounds the operations a hello may carry.
	maxChainOps = 1024

	frameHello = 'h'
	frameSync  = 's'
)

// Config is one side of a session.
type Config struct {
	Me     *keys.Identity
	Group  keys.Secret
	Roster *roster.Roster
	Logs   *memberlog.Set
	// Secret is the connection's shared secret (endpoint.Conn.Secret): the
	// proofs sign it, so neither can be replayed on another connection.
	Secret []byte
	// Caller is true on the side that placed the call.
	Caller bool
	// Local and Peer are the transport keys: the caller's signing key (a
	// rendezvous key, or a sync key) and the listener key it called
	// (endpoint.Conn.LocalKey and PeerKey).
	Local, Peer keys.PublicKey
	// Now places the session in a period, for the rendezvous and sync keys.
	Now time.Time
}

// Run admits the peer and syncs with it, returning its member key once
// both sides are finished. It closes conn if ctx ends first; otherwise
// conn is the caller's to close.
func Run(ctx context.Context, conn io.ReadWriteCloser, cfg Config) (keys.PublicKey, error) {
	s := &session{cfg: cfg, conn: conn, out: make(chan []byte, 256), werr: make(chan error, 1)}
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-stop:
		}
	}()
	go s.write()
	peer, err := s.run()
	close(s.out)
	if werr := <-s.werr; err == nil {
		err = werr
	}
	if err != nil && ctx.Err() != nil {
		err = ctx.Err()
	}
	return peer, err
}

type session struct {
	cfg  Config
	conn io.ReadWriteCloser
	out  chan []byte
	werr chan error
	// peerHello is the peer's hello, read and decoded; its proof is
	// checked in admit, once its member key can be.
	peerHello hello
}

// write sends queued frames in order, so this side never blocks reading
// on the peer reading.
func (s *session) write() {
	var err error
	for f := range s.out {
		if err == nil {
			_, err = s.conn.Write(f)
		}
	}
	s.werr <- err
}

func (s *session) send(kind byte, body []byte) {
	f := binary.BigEndian.AppendUint32(nil, uint32(len(body)+1))
	f = append(f, kind)
	s.out <- append(f, body...)
}

func (s *session) read() (byte, []byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(s.conn, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n < 1 || n > maxFrame {
		return 0, nil, ErrFrame
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(s.conn, b); err != nil {
		return 0, nil, err
	}
	return b[0], b[1:], nil
}

// periods are the periods a transport key may belong to: the current and
// its neighbors, for a call across a period boundary.
func (s *session) periods() []uint64 {
	p := keys.PeriodOf(s.cfg.Now)
	return []uint64{p - 1, p, p + 1}
}

// viaSync reports whether the caller's transport key is the sync key for
// calling the callee's rendezvous key: a caller the callee may not know.
func (s *session) viaSync() bool {
	caller, callee := s.cfg.Peer, s.cfg.Local
	if s.cfg.Caller {
		caller, callee = s.cfg.Local, s.cfg.Peer
	}
	for _, p := range s.periods() {
		if s.cfg.Group.SyncKey(p, callee).Public() == caller {
			return true
		}
	}
	return false
}

// proof is what a side signs: the connection's secret and which side it
// is, so a proof can be neither replayed on another connection nor
// reflected back.
func proof(secret []byte, caller bool) []byte {
	role := "callee"
	if caller {
		role = "caller"
	}
	return append([]byte("warren/group/v1 session "+role+" "), secret...)
}

func (s *session) run() (keys.PublicKey, error) {
	sync := s.viaSync()
	var peer keys.PublicKey
	if sync && s.cfg.Caller {
		// The callee may not know us: wait for its heads, then send the
		// operations it lacks that admit us, with our proof.
		heads, _, err := s.hello()
		if err != nil {
			return peer, err
		}
		s.sendHello(s.chainFor(heads))
		if peer, err = s.admit(heads, nil); err != nil {
			return peer, err
		}
	} else {
		s.sendHello(nil)
		heads, ops, err := s.hello()
		if err != nil {
			return peer, err
		}
		if len(ops) > 0 && (!sync || s.cfg.Caller) { // only a sync session's callee takes ops in a hello
			return peer, fmt.Errorf("%w: operations outside a sync session's hello", ErrFrame)
		}
		if peer, err = s.admit(heads, ops); err != nil {
			return peer, err
		}
	}
	return peer, s.sync()
}

type hello struct {
	key   keys.PublicKey
	sig   []byte
	heads []roster.ID
	ops   []*roster.Op
}

func (s *session) sendHello(ops []*roster.Op) {
	sig := s.cfg.Me.Sign(proof(s.cfg.Secret, s.cfg.Caller))
	var hs, os []bencode.Value
	for _, h := range s.cfg.Roster.Heads() {
		hs = append(hs, bencode.Value{Kind: bencode.String, Str: slices.Clone(h[:])})
	}
	for _, o := range ops {
		os = append(os, bencode.Value{Kind: bencode.String, Str: o.Encode()})
	}
	pub := s.cfg.Me.Public()
	d := bencode.Value{Kind: bencode.Dict, Dict: []bencode.Pair{
		{Key: []byte("h"), Value: bencode.Value{Kind: bencode.List, List: hs}},
		{Key: []byte("k"), Value: bencode.Value{Kind: bencode.String, Str: pub[:]}},
		{Key: []byte("o"), Value: bencode.Value{Kind: bencode.List, List: os}},
		{Key: []byte("s"), Value: bencode.Value{Kind: bencode.String, Str: sig}},
	}}
	s.send(frameHello, bencode.Append(nil, d))
}

func (s *session) hello() ([]roster.ID, []*roster.Op, error) {
	kind, b, err := s.read()
	if err != nil {
		return nil, nil, err
	}
	if kind != frameHello {
		return nil, nil, ErrFrame
	}
	h, err := decodeHello(b)
	if err != nil {
		return nil, nil, err
	}
	s.peerHello = h
	return h.heads, h.ops, nil
}

func decodeHello(b []byte) (hello, error) {
	var h hello
	v, err := bencode.DecodeLimit(b, 1<<16)
	if err != nil || v.Kind != bencode.Dict {
		return h, ErrFrame
	}
	k, ok1 := v.Get("k")
	sig, ok2 := v.Get("s")
	hs, ok3 := v.Get("h")
	os, ok4 := v.Get("o")
	if !ok1 || !ok2 || !ok3 || !ok4 || k.Kind != bencode.String || len(k.Str) != 32 ||
		sig.Kind != bencode.String || hs.Kind != bencode.List || os.Kind != bencode.List ||
		len(hs.List) > maxChainOps || len(os.List) > maxChainOps {
		return h, ErrFrame
	}
	h.key, h.sig = keys.PublicKey(k.Str), slices.Clone(sig.Str)
	for _, x := range hs.List {
		if x.Kind != bencode.String || len(x.Str) != len(roster.ID{}) {
			return h, ErrFrame
		}
		h.heads = append(h.heads, roster.ID(x.Str))
	}
	for _, x := range os.List {
		if x.Kind != bencode.String {
			return h, ErrFrame
		}
		o, err := roster.Decode(x.Str)
		if err != nil {
			return h, fmt.Errorf("%w: %w", ErrFrame, err)
		}
		h.ops = append(h.ops, o)
	}
	return h, nil
}

// chainFor is the operations the callee, holding heads, lacks: everything
// this side holds outside their history, parents first, which includes
// whatever admitted this side.
func (s *session) chainFor(heads []roster.ID) []*roster.Op {
	theirs := map[roster.ID]bool{}
	for _, h := range heads {
		if s.cfg.Roster.Has(h) {
			theirs[h] = true
			for id := range s.cfg.Roster.History(h) {
				theirs[id] = true
			}
		}
	}
	var ops []*roster.Op
	for _, id := range s.cfg.Roster.IDs() {
		if !theirs[id] && id != s.cfg.Roster.Group() {
			ops = append(ops, s.cfg.Roster.Op(id))
		}
	}
	if len(ops) > maxChainOps {
		ops = ops[len(ops)-maxChainOps:] // the newest, which admit recent members
	}
	return ops
}

// admit takes the peer's operations (a sync session's add chain), then
// checks its member key is on the roster, its proof verifies, and the
// transport key it used is that member's.
func (s *session) admit(_ []roster.ID, ops []*roster.Op) (keys.PublicKey, error) {
	h := s.peerHello
	for _, o := range ops {
		if _, err := s.cfg.Roster.Add(o); err != nil && !errors.Is(err, roster.ErrMissingParent) {
			return h.key, err
		}
	}
	f, err := s.cfg.Roster.Fold()
	if err != nil {
		return h.key, err
	}
	if err := s.cfg.Logs.Update(f); err != nil {
		return h.key, err
	}
	if f.Roles[h.key] == roster.None {
		return h.key, ErrNotMember
	}
	if !h.key.Verify(proof(s.cfg.Secret, !s.cfg.Caller), h.sig) {
		return h.key, ErrBadProof
	}
	if !s.transportMatches(h.key) {
		return h.key, ErrTransportKey
	}
	return h.key, nil
}

// transportMatches reports whether the peer's transport key is member's:
// its rendezvous key for a nearby period, or, for a caller, the sync key
// for calling this side.
func (s *session) transportMatches(member keys.PublicKey) bool {
	for _, p := range s.periods() {
		if r, err := keys.Rendezvous(s.cfg.Group, p, member); err == nil && r == s.cfg.Peer {
			return true
		}
	}
	return !s.cfg.Caller && s.viaSync()
}

// sync runs the group/sync exchange to its end.
func (s *session) sync() error {
	x := gsync.New(s.cfg.Roster, s.cfg.Logs)
	for _, m := range x.Start() {
		s.send(frameSync, gsync.Encode(m))
	}
	for !x.Finished() {
		kind, b, err := s.read()
		if err != nil {
			return err
		}
		if kind != frameSync {
			return ErrFrame
		}
		m, err := gsync.Decode(b)
		if err != nil {
			return err
		}
		out, err := x.Handle(m)
		if err != nil {
			return err
		}
		for _, o := range out {
			s.send(frameSync, gsync.Encode(o))
		}
	}
	return nil
}
