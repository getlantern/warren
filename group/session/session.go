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
	"sync"
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
	// ErrBacklog means the peer let more than maxQueued bytes of this
	// side's frames pile up unread.
	ErrBacklog = errors.New("session: peer isn't reading")
	// ErrRemoved means the peer's removal reached this side during the
	// session (through the session's own sync), which then stopped serving
	// it (docs/groups-design.md, *Removal*, step 2).
	ErrRemoved = errors.New("session: peer removed during the session")
	// ErrChainTooLarge means a sync session's add chain is past what a
	// callee takes from a peer it hasn't admitted yet.
	ErrChainTooLarge = errors.New("session: add chain too large")
)

const (
	// maxFrame bounds a frame: a sync message, a hello, or a piece of an
	// add chain.
	maxFrame = gsync.MaxMessage + 1
	// maxChainOps and maxChainBytes bound the add chain a callee takes
	// from a caller it hasn't admitted: generous for a real group's roster
	// (it is causally whole, never cut short), and a limit on what holding
	// G alone can make a callee keep before being refused.
	maxChainBytes = 16 << 20

	frameHello = 'h'
	frameChain = 'c'
	frameSync  = 's'
)

// maxQueued bounds the bytes of frames waiting to be written: sending
// never blocks the reader (two sides answering each other's bursts can't
// deadlock), and a peer that never reads can't make it grow without
// bound. Tests lower it.
var maxQueued = 64 << 20

var (
	// maxHeads bounds the roster heads a hello names: they are only a hint
	// of what the peer holds (fewer means more history sent), so a sender
	// caps what it advertises and a receiver refuses more. Tests lower it.
	maxHeads = 4096
	// chainChunk is the operation bytes one chain frame carries; tests
	// lower it.
	chainChunk = 1 << 20
	// maxChainOps bounds the add chain's operations, with maxChainBytes;
	// tests lower it.
	maxChainOps = 8192
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
	// Admitted, if set, is called once the peer is admitted, before the
	// sync: until then the peer has proved only that it holds an admitted
	// transport key, so a caller can bound that phase more tightly.
	Admitted func()
}

// Run admits the peer and syncs with it, returning its member key once
// both sides are finished. It closes conn if ctx ends or the session fails
// (so neither direction is left blocked); after a success conn is the
// caller's to close.
func Run(ctx context.Context, conn io.ReadWriteCloser, cfg Config) (keys.PublicKey, error) {
	s := newSession(cfg, conn)
	// The watcher is joined before Run returns, so a ctx the caller
	// cancels afterwards can't close conn under it.
	stop, watched := make(chan struct{}), make(chan struct{})
	defer func() {
		close(stop)
		<-watched
	}()
	go func() {
		defer close(watched)
		select {
		case <-ctx.Done():
			conn.Close()
		case <-stop:
		}
	}()
	go s.write()
	peer, err := s.run()
	if s.backlogged() {
		err = ErrBacklog // the close it caused is what failed the rest
	}
	if err != nil {
		conn.Close() // unblocks a writer the peer stopped reading
	}
	s.finish()
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
	werr chan error

	mu       sync.Mutex
	queue    [][]byte // frames to write, in order
	queued   int      // their bytes
	done     bool     // no more frames: write what's queued and stop
	overflow bool     // the queue passed maxQueued
	wake     chan struct{}
	// peerHello is the peer's hello, read and decoded; its proof is
	// checked in admit, once its member key can be.
	peerHello hello
}

func newSession(cfg Config, conn io.ReadWriteCloser) *session {
	return &session{cfg: cfg, conn: conn, werr: make(chan error, 1), wake: make(chan struct{}, 1)}
}

// write sends queued frames in order, from its own goroutine, so this
// side never blocks reading on the peer reading.
func (s *session) write() {
	var err error
	for {
		s.mu.Lock()
		batch, done := s.queue, s.done
		s.queue, s.queued = nil, 0
		s.mu.Unlock()
		for _, f := range batch {
			if err == nil {
				if _, err = s.conn.Write(f); err != nil {
					s.conn.Close() // unblocks the reader: the session has failed
				}
			}
		}
		if len(batch) == 0 {
			if done {
				s.werr <- err
				return
			}
			<-s.wake
		}
	}
}

// send queues a frame without blocking. Past maxQueued bytes unwritten the
// session fails, closing the connection.
func (s *session) send(kind byte, body []byte) {
	f := binary.BigEndian.AppendUint32(nil, uint32(len(body)+1))
	f = append(append(f, kind), body...)
	s.mu.Lock()
	if s.queued+len(f) > maxQueued {
		s.overflow = true
		s.mu.Unlock()
		s.conn.Close()
		return
	}
	s.queue = append(s.queue, f)
	s.queued += len(f)
	s.mu.Unlock()
	s.signal()
}

func (s *session) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// finish tells the writer no more frames come: it writes what's queued
// and stops.
func (s *session) finish() {
	s.mu.Lock()
	s.done = true
	s.mu.Unlock()
	s.signal()
}

func (s *session) backlogged() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.overflow
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
	caller, callee := s.transport()
	for _, p := range s.periods() {
		if s.cfg.Group.SyncKey(p, callee).Public() == caller {
			return true
		}
	}
	return false
}

// proof is what a side signs: the group, which side it is, both transport
// keys (the key the caller signed the call with and the key it called),
// and the connection's secret. The caller picks the secret, so the keys
// are what keep a proof one member made for calling another from being
// replayed to a third, under another caller key (a sync key) or to
// another callee; the role keeps it from being reflected back.
func proof(group roster.ID, caller bool, callerKey, calleeKey keys.PublicKey, secret []byte) []byte {
	role := "callee"
	if caller {
		role = "caller"
	}
	b := append([]byte("warren/group/v1 session "+role+" "), group[:]...)
	b = append(b, callerKey[:]...)
	b = append(b, calleeKey[:]...)
	return append(b, secret...)
}

// transport is the call's caller and callee keys, whichever side this is.
func (s *session) transport() (caller, callee keys.PublicKey) {
	if s.cfg.Caller {
		return s.cfg.Local, s.cfg.Peer
	}
	return s.cfg.Peer, s.cfg.Local
}

// proofFor is what the caller side (callerSide) signs in this session.
func (s *session) proofFor(callerSide bool) []byte {
	caller, callee := s.transport()
	return proof(s.cfg.Roster.Group(), callerSide, caller, callee, s.cfg.Secret)
}

func (s *session) run() (keys.PublicKey, error) {
	sync := s.viaSync()
	var peer keys.PublicKey
	if sync && s.cfg.Caller {
		// The callee may not know us: wait for its heads, then send the
		// operations it lacks that admit us, with our proof.
		heads, _, err := s.hello(false)
		if err != nil {
			return peer, err
		}
		// We know the callee: admit it before sending it anything, so a
		// peer that isn't it learns nothing of the roster.
		if peer, err = s.admit(nil); err != nil {
			return peer, err
		}
		s.sendChain(s.chainFor(heads))
		s.sendHello()
	} else {
		s.sendHello()
		// Only a sync session's callee takes an add chain before the hello.
		_, ops, err := s.hello(sync && !s.cfg.Caller)
		if err != nil {
			return peer, err
		}
		if peer, err = s.admit(ops); err != nil {
			return peer, err
		}
	}
	return peer, s.sync(peer)
}

type hello struct {
	key   keys.PublicKey
	sig   []byte
	heads []roster.ID
}

func (s *session) sendHello() {
	sig := s.cfg.Me.Sign(s.proofFor(s.cfg.Caller))
	var hs []bencode.Value
	heads := s.cfg.Roster.Heads()
	for _, h := range heads[:min(len(heads), maxHeads)] {
		hs = append(hs, bencode.Value{Kind: bencode.String, Str: slices.Clone(h[:])})
	}
	pub := s.cfg.Me.Public()
	d := bencode.Value{Kind: bencode.Dict, Dict: []bencode.Pair{
		{Key: []byte("h"), Value: bencode.Value{Kind: bencode.List, List: hs}},
		{Key: []byte("k"), Value: bencode.Value{Kind: bencode.String, Str: pub[:]}},
		{Key: []byte("s"), Value: bencode.Value{Kind: bencode.String, Str: sig}},
	}}
	s.send(frameHello, bencode.Append(nil, d))
}

// sendChain sends ops in frames of up to chainChunk bytes, before the
// hello they belong to.
func (s *session) sendChain(ops []*roster.Op) {
	var cur []bencode.Value
	size := 0
	flush := func() {
		if len(cur) > 0 {
			s.send(frameChain, bencode.Append(nil, bencode.Value{Kind: bencode.List, List: cur}))
			cur, size = nil, 0
		}
	}
	for _, o := range ops {
		b := o.Encode()
		n := len(b) + 16 // its string's length prefix, with room to spare
		if size+n > chainChunk && len(cur) > 0 {
			flush()
		}
		cur = append(cur, bencode.Value{Kind: bencode.String, Str: b})
		size += n
	}
	flush()
}

// hello reads the peer's hello, and before it, if takeChain, the add
// chain it sends; a chain past maxChainOps or maxChainBytes ends the
// session.
func (s *session) hello(takeChain bool) ([]roster.ID, []*roster.Op, error) {
	var ops []*roster.Op
	total := 0
	for {
		kind, b, err := s.read()
		if err != nil {
			return nil, nil, err
		}
		switch {
		case kind == frameChain && takeChain:
			if total += len(b); total > maxChainBytes {
				return nil, nil, ErrChainTooLarge
			}
			got, err := decodeChain(b)
			if err != nil {
				return nil, nil, err
			}
			if ops = append(ops, got...); len(ops) > maxChainOps {
				return nil, nil, ErrChainTooLarge
			}
			continue
		case kind != frameHello:
			return nil, nil, ErrFrame
		}
		h, err := decodeHello(b)
		if err != nil {
			return nil, nil, err
		}
		s.peerHello = h
		return h.heads, ops, nil
	}
}

func decodeChain(b []byte) ([]*roster.Op, error) {
	v, err := bencode.DecodeLimit(b, 1<<16)
	if err != nil || v.Kind != bencode.List {
		return nil, ErrFrame
	}
	var ops []*roster.Op
	for _, x := range v.List {
		if x.Kind != bencode.String {
			return nil, ErrFrame
		}
		o, err := roster.Decode(x.Str)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrFrame, err)
		}
		ops = append(ops, o)
	}
	return ops, nil
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
	if !ok1 || !ok2 || !ok3 || k.Kind != bencode.String || len(k.Str) != 32 ||
		sig.Kind != bencode.String || hs.Kind != bencode.List || len(hs.List) > maxHeads {
		return h, ErrFrame
	}
	h.key, h.sig = keys.PublicKey(k.Str), slices.Clone(sig.Str)
	for _, x := range hs.List {
		if x.Kind != bencode.String || len(x.Str) != len(roster.ID{}) {
			return h, ErrFrame
		}
		h.heads = append(h.heads, roster.ID(x.Str))
	}
	return h, nil
}

// chainFor is the operations the callee, holding heads, lacks: everything
// this side holds outside their history, parents first, which includes
// whatever admitted this side.
func (s *session) chainFor(heads []roster.ID) []*roster.Op {
	theirs := s.cfg.Roster.Closure(heads) // one walk, however many heads share history
	var ops []*roster.Op
	for _, id := range s.cfg.Roster.IDs() {
		if !theirs[id] && id != s.cfg.Roster.Group() {
			ops = append(ops, s.cfg.Roster.Op(id))
		}
	}
	return ops // whole: a chain cut short would lack the parents of what it keeps
}

// admit checks the peer's proof verifies under the member key it named,
// that key is on the roster (with a sync session's add chain folded in),
// and the transport key it used is that member's. The add chain is folded
// on a copy of the roster and kept only once all three pass, so a peer
// that isn't admitted leaves nothing behind.
func (s *session) admit(ops []*roster.Op) (keys.PublicKey, error) {
	h := s.peerHello
	if !h.key.Verify(s.proofFor(!s.cfg.Caller), h.sig) {
		return h.key, ErrBadProof
	}
	// Only operations this side lacks need a copy to fold on; a chain of
	// ones already held (a replayed hello) costs nothing more.
	var fresh []*roster.Op
	for _, o := range ops {
		if !s.cfg.Roster.Has(o.ID()) {
			fresh = append(fresh, o)
		}
	}
	ops = fresh
	r := s.cfg.Roster
	if len(ops) > 0 {
		r = r.Clone()
		for _, o := range ops {
			if _, err := r.Add(o); err != nil && !errors.Is(err, roster.ErrMissingParent) {
				return h.key, err
			}
		}
	}
	f, err := r.Fold()
	if err != nil {
		return h.key, err
	}
	if f.Roles[h.key] == roster.None {
		return h.key, ErrNotMember
	}
	if !s.transportMatches(h.key) {
		return h.key, ErrTransportKey
	}
	if s.cfg.Admitted != nil {
		s.cfg.Admitted()
	}
	// Admitted: keep the chain, and bring the logs up to the roster.
	for _, o := range ops {
		if _, err := s.cfg.Roster.Add(o); err != nil && !errors.Is(err, roster.ErrMissingParent) {
			return h.key, err
		}
	}
	if len(ops) > 0 {
		if f, err = s.cfg.Roster.Fold(); err != nil {
			return h.key, err
		}
	}
	return h.key, s.cfg.Logs.Update(f)
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

// batchDone reports whether m leaves the peer's roster operations whole:
// it isn't an Ops message with more to follow.
func batchDone(m gsync.Message) bool {
	o, ok := m.(gsync.Ops)
	return !ok || !o.More
}

// sync runs group/sync with peer to the end. A message that adds roster
// operations is checked for peer's removal, which ends the session before
// anything more is sent: a removed member is served nothing after this
// side learns of it, whoever it learned it from. On failure the logs are
// brought up to the roster as it now stands: operations taken before the
// session failed (a removal in a batch the peer never finished) stay in
// the roster, so the logs must follow them.
func (s *session) sync(peer keys.PublicKey) (err error) {
	defer func() {
		if err != nil {
			if f, ferr := s.cfg.Roster.Fold(); ferr == nil {
				_ = s.cfg.Logs.Update(f)
			}
		}
	}()
	x := gsync.New(s.cfg.Roster, s.cfg.Logs)
	pending := false // roster operations added, peer's membership not yet checked
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
		before := s.cfg.Roster.Len()
		out, err := x.Handle(m)
		if err != nil {
			return err
		}
		if s.cfg.Roster.Len() != before { // only then can peer have been removed
			pending = true
		}
		// Decided on the whole batch: a later chunk can void a removal in
		// an earlier one (the remover's concurrent demotion, say). The
		// sync answers no chunk but the last, so nothing is served
		// meanwhile.
		if pending && batchDone(m) {
			pending = false
			f := x.Fold() // the sync's own, for the batch just finished
			if f == nil {
				if f, err = s.cfg.Roster.Fold(); err != nil {
					return err
				}
			}
			if f.Roles[peer] == roster.None {
				return ErrRemoved
			}
		}
		for _, o := range out {
			s.send(frameSync, gsync.Encode(o))
		}
	}
	return nil
}
