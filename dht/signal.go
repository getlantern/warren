package dht

// DHT signaling, after HyperDHT's design but carried entirely in standard
// BEP 44 messages so it looks like ordinary mutable-item traffic:
//
//   - A provider publishes a record (a mutable item it signs, holding its
//     X25519 key) under a salt that rotates hourly. The nodes storing it
//     become its holders. Each holder binds the record to the provider's
//     NAT-observed address when the provider's signed put arrives, and the
//     provider's periodic gets for its own record keep that NAT path open.
//   - A caller looks the record up, then sends an offer to a holder as a
//     mutable put signed by the caller. The offer's salt is
//     nonce ‖ HMAC(record target, nonce): the holder can tell which record
//     it is for, but an observer cannot link it to the provider without
//     knowing the record target. The value is encrypted to the provider.
//   - The holder forwards the offer to the provider over the bound path. The
//     provider's answer, signed by the provider and stored under a salt
//     derived from the offer's, returns the same way.
//
// Only a signed put can bind or rebind a record to an address, so replaying
// a captured put from elsewhere cannot hijack forwarding while the provider
// keeps its binding fresh; offers and answers are end-to-end encrypted, so a
// misbehaving holder can drop them but not read or forge them.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"time"

	"github.com/getlantern/warren/bencode"
	"github.com/getlantern/warren/krpc"
)

type SessionID [16]byte

// Incoming is an offer delivered to a listening provider. Reply with Answer.
type Incoming struct {
	Session SessionID
	Caller  [32]byte // the caller's ed25519 key, verified
	Payload []byte
}

// Answered completes a Signal call.
type Answered struct {
	Op       OpID
	Provider [32]byte
	Payload  []byte
	Via      netip.AddrPort // the holder that relayed it
}

type SignalFailed struct {
	Op  OpID
	Err error
}

func (Incoming) isEvent()     {}
func (Answered) isEvent()     {}
func (SignalFailed) isEvent() {}

var (
	ErrNoRecord        = errors.New("dht: provider record not found")
	ErrNoAnswer        = errors.New("dht: no holder delivered an answer")
	ErrNotListening    = errors.New("dht: not listening")
	ErrUnknownSession  = errors.New("dht: unknown or expired session")
	ErrPayloadTooLarge = errors.New("dht: signaling payload too large")
)

const (
	MaxSignalPayload = 900
	RecordEpoch      = time.Hour

	signalAttemptTimeout = 4 * time.Second // answers wait on the provider gathering a fresh socket; dead holders are caught by the ack
	offerMaxSkew         = 60              // seconds between signer and verifier clocks
	sessionLifetime      = time.Minute
	forwardTTL           = 2 * time.Minute
	pendingAnswerTTL     = 30 * time.Second
	maxBindings          = 512
	maxPendingAnswers    = 256
	maxSessions          = 64
	maxHolders           = 4
	holderMaxFailures    = 2
)

// RecordSalt is the BEP 44 salt of provider's record in epoch.
func RecordSalt(provider [32]byte, epoch int64) []byte {
	h := sha256.New()
	h.Write([]byte("warren/record/v1"))
	h.Write(provider[:])
	h.Write(binary.LittleEndian.AppendUint64(nil, uint64(epoch)))
	return h.Sum(nil)[:16]
}

func epochOf(t time.Time) int64 { return t.Unix() / int64(RecordEpoch/time.Second) }

func offerSalt(nonce []byte, recordTarget krpc.NodeID) []byte {
	m := hmac.New(sha256.New, recordTarget[:])
	m.Write(nonce)
	return append(slices.Clone(nonce[:16]), m.Sum(nil)[:16]...)
}

func saltMatchesRecord(salt []byte, recordTarget krpc.NodeID) bool {
	if len(salt) != 32 {
		return false
	}
	m := hmac.New(sha256.New, recordTarget[:])
	m.Write(salt[:16])
	return hmac.Equal(m.Sum(nil)[:16], salt[16:])
}

func answerSalt(offer []byte) []byte {
	h := sha256.Sum256(append([]byte("warren/answer/v1"), offer...))
	return h[:]
}

func encodeRecord(x [32]byte) []byte {
	b := []byte{'d'}
	b = bencode.AppendString(b, "x")
	b = bencode.AppendBytes(b, x[:])
	return append(b, 'e')
}

func decodeRecord(v []byte) ([32]byte, bool) {
	d, err := bencode.Decode(v)
	if err != nil {
		return [32]byte{}, false
	}
	x, ok := d.Get("x")
	if !ok || x.Kind != bencode.String || len(x.Str) != 32 {
		return [32]byte{}, false
	}
	return [32]byte(x.Str), true
}

func decodeString(v []byte) ([]byte, bool) {
	d, err := bencode.Decode(v)
	if err != nil || d.Kind != bencode.String {
		return nil, false
	}
	return d.Str, true
}

// signalKeys derives the offer and answer keys from an X25519 exchange,
// binding both public keys.
func signalKeys(shared, ePub, xPub []byte) (offer, answer []byte, err error) {
	salt := append(slices.Clone(ePub), xPub...)
	if offer, err = hkdf.Key(sha256.New, shared, salt, "warren/signal/v1 offer", 32); err != nil {
		return nil, nil, err
	}
	answer, err = hkdf.Key(sha256.New, shared, salt, "warren/signal/v1 answer", 32)
	return offer, answer, err
}

func (n *Node) randBytes(k int) []byte {
	b := make([]byte, k)
	for i := 0; i < k; i += 8 {
		var w [8]byte
		binary.LittleEndian.PutUint64(w[:], n.cfg.Rand.Uint64())
		copy(b[i:], w[:])
	}
	return b
}

func (n *Node) seal(key, plaintext []byte) []byte {
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := n.randBytes(gcm.NonceSize())
	return gcm.Seal(nonce, nonce, plaintext, nil)
}

func open(key, sealed []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, errors.New("dht: sealed message too short")
	}
	return gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], nil)
}

func fresh(seq int64, now time.Time) bool {
	d := seq - now.Unix()
	return d >= -offerMaxSkew && d <= offerMaxSkew
}

// ---- holder: forwarding ----

type binding struct {
	addr netip.AddrPort
	seq  int64
	seen time.Time
}

type pendingAnswer struct {
	caller  netip.AddrPort
	expires time.Time
}

type forwarder struct {
	binds   map[krpc.NodeID]*binding
	answers map[string]pendingAnswer
}

// bind records the address a signed put for target came from. Only a
// strictly newer sequence number moves a binding to a new address; an equal
// one only refreshes the same address, even once stale, since anyone can
// replay the provider's last put. Providers re-sign on every republish, so a
// binding lost to a gap in keepalives recovers within one republish interval.
func (f *forwarder) bind(target krpc.NodeID, addr netip.AddrPort, seq int64, now time.Time) {
	if f.binds == nil {
		f.binds = map[krpc.NodeID]*binding{}
	}
	b := f.binds[target]
	if b != nil && seq <= b.seq && addr != b.addr {
		return
	}
	if b == nil && len(f.binds) >= maxBindings {
		var oldest krpc.NodeID
		var at time.Time
		for k, x := range f.binds {
			if at.IsZero() || x.seen.Before(at) || (x.seen.Equal(at) && compareID(k, oldest) < 0) {
				oldest, at = k, x.seen
			}
		}
		delete(f.binds, oldest)
	}
	f.binds[target] = &binding{addr: addr, seq: max(seq, seqOf(b)), seen: now}
}

func seqOf(b *binding) int64 {
	if b == nil {
		return 0
	}
	return b.seq
}

// touch refreshes a binding when its provider polls its own record.
func (f *forwarder) touch(target krpc.NodeID, addr netip.AddrPort, now time.Time) {
	if b := f.binds[target]; b != nil && b.addr == addr {
		b.seen = now
	}
}

func (f *forwarder) offerDest(salt []byte, now time.Time) (netip.AddrPort, bool) {
	for target, b := range f.binds {
		if now.Sub(b.seen) < forwardTTL && saltMatchesRecord(salt, target) {
			return b.addr, true
		}
	}
	return netip.AddrPort{}, false
}

func (f *forwarder) expect(salt []byte, caller netip.AddrPort, now time.Time) {
	if f.answers == nil {
		f.answers = map[string]pendingAnswer{}
	}
	if len(f.answers) >= maxPendingAnswers {
		return
	}
	f.answers[string(salt)] = pendingAnswer{caller: caller, expires: now.Add(pendingAnswerTTL)}
}

func (f *forwarder) answerDest(salt []byte, now time.Time) (netip.AddrPort, bool) {
	p, ok := f.answers[string(salt)]
	if !ok || !now.Before(p.expires) {
		return netip.AddrPort{}, false
	}
	delete(f.answers, string(salt))
	return p.caller, true
}

func (f *forwarder) expire(now time.Time) {
	for k, p := range f.answers {
		if !now.Before(p.expires) {
			delete(f.answers, k)
		}
	}
	for k, b := range f.binds {
		if now.Sub(b.seen) >= 2*forwardTTL {
			delete(f.binds, k)
		}
	}
}

// relay handles a verified signaling put: offers go to the bound provider,
// answers back to the caller that sent the offer. It reports whether the
// put was consumed.
func (n *Node) relay(now time.Time, from netip.AddrPort, m *MutableItem) bool {
	if len(m.Salt) != 32 {
		return false
	}
	if dst, ok := n.fwd.answerDest(m.Salt, now); ok {
		n.push(dst, m)
		return true
	}
	if dst, ok := n.fwd.offerDest(m.Salt, now); ok {
		n.fwd.expect(answerSalt(m.Salt), from, now)
		n.push(dst, m)
		return true
	}
	return false
}

// push delivers a signaling item as a put query over a path the recipient
// keeps open. No reply is expected; callers retry through other holders.
func (n *Node) push(to netip.AddrPort, m *MutableItem) {
	a := m.args()
	a.ID = n.cfg.ID
	a.Token = n.token(to.Addr(), n.secret)
	var tid [2]byte
	binary.BigEndian.PutUint16(tid[:], uint16(n.cfg.Rand.Uint32()))
	q := krpc.Msg{T: tid[:], Y: krpc.Query, Q: "put", A: a, RO: n.cfg.ReadOnly, V: n.cfg.Version}
	n.sends = append(n.sends, Send{To: to, Data: krpc.AppendMarshal(nil, &q)})
}

// ---- provider: listening ----

type holder struct {
	addr     netip.AddrPort
	target   krpc.NodeID
	token    []byte
	mapped   netip.AddrPort
	fails    int
	domestic bool
}

type session struct {
	via        netip.AddrPort
	answerSalt []byte
	key        []byte
	expires    time.Time
	// answer is kept after Answer: if it is lost, the caller retries the same
	// offer through another holder, and we resend rather than drop it.
	answer *MutableItem
	// relays are further addresses that relayed this offer, which also get
	// the answer. A retry never replaces via: offers are replayable, so a
	// later source may be anyone, and redirecting to it would let a replayer
	// swallow the answer.
	relays     []netip.AddrPort
	unverified int // relays that are not adopted holders
	// tokens are write tokens fetched from relays we never adopted, kept per
	// session so they are bounded and expire with it.
	tokens map[netip.AddrPort][]byte
}

const maxSessionRelays = 4

type listener struct {
	priv     ed25519.PrivateKey
	pub      [32]byte
	x        *ecdh.PrivateKey
	records  map[int64]krpc.NodeID // epoch → record target
	holders  []*holder
	nextKA   time.Time
	sessions map[SessionID]*session
	seen     map[string]time.Time
	retry    time.Duration // publication backoff while nothing stores our record
}

// Listen publishes a signaling record for priv's key and keeps it reachable.
func (n *Node) Listen(now time.Time, priv ed25519.PrivateKey) error {
	x, err := ecdh.X25519().NewPrivateKey(n.randBytes(32))
	if err != nil {
		return err
	}
	// A new identity replaces the old one entirely: its records stop being
	// republished, since their offers could no longer be decrypted.
	n.Unlisten()
	n.lst = &listener{
		priv: priv, pub: [32]byte(priv.Public().(ed25519.PublicKey)), x: x,
		records: map[int64]krpc.NodeID{}, sessions: map[SessionID]*session{}, seen: map[string]time.Time{},
	}
	n.ensureRecords(now)
	n.maintain(now)
	return nil
}

func (n *Node) Unlisten() {
	if n.lst == nil {
		return
	}
	for _, t := range n.lst.records {
		delete(n.owned, t)
	}
	n.lst = nil
}

// ensureRecords publishes the current epoch's record and retires records
// older than the previous epoch, which callers still try during rollover.
func (n *Node) ensureRecords(now time.Time) {
	l := n.lst
	cur := epochOf(now)
	if _, ok := l.records[cur]; !ok {
		l.records[cur] = n.signRecord(now, cur)
	}
	for e, t := range l.records {
		if e < cur-1 {
			delete(n.owned, t)
			delete(l.records, e)
			l.holders = slices.DeleteFunc(l.holders, func(h *holder) bool { return h.target == t })
		}
	}
}

func (n *Node) signRecord(now time.Time, epoch int64) krpc.NodeID {
	l := n.lst
	salt := RecordSalt(l.pub, epoch)
	target := MutableTarget(l.pub, salt)
	seq := now.Unix()
	if o := n.owned[target]; o != nil && o.rec.mut != nil {
		seq = max(seq, o.rec.mut.Seq+1)
	}
	m, _ := NewMutable(l.priv, salt, seq, encodeRecord([32]byte(l.x.PublicKey().Bytes())))
	n.owned[target] = &owned{rec: record{v: m.V, mut: &m}, next: now}
	return target
}

// resign republishes every record with a newer sequence number, rebinding
// holders to our current address after a NAT mapping change.
func (n *Node) resign(now time.Time) {
	for e := range n.lst.records {
		n.signRecord(now, e)
	}
}

// recordEpoch reports the epoch of one of our record targets.
func (n *Node) recordEpoch(target krpc.NodeID) (int64, bool) {
	if n.lst == nil {
		return 0, false
	}
	for e, t := range n.lst.records {
		if t == target {
			return e, true
		}
	}
	return 0, false
}

func (n *Node) isRecord(target krpc.NodeID) bool {
	if n.lst == nil {
		return false
	}
	for _, t := range n.lst.records {
		if t == target {
			return true
		}
	}
	return false
}

// recordStored adopts the nodes that acknowledged a record put as holders:
// the closest few, plus a domestic one when domestic copies are on.
func (n *Node) recordStored(now time.Time, l *lookup) {
	if n.lst == nil || !n.isRecord(l.target) {
		return // a publication started by a listener since replaced
	}
	if len(l.acked) == 0 {
		// Nothing stored it, e.g. Listen before Bootstrap or every contact
		// briefly unreachable: retry soon rather than at the next republish.
		n.lst.retry = min(max(2*n.lst.retry, 5*time.Second), time.Minute)
		if o := n.owned[l.target]; o != nil {
			o.next = now.Add(n.lst.retry)
		}
		return
	}
	n.lst.retry = 0
	var picked []*holder
	dom := 0
	for _, a := range l.acked {
		if len(picked) >= maxHolders {
			break
		}
		if len(picked) == maxHolders-1 && n.cfg.Domestic != nil && dom == 0 && !a.domestic {
			continue
		}
		picked = append(picked, &holder{addr: a.addr, target: l.target, token: a.token, domestic: a.domestic})
		if a.domestic {
			dom++
		}
	}
	if len(picked) == 0 {
		return
	}
	n.lst.holders = slices.DeleteFunc(n.lst.holders, func(h *holder) bool { return h.target == l.target })
	n.lst.holders = append(n.lst.holders, picked...)
}

func (n *Node) keepalive(now time.Time) {
	l := n.lst
	if now.Before(l.nextKA) {
		return
	}
	l.nextKA = now.Add(n.cfg.KeepaliveInterval)
	for _, h := range l.holders {
		target := h.target
		n.send(now, h.addr, "get", krpc.Args{Target: &target}, &txn{kind: txKeepalive, holder: h})
	}
	for id, s := range l.sessions {
		if !now.Before(s.expires) {
			delete(l.sessions, id)
		}
	}
	for k, at := range l.seen {
		if now.Sub(at) > 2*offerMaxSkew*time.Second {
			delete(l.seen, k)
		}
	}
}

func (n *Node) keepaliveReply(now time.Time, h *holder, m *krpc.Msg) {
	if n.lst == nil || !slices.Contains(n.lst.holders, h) {
		return
	}
	h.fails = 0
	if m.R.Token != nil {
		h.token = slices.Clone(m.R.Token)
	}
	if m.R.V == nil {
		// The holder lost our record, e.g. it restarted: republish.
		if o := n.owned[h.target]; o != nil {
			o.next = now
		}
	}
	if m.IP.IsValid() {
		if h.mapped.IsValid() && h.mapped != m.IP {
			n.resign(now)
		}
		h.mapped = m.IP
	}
}

func (n *Node) keepaliveFailed(now time.Time, h *holder) {
	if n.lst == nil {
		return
	}
	if h.fails++; h.fails < holderMaxFailures {
		return
	}
	n.lst.holders = slices.DeleteFunc(n.lst.holders, func(x *holder) bool { return x == h })
	live := 0
	for _, x := range n.lst.holders {
		if x.target == h.target {
			live++
		}
	}
	if live < 2 {
		if o := n.owned[h.target]; o != nil {
			o.next = now
		}
	}
}

// acceptOffer decrypts an offer for one of our records.
func (n *Node) acceptOffer(now time.Time, from netip.AddrPort, m *MutableItem) bool {
	l := n.lst
	matched := false
	for _, t := range l.records {
		if saltMatchesRecord(m.Salt, t) {
			matched = true
			break
		}
	}
	if !matched || !fresh(m.Seq, now) || len(l.sessions) >= maxSessions {
		return matched
	}
	if _, dup := l.seen[string(m.Salt)]; dup {
		if s := l.sessions[SessionID(m.Salt[:16])]; s != nil && from != s.via && !slices.Contains(s.relays, from) {
			// Our adopted holders always qualify (few, and known to store the
			// record); unverified sources share a small cap, so replays can't
			// crowd out a genuine retry.
			holder := slices.ContainsFunc(l.holders, func(h *holder) bool { return h.addr == from })
			if holder || s.unverified < maxSessionRelays {
				if !holder {
					s.unverified++
				}
				s.relays = append(s.relays, from)
				if s.answer != nil {
					n.sendAnswer(now, s, from)
				}
			}
		}
		return true
	}
	sealed, ok := decodeString(m.V)
	if !ok || len(sealed) < 32 {
		return true
	}
	ePub, err := ecdh.X25519().NewPublicKey(sealed[:32])
	if err != nil {
		return true
	}
	shared, err := l.x.ECDH(ePub)
	if err != nil {
		return true
	}
	offerKey, answerKey, err := signalKeys(shared, sealed[:32], l.x.PublicKey().Bytes())
	if err != nil {
		return true
	}
	payload, err := open(offerKey, sealed[32:])
	if err != nil {
		return true
	}
	l.seen[string(m.Salt)] = now
	id := SessionID(m.Salt[:16])
	l.sessions[id] = &session{via: from, answerSalt: answerSalt(m.Salt), key: answerKey, expires: now.Add(sessionLifetime)}
	n.events = append(n.events, Incoming{Session: id, Caller: m.Key, Payload: payload})
	return true
}

// Answer replies to an Incoming offer through the holder that relayed it.
func (n *Node) Answer(now time.Time, id SessionID, payload []byte) error {
	if n.lst == nil {
		return ErrNotListening
	}
	if len(payload) > MaxSignalPayload {
		return ErrPayloadTooLarge
	}
	s := n.lst.sessions[id]
	if s == nil || !now.Before(s.expires) || s.answer != nil {
		return ErrUnknownSession
	}
	m, err := NewMutable(n.lst.priv, s.answerSalt, now.Unix(), bencode.AppendBytes(nil, n.seal(s.key, payload)))
	if err != nil {
		return err
	}
	s.answer = &m
	for _, via := range append([]netip.AddrPort{s.via}, s.relays...) {
		n.sendAnswer(now, s, via)
	}
	return nil
}

// sendAnswer sends an answer through the holder that relayed the offer. Any
// replica of our record can relay one, including one whose put
// acknowledgement we lost and so never adopted; without a write token for it
// we fetch one with a get first.
func (n *Node) sendAnswer(now time.Time, s *session, via netip.AddrPort) {
	if tok := n.lst.tokenFor(s, via); tok != nil {
		a := s.answer.args()
		a.Token = tok
		n.send(now, via, "put", a, &txn{kind: txPing})
		return
	}
	for _, target := range n.lst.records {
		t := target
		n.send(now, via, "get", krpc.Args{Target: &t}, &txn{kind: txAnswerToken, session: s})
		return
	}
}

// answerToken completes sendAnswer once a relay hands us a write token.
func (n *Node) answerToken(now time.Time, via netip.AddrPort, m *krpc.Msg, s *session) {
	if n.lst == nil || s == nil || s.answer == nil || m.Y != krpc.Response || len(m.R.Token) == 0 {
		return
	}
	if s.tokens == nil {
		s.tokens = map[netip.AddrPort][]byte{}
	}
	s.tokens[via] = slices.Clone(m.R.Token)
	a := s.answer.args()
	a.Token = m.R.Token
	n.send(now, via, "put", a, &txn{kind: txPing})
}

func (l *listener) tokenFor(s *session, via netip.AddrPort) []byte {
	for _, h := range l.holders {
		if h.addr == via && h.token != nil {
			return h.token
		}
	}
	return s.tokens[via]
}

// ---- caller ----

type signalOp struct {
	op        OpID
	priv      ed25519.PrivateKey
	provider  [32]byte
	payload   []byte
	epoch     int64
	triedPrev bool
	holders   []*cand
	attempt   int
	offer     *MutableItem
	answer    []byte // expected answer salt
	answerKey []byte
	deadline  time.Time // current attempt's answer
	// ackBy is when the current holder must have acknowledged the offer.
	// A dead holder is detected after one round trip, not the whole answer
	// window.
	ackBy time.Time
	acked bool
}

// Signal sends payload to provider through the DHT and returns its answer
// as an Answered event, or SignalFailed. priv signs the offer; the provider
// sees its public key as the caller's identity.
func (n *Node) Signal(now time.Time, priv ed25519.PrivateKey, provider [32]byte, payload []byte) (OpID, error) {
	if len(payload) > MaxSignalPayload {
		return 0, ErrPayloadTooLarge
	}
	if len(n.lookups) >= n.cfg.MaxLookups {
		return 0, ErrBusy
	}
	n.nextOp++
	s := &signalOp{op: n.nextOp, priv: priv, provider: provider, payload: payload, epoch: epochOf(now)}
	n.signals = append(n.signals, s)
	n.findRecord(now, s)
	return s.op, nil
}

func (n *Node) findRecord(now time.Time, s *signalOp) {
	salt := RecordSalt(s.provider, s.epoch)
	key := s.provider
	l := n.startLookup(now, n.primary, getItem, MutableTarget(s.provider, salt), record{}, nil, true)
	if l == nil {
		n.signalFailed(s, ErrBusy)
		return
	}
	l.key, l.salt = &key, salt
	l.onDone = func(now time.Time, l *lookup) { n.recordFound(now, s, l) }
	n.step(now, l)
}

func (n *Node) recordFound(now time.Time, s *signalOp, l *lookup) {
	x, ok := [32]byte{}, false
	if l.best != nil {
		x, ok = decodeRecord(l.best.V)
	}
	if !ok {
		if !s.triedPrev {
			s.triedPrev = true
			s.epoch--
			n.findRecord(now, s)
			return
		}
		n.signalFailed(s, ErrNoRecord)
		return
	}
	for _, c := range l.holders {
		if c.token != nil {
			s.holders = append(s.holders, c)
		}
	}
	if len(s.holders) == 0 {
		n.signalFailed(s, ErrNoRecord)
		return
	}
	xPub, err := ecdh.X25519().NewPublicKey(x[:])
	if err != nil {
		n.signalFailed(s, ErrNoRecord)
		return
	}
	e, _ := ecdh.X25519().NewPrivateKey(n.randBytes(32))
	shared, err := e.ECDH(xPub)
	if err != nil {
		n.signalFailed(s, ErrNoRecord)
		return
	}
	ePub := e.PublicKey().Bytes()
	offerKey, answerKey, err := signalKeys(shared, ePub, x[:])
	if err != nil {
		n.signalFailed(s, err)
		return
	}
	salt := offerSalt(n.randBytes(16), l.target)
	sealed := append(slices.Clone(ePub), n.seal(offerKey, s.payload)...)
	m, err := NewMutable(s.priv, salt, now.Unix(), bencode.AppendBytes(nil, sealed))
	if err != nil {
		n.signalFailed(s, err)
		return
	}
	s.offer, s.answer, s.answerKey = &m, answerSalt(salt), answerKey
	n.sendOffer(now, s)
}

func (n *Node) sendOffer(now time.Time, s *signalOp) {
	if s.attempt >= len(s.holders) {
		n.signalFailed(s, ErrNoAnswer)
		return
	}
	h := s.holders[s.attempt]
	a := s.offer.args()
	a.Token = h.token
	n.send(now, h.addr, "put", a, &txn{kind: txOffer, signal: s, attempt: s.attempt})
	s.deadline = now.Add(signalAttemptTimeout)
	s.ackBy, s.acked = now.Add(n.cfg.ShortTimeout), false
}

func (n *Node) offerAcked(s *signalOp, attempt int, ok bool) {
	if s.attempt == attempt && ok {
		s.acked = true
	}
}

// acceptAnswer completes a pending Signal whose answer salt matches.
func (n *Node) acceptAnswer(now time.Time, from netip.AddrPort, m *MutableItem) bool {
	for _, s := range n.signals {
		if s.offer == nil || string(m.Salt) != string(s.answer) {
			continue
		}
		if m.Key != s.provider {
			return true // forged: wrong signer
		}
		sealed, ok := decodeString(m.V)
		if !ok {
			return true
		}
		payload, err := open(s.answerKey, sealed)
		if err != nil {
			return true
		}
		n.events = append(n.events, Answered{Op: s.op, Provider: s.provider, Payload: payload, Via: from})
		n.removeSignal(s)
		return true
	}
	return false
}

func (n *Node) signalFailed(s *signalOp, err error) {
	n.events = append(n.events, SignalFailed{Op: s.op, Err: err})
	n.removeSignal(s)
}

func (n *Node) removeSignal(s *signalOp) {
	n.signals = slices.DeleteFunc(n.signals, func(x *signalOp) bool { return x == s })
}

func (n *Node) signalTimeouts(now time.Time) {
	for _, s := range slices.Clone(n.signals) {
		if s.offer != nil && (!now.Before(s.deadline) || (!s.acked && !now.Before(s.ackBy))) {
			s.attempt++
			n.sendOffer(now, s)
		}
	}
}

// handleSignal intercepts signaling puts addressed to us, before the
// read-only check: phones are read-only yet must receive forwarded offers
// and answers.
func (n *Node) handleSignal(now time.Time, from netip.AddrPort, q *krpc.Msg) bool {
	if q.Q != "put" || len(q.A.Salt) != 32 || len(q.A.K) != 32 || len(q.A.Sig) != 64 || q.A.Seq == nil {
		return false
	}
	m := &MutableItem{Key: [32]byte(q.A.K), Salt: q.A.Salt, Seq: *q.A.Seq, V: q.A.V, Sig: [64]byte(q.A.Sig)}
	pending := len(n.signals) > 0
	listening := n.lst != nil
	if !pending && !listening {
		return false
	}
	if !m.Verify() {
		return false
	}
	if pending && n.acceptAnswer(now, from, m) {
		return true
	}
	return listening && n.acceptOffer(now, from, m)
}

// Holders reports the record holders a listening provider keeps alive.
func (n *Node) Holders() []netip.AddrPort {
	if n.lst == nil {
		return nil
	}
	var out []netip.AddrPort
	for _, h := range n.lst.holders {
		out = append(out, h.addr)
	}
	return out
}
