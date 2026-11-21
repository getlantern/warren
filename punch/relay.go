package punch

import (
	"crypto/hmac"
	"crypto/sha256"
	"net/netip"
	"time"

	"github.com/getlantern/warren/krpc"
)

// Relay fallback: both sides bind socket 0 to the initiator's chosen DHT
// router with get_peers then announce_peer on a secret-derived info-hash.
// The router pairs the two announcers and forwards non-KRPC datagrams
// between them. Probes through it are 20-byte datagrams shaped like a uTP
// ST_SYN (and ST_STATE for the reply) whose remaining bytes are a MAC, so
// the router forwards them like any uTP traffic and only the peer can
// produce them.

const (
	relayRetry      = 500 * time.Millisecond
	relayProbeEvery = 100 * time.Millisecond
	relayProbeLen   = 20
)

func relayMAC(secret []byte, label string, typ byte) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("warren/punch/v1 relay " + label))
	out := make([]byte, relayProbeLen)
	out[0] = typ<<4 | 1 // uTP version 1
	copy(out[2:], m.Sum(nil))
	return out
}

func (s *Session) startRelay(now time.Time, secret []byte, me, peer string) {
	h := sha256.Sum256(append([]byte("warren/punch/v1 relay info-hash "), secret...))
	s.relayInfo = krpc.NodeID(h[:20])
	s.relayProbe, s.relayAck = relayMAC(secret, "probe "+me, 4), relayMAC(secret, "ack "+me, 2)
	s.peerProbe, s.peerAck = relayMAC(secret, "probe "+peer, 4), relayMAC(secret, "ack "+peer, 2)
	s.relayFrom = now
	if s.strategy != Relay {
		// A direct path wins if one exists; fall back halfway to the deadline.
		s.relayFrom = now.Add(s.cfg.Deadline / 2)
	}
	s.nextRelay = now
}

func (s *Session) tickRelay(now time.Time) {
	if !s.relay.IsValid() || s.nominating || now.Before(s.nextRelay) {
		return
	}
	switch {
	case s.relayToken == nil:
		info := s.relayInfo
		s.relayT[s.query0("get_peers", krpc.Args{InfoHash: &info})] = true
		s.nextRelay = now.Add(relayRetry)
	case !s.relayBound:
		info := s.relayInfo
		s.relayT[s.query0("announce_peer", krpc.Args{InfoHash: &info, Token: s.relayToken, Port: 6881, ImpliedPort: true})] = true
		s.nextRelay = now.Add(relayRetry)
	case now.Before(s.relayFrom):
		s.nextRelay = s.relayFrom
	case s.cfg.Initiator:
		s.sends = append(s.sends, Send{Socket: 0, To: s.relay, Data: s.relayProbe})
		s.nextRelay = now.Add(relayProbeEvery)
	default:
		s.nextRelay = s.deadline // the responder waits for the initiator's probe
	}
}

// query0 sends a KRPC query from socket 0 with the gathering node ID.
func (s *Session) query0(q string, a krpc.Args) uint16 {
	a.ID = s.gatherID
	return s.queryArgs(0, s.relay, q, a)
}

func (s *Session) relayReply(now time.Time, m *krpc.Msg) {
	switch {
	case m.Y != krpc.Response:
	case s.relayToken == nil && len(m.R.Token) > 0:
		s.relayToken = append([]byte(nil), m.R.Token...)
		s.nextRelay = now
	case s.relayToken != nil:
		s.relayBound = true
		s.nextRelay = now
	}
}

// relayData handles non-KRPC datagrams arriving on socket 0 from the relay.
func (s *Session) relayData(socket int, from netip.AddrPort, b []byte) {
	if !s.started || socket != 0 || from != s.relay || len(b) != relayProbeLen {
		return
	}
	switch {
	case !s.cfg.Initiator && hmac.Equal(b, s.peerProbe):
		s.sends = append(s.sends, Send{Socket: 0, To: s.relay, Data: s.relayAck})
		if !s.done {
			s.connectRelayed()
		}
	case s.cfg.Initiator && !s.done && hmac.Equal(b, s.peerAck):
		s.connectRelayed()
	}
}

func (s *Session) connectRelayed() {
	s.done, s.selected = true, pair{0, s.relay}
	s.events = append(s.events, Connected{Socket: 0, Remote: s.relay, Strategy: Relay, Probes: s.probes, Relayed: true})
}
