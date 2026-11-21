// Package punch is a sans-IO UDP hole-punching engine. A Session owns a set
// of numbered sockets that its runner opens; it consumes datagrams and time
// and produces datagrams to send and events, like package dht.
//
// Probes are ordinary KRPC pings whose node IDs are derived from a secret
// exchanged through encrypted DHT signaling, so a punch looks like two DHT
// nodes pinging each other and probes cannot be forged.
package punch

import (
	"errors"
	"net/netip"

	"github.com/getlantern/warren/bencode"
	"github.com/getlantern/warren/krpc"
)

type Mapping uint8

const (
	MappingUnknown Mapping = iota
	MappingIndependent
	MappingDependent
)

type Allocation uint8

const (
	AllocUnknown Allocation = iota
	AllocSequential
	AllocBlock
	AllocRandom
)

// Profile is one side's measured NAT behavior (see package natprobe).
type Profile struct {
	Mapping    Mapping
	Allocation Allocation
	// Step is a sequential allocator's per-mapping increment.
	Step uint16
	// BlockLo and BlockHi bound a port-block allocator's range.
	BlockLo, BlockHi uint16
}

// Offer is what each side sends through signaling: its candidate addresses
// and NAT profile. The initiator also supplies the session secret.
type Offer struct {
	Secret     []byte
	Candidates []netip.AddrPort
	Profile    Profile
	// Relays are the initiator's relay candidates, in preference order.
	Relays []netip.AddrPort
	// Relay, in the responder's answer, is the relay it chose (one of Relays,
	// or a router of its own when it keeps its address private); both sides
	// bind to it.
	Relay netip.AddrPort
}

const maxRelays = 8

const maxCandidates = 8

var ErrBadOffer = errors.New("punch: malformed offer")

func (o *Offer) Marshal() []byte {
	b := []byte{'d'}
	b = bencode.AppendString(b, "c")
	var c []byte
	for _, a := range o.Candidates[:min(len(o.Candidates), maxCandidates)] {
		c = bencode.AppendBytes(c, krpc.AppendCompactAddr(nil, a))
	}
	b = append(b, 'l')
	b = append(b, c...)
	b = append(b, 'e')
	b = bencode.AppendString(b, "p")
	p := o.Profile
	b = bencode.AppendBytes(b, []byte{byte(p.Mapping), byte(p.Allocation), byte(p.Step >> 8), byte(p.Step),
		byte(p.BlockLo >> 8), byte(p.BlockLo), byte(p.BlockHi >> 8), byte(p.BlockHi)})
	if o.Relay.IsValid() {
		b = bencode.AppendString(b, "r")
		b = bencode.AppendBytes(b, krpc.AppendCompactAddr(nil, o.Relay))
	}
	if len(o.Relays) > 0 {
		b = bencode.AppendString(b, "rs")
		b = append(b, 'l')
		for _, r := range o.Relays[:min(len(o.Relays), maxRelays)] {
			b = bencode.AppendBytes(b, krpc.AppendCompactAddr(nil, r))
		}
		b = append(b, 'e')
	}
	if len(o.Secret) > 0 {
		b = bencode.AppendString(b, "s")
		b = bencode.AppendBytes(b, o.Secret)
	}
	return append(b, 'e')
}

// parseAddr reads a compact address in canonical form: IPv4-mapped
// addresses (an 18-byte encoding of an IPv4 peer) are unmapped, so they
// compare equal to what sockets report, and port 0 is rejected.
func parseAddr(b []byte) (netip.AddrPort, bool) {
	a, ok := krpc.ParseCompactAddr(b)
	if !ok || a.Port() == 0 {
		return netip.AddrPort{}, false
	}
	return unmapAddr(a), true
}

func UnmarshalOffer(b []byte) (Offer, error) {
	var o Offer
	v, err := bencode.Decode(b)
	if err != nil || v.Kind != bencode.Dict {
		return o, ErrBadOffer
	}
	if c, ok := v.Get("c"); ok && c.Kind == bencode.List {
		for _, item := range c.List[:min(len(c.List), maxCandidates)] {
			if a, ok := parseAddr(item.Str); ok {
				o.Candidates = append(o.Candidates, a)
			}
		}
	}
	p, ok := v.Get("p")
	if !ok || len(p.Str) != 8 {
		return o, ErrBadOffer
	}
	s := p.Str
	o.Profile = Profile{
		Mapping: Mapping(s[0]), Allocation: Allocation(s[1]),
		Step:    uint16(s[2])<<8 | uint16(s[3]),
		BlockLo: uint16(s[4])<<8 | uint16(s[5]), BlockHi: uint16(s[6])<<8 | uint16(s[7]),
	}
	if r, ok := v.Get("r"); ok && r.Kind == bencode.String {
		o.Relay, _ = parseAddr(r.Str)
	}
	if rs, ok := v.Get("rs"); ok && rs.Kind == bencode.List {
		for _, item := range rs.List[:min(len(rs.List), maxRelays)] {
			if a, ok := parseAddr(item.Str); ok {
				o.Relays = append(o.Relays, a)
			}
		}
	}
	if sec, ok := v.Get("s"); ok && sec.Kind == bencode.String {
		o.Secret = append([]byte(nil), sec.Str...)
	}
	return o, nil
}
