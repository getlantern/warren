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
	// Relay is a DHT router both sides bind to as a fallback, chosen by the
	// initiator.
	Relay netip.AddrPort
}

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
	if len(o.Secret) > 0 {
		b = bencode.AppendString(b, "s")
		b = bencode.AppendBytes(b, o.Secret)
	}
	return append(b, 'e')
}

func UnmarshalOffer(b []byte) (Offer, error) {
	var o Offer
	v, err := bencode.Decode(b)
	if err != nil || v.Kind != bencode.Dict {
		return o, ErrBadOffer
	}
	if c, ok := v.Get("c"); ok && c.Kind == bencode.List {
		for _, item := range c.List[:min(len(c.List), maxCandidates)] {
			if a, ok := krpc.ParseCompactAddr(item.Str); ok && a.Port() != 0 {
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
		o.Relay, _ = krpc.ParseCompactAddr(r.Str)
	}
	if sec, ok := v.Get("s"); ok && sec.Kind == bencode.String {
		o.Secret = append([]byte(nil), sec.Str...)
	}
	return o, nil
}
