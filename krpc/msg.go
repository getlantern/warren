// Package krpc encodes and decodes Mainline DHT messages: BEP 5 plus the
// extensions this project relies on (BEP 32 dual-stack, BEP 42 observed
// address, BEP 43 read-only, BEP 44 storage).
package krpc

import (
	"errors"
	"net/netip"
	"strconv"

	"github.com/getlantern/warren/bencode"
)

const (
	Query    = 'q'
	Response = 'r'
	Err      = 'e'
)

// Standard KRPC error codes.
const (
	ErrGeneric       = 201
	ErrServer        = 202
	ErrProtocol      = 203
	ErrMethodUnknown = 204
)

var ErrMalformed = errors.New("krpc: malformed message")

// Msg's byte-slice fields alias the decoded datagram.
type Msg struct {
	T  []byte
	Y  byte
	Q  string
	V  []byte // client version, e.g. "LT\x01\x02"
	RO bool   // BEP 43
	// IP is the recipient's address as observed by the sender (BEP 42),
	// typically present in responses.
	IP netip.AddrPort
	A  Args
	R  Return
	E  *Error
}

type Args struct {
	ID          NodeID
	Target      *NodeID // find_node, get
	InfoHash    *NodeID // get_peers, announce_peer
	Token       []byte
	Port        int
	ImpliedPort bool
	Want        []string // BEP 32: "n4", "n6"

	// BEP 44 put.
	V    []byte // raw bencoded value
	K    []byte // 32-byte ed25519 public key
	Sig  []byte // 64-byte signature
	Salt []byte
	Seq  *int64
	CAS  *int64
}

type Return struct {
	ID     NodeID
	Nodes  []NodeInfo
	Nodes6 []NodeInfo
	// P is the requester's observed port. libtorrent adds it to every
	// response alongside the top-level "ip" field.
	P      int
	Values []netip.AddrPort
	Token  []byte

	// BEP 44 get.
	V   []byte
	K   []byte
	Sig []byte
	Seq *int64
}

type Error struct {
	Code int
	Msg  string
}

func (e *Error) Error() string { return "krpc error " + strconv.Itoa(e.Code) + ": " + e.Msg }

// AppendMarshal encodes m, writing every dictionary in canonical key order.
func AppendMarshal(b []byte, m *Msg) []byte {
	b = append(b, 'd')
	if m.Y == Query {
		b = bencode.AppendString(b, "a")
		b = appendArgs(b, &m.A)
	}
	if m.Y == Err && m.E != nil {
		b = bencode.AppendString(b, "e")
		b = append(b, 'l')
		b = bencode.AppendInt(b, int64(m.E.Code))
		b = bencode.AppendString(b, m.E.Msg)
		b = append(b, 'e')
	}
	if m.IP.IsValid() {
		b = bencode.AppendString(b, "ip")
		b = bencode.AppendBytes(b, AppendCompactAddr(nil, m.IP))
	}
	if m.Y == Query {
		b = bencode.AppendString(b, "q")
		b = bencode.AppendString(b, m.Q)
	}
	if m.Y == Response {
		b = bencode.AppendString(b, "r")
		b = appendReturn(b, &m.R)
	}
	if m.RO {
		b = bencode.AppendString(b, "ro")
		b = bencode.AppendInt(b, 1)
	}
	b = bencode.AppendString(b, "t")
	b = bencode.AppendBytes(b, m.T)
	if len(m.V) > 0 {
		b = bencode.AppendString(b, "v")
		b = bencode.AppendBytes(b, m.V)
	}
	b = bencode.AppendString(b, "y")
	b = bencode.AppendBytes(b, []byte{m.Y})
	return append(b, 'e')
}

func appendArgs(b []byte, a *Args) []byte {
	b = append(b, 'd')
	if a.CAS != nil {
		b = bencode.AppendString(b, "cas")
		b = bencode.AppendInt(b, *a.CAS)
	}
	b = bencode.AppendString(b, "id")
	b = bencode.AppendBytes(b, a.ID[:])
	if a.ImpliedPort {
		b = bencode.AppendString(b, "implied_port")
		b = bencode.AppendInt(b, 1)
	}
	if a.InfoHash != nil {
		b = bencode.AppendString(b, "info_hash")
		b = bencode.AppendBytes(b, a.InfoHash[:])
	}
	if a.K != nil {
		b = bencode.AppendString(b, "k")
		b = bencode.AppendBytes(b, a.K)
	}
	if a.Port != 0 {
		b = bencode.AppendString(b, "port")
		b = bencode.AppendInt(b, int64(a.Port))
	}
	if a.Salt != nil {
		b = bencode.AppendString(b, "salt")
		b = bencode.AppendBytes(b, a.Salt)
	}
	if a.Seq != nil {
		b = bencode.AppendString(b, "seq")
		b = bencode.AppendInt(b, *a.Seq)
	}
	if a.Sig != nil {
		b = bencode.AppendString(b, "sig")
		b = bencode.AppendBytes(b, a.Sig)
	}
	if a.Target != nil {
		b = bencode.AppendString(b, "target")
		b = bencode.AppendBytes(b, a.Target[:])
	}
	if a.Token != nil {
		b = bencode.AppendString(b, "token")
		b = bencode.AppendBytes(b, a.Token)
	}
	if a.V != nil {
		b = bencode.AppendString(b, "v")
		b = append(b, a.V...)
	}
	if len(a.Want) > 0 {
		b = bencode.AppendString(b, "want")
		b = append(b, 'l')
		for _, w := range a.Want {
			b = bencode.AppendString(b, w)
		}
		b = append(b, 'e')
	}
	return append(b, 'e')
}

func appendReturn(b []byte, r *Return) []byte {
	b = append(b, 'd')
	b = bencode.AppendString(b, "id")
	b = bencode.AppendBytes(b, r.ID[:])
	if r.K != nil {
		b = bencode.AppendString(b, "k")
		b = bencode.AppendBytes(b, r.K)
	}
	if r.Nodes != nil {
		b = bencode.AppendString(b, "nodes")
		b = bencode.AppendBytes(b, appendCompactNodes(nil, r.Nodes))
	}
	if r.Nodes6 != nil {
		b = bencode.AppendString(b, "nodes6")
		b = bencode.AppendBytes(b, appendCompactNodes(nil, r.Nodes6))
	}
	if r.P != 0 {
		b = bencode.AppendString(b, "p")
		b = bencode.AppendInt(b, int64(r.P))
	}
	if r.Seq != nil {
		b = bencode.AppendString(b, "seq")
		b = bencode.AppendInt(b, *r.Seq)
	}
	if r.Sig != nil {
		b = bencode.AppendString(b, "sig")
		b = bencode.AppendBytes(b, r.Sig)
	}
	if r.Token != nil {
		b = bencode.AppendString(b, "token")
		b = bencode.AppendBytes(b, r.Token)
	}
	if r.V != nil {
		b = bencode.AppendString(b, "v")
		b = append(b, r.V...)
	}
	if r.Values != nil {
		b = bencode.AppendString(b, "values")
		b = append(b, 'l')
		for _, v := range r.Values {
			b = bencode.AppendBytes(b, AppendCompactAddr(nil, v))
		}
		b = append(b, 'e')
	}
	return append(b, 'e')
}

// Unmarshal decodes a datagram. Unknown keys are ignored, as in every
// deployed implementation; required fields that are absent or the wrong
// shape are errors.
func Unmarshal(b []byte, m *Msg) error {
	v, err := bencode.Decode(b)
	if err != nil {
		return err
	}
	if v.Kind != bencode.Dict {
		return ErrMalformed
	}
	*m = Msg{}
	t, ok := v.Get("t")
	if !ok || t.Kind != bencode.String {
		return ErrMalformed
	}
	m.T = t.Str
	y, ok := v.Get("y")
	if !ok || y.Kind != bencode.String || len(y.Str) != 1 {
		return ErrMalformed
	}
	m.Y = y.Str[0]
	if s, ok := str(v, "v"); ok {
		m.V = s
	}
	if ro, ok := v.Get("ro"); ok && ro.Kind == bencode.Int && ro.Int == 1 {
		m.RO = true
	}
	if s, ok := str(v, "ip"); ok {
		m.IP, _ = ParseCompactAddr(s)
	}
	switch m.Y {
	case Query:
		q, ok := str(v, "q")
		if !ok {
			return ErrMalformed
		}
		m.Q = string(q)
		a, ok := v.Get("a")
		if !ok || a.Kind != bencode.Dict {
			return ErrMalformed
		}
		return parseArgs(a, &m.A)
	case Response:
		r, ok := v.Get("r")
		if !ok || r.Kind != bencode.Dict {
			return ErrMalformed
		}
		return parseReturn(r, &m.R)
	case Err:
		e, ok := v.Get("e")
		if !ok || e.Kind != bencode.List || len(e.List) < 2 ||
			e.List[0].Kind != bencode.Int || e.List[1].Kind != bencode.String {
			return ErrMalformed
		}
		m.E = &Error{Code: int(e.List[0].Int), Msg: string(e.List[1].Str)}
		return nil
	}
	return ErrMalformed
}

func parseArgs(a bencode.Value, out *Args) error {
	id, ok := nodeID(a, "id")
	if !ok {
		return ErrMalformed
	}
	out.ID = *id
	out.Target, _ = nodeID(a, "target")
	out.InfoHash, _ = nodeID(a, "info_hash")
	out.Token, _ = str(a, "token")
	if p, ok := a.Get("port"); ok && p.Kind == bencode.Int && p.Int > 0 && p.Int < 65536 {
		out.Port = int(p.Int)
	}
	if ip, ok := a.Get("implied_port"); ok && ip.Kind == bencode.Int && ip.Int != 0 {
		out.ImpliedPort = true
	}
	if w, ok := a.Get("want"); ok && w.Kind == bencode.List {
		for _, item := range w.List {
			if item.Kind == bencode.String {
				out.Want = append(out.Want, string(item.Str))
			}
		}
	}
	if v, ok := a.Get("v"); ok {
		out.V = v.Raw
	}
	out.K, _ = str(a, "k")
	out.Sig, _ = str(a, "sig")
	out.Salt, _ = str(a, "salt")
	out.Seq = integer(a, "seq")
	out.CAS = integer(a, "cas")
	return nil
}

func parseReturn(r bencode.Value, out *Return) error {
	id, ok := nodeID(r, "id")
	if !ok {
		return ErrMalformed
	}
	out.ID = *id
	if s, ok := str(r, "nodes"); ok {
		out.Nodes = parseCompactNodes(s, compactNode4)
	}
	if s, ok := str(r, "nodes6"); ok {
		out.Nodes6 = parseCompactNodes(s, compactNode6)
	}
	if vals, ok := r.Get("values"); ok && vals.Kind == bencode.List {
		for _, item := range vals.List {
			if item.Kind != bencode.String {
				continue
			}
			if ap, ok := ParseCompactAddr(item.Str); ok {
				out.Values = append(out.Values, ap)
			}
		}
	}
	out.Token, _ = str(r, "token")
	if p, ok := r.Get("p"); ok && p.Kind == bencode.Int && p.Int > 0 && p.Int < 65536 {
		out.P = int(p.Int)
	}
	if v, ok := r.Get("v"); ok {
		out.V = v.Raw
	}
	out.K, _ = str(r, "k")
	out.Sig, _ = str(r, "sig")
	out.Seq = integer(r, "seq")
	return nil
}

func str(d bencode.Value, key string) ([]byte, bool) {
	v, ok := d.Get(key)
	if !ok || v.Kind != bencode.String {
		return nil, false
	}
	return v.Str, true
}

func integer(d bencode.Value, key string) *int64 {
	v, ok := d.Get(key)
	if !ok || v.Kind != bencode.Int {
		return nil
	}
	n := v.Int
	return &n
}

func nodeID(d bencode.Value, key string) (*NodeID, bool) {
	s, ok := str(d, key)
	if !ok || len(s) != 20 {
		return nil, false
	}
	id := NodeID(s)
	return &id, true
}
