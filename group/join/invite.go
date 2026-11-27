// Package join is how a device joins a group, or rejoins one after being
// away past the grace window, by invite (docs/groups-design.md, *Invites*).
//
// An admin issues an Invite: an invite key whose private half it keeps, a
// random invite secret I, an expiry, the group's name, and bootstrap hints,
// handed to the joiner out of band as a link. It carries neither G nor any
// member key. The admin listens under the invite key blinded per period
// with I, which the joiner computes from the link; over that connection the
// two run a join session (Serve and Join), which carries only the request
// and its answer and serves no member data.
package join

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net/netip"
	"strings"
	"time"

	"github.com/getlantern/warren/bencode"
	"github.com/getlantern/warren/group/keys"
	"github.com/getlantern/warren/group/roster"
)

// MaxHints bounds an invite's bootstrap hints.
const MaxHints = 16

const linkPrefix = "warren-invite:1:"

// ErrBadLink means a link that doesn't parse as an invite.
var ErrBadLink = errors.New("join: bad invite link")

// Invite is what a joiner is handed.
type Invite struct {
	Key     keys.PublicKey // the invite key's public half
	Secret  [32]byte       // the invite secret I
	Expires int64          // Unix seconds
	Name    string         // the group's display name
	Hints   []netip.AddrPort
}

// Listener is the key the admin listens under for this invite in period p:
// the invite key blinded with I, so it can't be linked to the invite key
// without the link.
func (iv Invite) Listener(p uint64) (keys.PublicKey, error) {
	return iv.Key.Blind(keys.InviteBlind(iv.Secret, p))
}

// Link encodes the invite as a string for a link or a QR code.
func (iv Invite) Link() string {
	hints := bencode.Value{Kind: bencode.List}
	for _, h := range iv.Hints {
		b, _ := h.MarshalBinary()
		hints.List = append(hints.List, bencode.Value{Kind: bencode.String, Str: b})
	}
	str := func(b []byte) bencode.Value { return bencode.Value{Kind: bencode.String, Str: b} }
	d := bencode.Value{Kind: bencode.Dict, Dict: []bencode.Pair{
		{Key: []byte("e"), Value: bencode.Value{Kind: bencode.Int, Int: iv.Expires}},
		{Key: []byte("h"), Value: hints},
		{Key: []byte("i"), Value: str(iv.Key[:])},
		{Key: []byte("n"), Value: str([]byte(iv.Name))},
		{Key: []byte("s"), Value: str(iv.Secret[:])},
	}}
	return linkPrefix + base64.RawURLEncoding.EncodeToString(bencode.Append(nil, d))
}

// ParseLink decodes a link made by Link.
func ParseLink(s string) (Invite, error) {
	var iv Invite
	rest, ok := strings.CutPrefix(s, linkPrefix)
	if !ok {
		return iv, ErrBadLink
	}
	raw, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil || len(raw) > 4096 {
		return iv, ErrBadLink
	}
	v, err := bencode.DecodeLimit(raw, 64)
	if err != nil || v.Kind != bencode.Dict {
		return iv, ErrBadLink
	}
	get := func(k string, kind bencode.Kind) (bencode.Value, bool) {
		x, ok := v.Get(k)
		return x, ok && x.Kind == kind
	}
	e, okE := get("e", bencode.Int)
	h, okH := get("h", bencode.List)
	i, okI := get("i", bencode.String)
	n, okN := get("n", bencode.String)
	sec, okS := get("s", bencode.String)
	if !okE || !okH || !okI || !okN || !okS || len(v.Dict) != 5 ||
		e.Int <= 0 || len(i.Str) != 32 || len(sec.Str) != 32 || len(n.Str) > roster.MaxName || len(h.List) > MaxHints {
		return iv, ErrBadLink
	}
	iv.Expires, iv.Name = e.Int, string(n.Str)
	copy(iv.Key[:], i.Str)
	copy(iv.Secret[:], sec.Str)
	if iv.Key.Valid() != nil {
		return iv, ErrBadLink
	}
	for _, x := range h.List {
		var a netip.AddrPort
		if x.Kind != bencode.String || a.UnmarshalBinary(x.Str) != nil || !a.IsValid() {
			return iv, ErrBadLink
		}
		iv.Hints = append(iv.Hints, a)
	}
	return iv, nil
}

// Issued is an invite with the admin's private half: the invite key it
// listens under. The admin keeps it until the invite is spent or expires.
type Issued struct {
	Invite Invite
	Key    *keys.Identity
}

// Listener is the signer the admin listens under in period p (see
// Invite.Listener).
func (is *Issued) Listener(p uint64) keys.Signer {
	return is.Key.Blind(keys.InviteBlind(is.Invite.Secret, p))
}

// Issue makes an invite admitting up to uses joiners and rejoiners for ttl,
// and records it in w's roster with an invite operation, which it returns
// for the caller to share with members. w.Me must be an owner or admin.
// random defaults to crypto/rand.
func Issue(w *roster.Writer, uses uint32, ttl time.Duration, hints []netip.AddrPort, random io.Reader) (*Issued, *roster.Op, error) {
	if random == nil {
		random = rand.Reader
	}
	if len(hints) > MaxHints || ttl <= 0 {
		return nil, nil, roster.ErrNotAllowed
	}
	key, err := keys.NewIdentity(random)
	if err != nil {
		return nil, nil, err
	}
	var secret [32]byte
	if _, err := io.ReadFull(random, secret[:]); err != nil {
		return nil, nil, err
	}
	now := time.Now()
	if w.Now != nil {
		now = w.Now()
	}
	expires := now.Add(ttl).Unix()
	op, err := w.Invite(key.Public(), uses, expires)
	if err != nil {
		return nil, nil, err
	}
	iv := Invite{Key: key.Public(), Secret: secret, Expires: expires, Name: w.R.Op(w.R.Group()).Name, Hints: hints}
	return &Issued{Invite: iv, Key: key}, op, nil
}
