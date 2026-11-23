package endpoint

import (
	"errors"
	"slices"
)

// ErrRefusing is returned by Connect while the endpoint refuses new
// connections (see SetRefusing).
var ErrRefusing = errors.New("endpoint: refusing new connections")

// The methods below let a memory monitor reclaim what warren holds, the way
// a mobile VPN sheds its own connections under pressure (radiance's memmon:
// close the oldest connections first, then all of them, and refuse new
// ones until pressure recedes). A connection's memory is mostly its
// protocol's receive buffers (hysteria2's QUIC windows), freed when the
// layer above sees the Conn close; the DHT itself is a fraction of a MiB
// and keeps running, so the endpoint stays reachable.

// Connections reports how many connections are open, inbound and outbound,
// including inbound ones not yet accepted.
func (e *Endpoint) Connections() int {
	e.connsMu.Lock()
	defer e.connsMu.Unlock()
	return len(e.all)
}

// CloseOldest closes up to n open connections, oldest first, and reports
// how many it closed.
func (e *Endpoint) CloseOldest(n int) int {
	if n <= 0 {
		return 0
	}
	e.connsMu.Lock()
	conns := make([]*Conn, 0, len(e.all))
	for c := range e.all {
		conns = append(conns, c)
	}
	e.connsMu.Unlock()
	slices.SortFunc(conns, func(a, b *Conn) int { return a.created.Compare(b.created) })
	conns = conns[:min(n, len(conns))]
	for _, c := range conns {
		_ = c.Close()
	}
	return len(conns)
}

// CloseAll closes every open connection and reports how many it closed.
// The DHT keeps running, and so does listening.
func (e *Endpoint) CloseAll() int {
	return e.CloseOldest(int(^uint(0) >> 1))
}

// SetRefusing turns refusing new connections on or off. While on, Connect
// fails with ErrRefusing and a caller's offer is answered at once, empty,
// so it fails fast instead of waiting out signaling. A punch already in
// flight when refusing begins doesn't add its connection either (its
// socket is closed, and Connect fails with ErrRefusing), so a CloseAll
// after SetRefusing(true) leaves none. Live connections keep migrating: a
// resume moves a session that already exists.
func (e *Endpoint) SetRefusing(on bool) {
	e.connsMu.Lock() // ordered against newConn's registration
	e.refusing.Store(on)
	e.connsMu.Unlock()
}
