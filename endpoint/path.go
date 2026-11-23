package endpoint

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/getlantern/warren/utpshape"
)

// path is a Conn's view of the network: one socket and the peer's real
// address on it, both of which Migrate can replace. Everything above (the
// application, hysteria2, QUIC) sees a fixed peer address, the Conn's
// Remote, so a session survives moving onto a new punched path without
// knowing it moved.
type path struct {
	mu            sync.Mutex
	sock          *net.UDPConn
	real          netip.AddrPort // the peer's address on sock
	gen           int            // bumped on every swap
	seq           uint64         // the migration that installed this path
	closed        bool
	readDeadline  time.Time
	writeDeadline time.Time
	// waiting is when the first datagram that expects an answer went out
	// since the peer was last heard from (Unix nanoseconds), or zero: how
	// long the peer has been silent while we expected an answer. lastRecv
	// is when the peer was last heard from.
	waiting  atomic.Int64
	lastRecv atomic.Int64
	// testHookWrite, if set, runs between a write choosing its socket and
	// sending, so tests can swap the path in that window.
	testHookWrite func()
	// testDrop, if set, silently drops writes on that socket, as a path
	// that died without an error would.
	testDrop atomic.Pointer[net.UDPConn]
}

func newPath(sock *net.UDPConn, real netip.AddrPort) *path {
	utpshape.SetDontFragment(sock)
	return &path{sock: sock, real: real}
}

// swap moves the path onto sock, closing the old socket, if seq is newer
// than the migration that installed the current path: a slow resume can't
// overwrite a newer one. A read blocked on the old socket wakes and
// continues on the new one.
func (p *path) swap(seq uint64, sock *net.UDPConn, real netip.AddrPort) bool {
	p.mu.Lock()
	if p.closed || seq <= p.seq {
		p.mu.Unlock()
		return false
	}
	old := p.sock
	p.sock, p.real, p.seq = sock, real, seq
	p.gen++
	// A fresh path starts unjudged. lastRecv carries over: an acknowledgment
	// of what arrived on the old path can still go out on the new one.
	p.waiting.Store(0)
	utpshape.SetDontFragment(sock)
	_ = sock.SetReadDeadline(p.readDeadline)
	_ = sock.SetWriteDeadline(p.writeDeadline)
	p.mu.Unlock()
	old.Close()
	return true
}

func (p *path) current() (*net.UDPConn, netip.AddrPort, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sock, p.real, p.gen
}

// read returns the next datagram from the peer's real address, skipping
// strangers, and follows the path across swaps.
func (p *path) read(b []byte) (int, error) {
	for {
		sock, real, gen := p.current()
		n, from, err := sock.ReadFromUDPAddrPort(b)
		if err != nil {
			p.mu.Lock()
			swapped, closed := p.gen != gen, p.closed
			p.mu.Unlock()
			if swapped && !closed {
				continue // the socket was replaced under us
			}
			return 0, err
		}
		if netip.AddrPortFrom(from.Addr().Unmap(), from.Port()) != real {
			continue
		}
		p.heard(gen)
		return n, nil
	}
}

// write sends b to the peer's real address, following the path across a
// swap: a closed-socket error from a socket swapped out mid-write would
// otherwise reach QUIC, which treats a write error as fatal.
func (p *path) write(b []byte) (int, error) {
	for {
		sock, real, gen := p.current()
		if p.testHookWrite != nil {
			p.testHookWrite()
		}
		if p.testDrop.Load() == sock {
			p.sent(gen)
			return len(b), nil
		}
		n, err := sock.WriteToUDPAddrPort(b, real)
		if err == nil {
			p.sent(gen)
			return n, nil
		}
		p.mu.Lock()
		swapped, closed := p.gen != gen, p.closed
		p.mu.Unlock()
		switch {
		case swapped && !closed:
			continue
		case closed, errors.Is(err, os.ErrDeadlineExceeded):
			return n, err
		}
		// Anything else (network unreachable mid-handover, no route yet) is
		// packet loss to the protocol above: QUIC treats a send error as
		// fatal, and the session must outlive the moment before a migration
		// installs a working path. It still awaits an answer, so a path whose
		// route is gone is judged stalled.
		p.sent(gen)
		return len(b), nil
	}
}

// heard notes a datagram from the peer arrived on path generation gen.
// Every delivered datagram counts as heard, for ackGrace: the protocol
// above may acknowledge it on the new path. Only one from the current path
// clears the wait: a datagram read from a socket since swapped out would
// clear a wait begun on the new path, which nothing there has answered.
func (p *path) heard(gen int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lastRecv.Store(time.Now().UnixNano())
	if p.gen != gen {
		return
	}
	if p.waiting.Load() != 0 {
		p.waiting.Store(0)
	}
}

// ackGrace: a datagram sent this soon after one arrived doesn't start the
// wait for an answer. It is likely a bare acknowledgment (QUIC sends them
// within 25 ms), which the peer never answers, so it would otherwise make
// an idle session look stalled until the next keepalive. A real request
// that goes unanswered is retransmitted later than this and starts it then.
const ackGrace = time.Second

// sent notes a datagram went out on path generation gen, starting the
// wait for an answer if none is running and it isn't an acknowledgment of
// what just arrived. It holds mu, as heard does, so a reply can't land
// between the check and the start and leave a wait nothing will clear, and
// a write that went out on a socket since swapped out doesn't start a wait
// on the new path, which sent nothing.
func (p *path) sent(gen int) {
	if p.waiting.Load() != 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.gen != gen || p.waiting.Load() != 0 {
		return
	}
	now := time.Now().UnixNano()
	if now-p.lastRecv.Load() < int64(ackGrace) {
		return
	}
	p.waiting.Store(now)
}

func (p *path) close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	sock := p.sock
	p.mu.Unlock()
	return sock.Close()
}

// resumeID names a session to its two ends, derived from the secret only
// they hold, so a resume offer can find the session to move.
func resumeID(secret []byte) [16]byte {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("warren/endpoint/v1 resume"))
	return [16]byte(m.Sum(nil))
}

var (
	ErrNotCaller  = errors.New("endpoint: only the caller can migrate a connection")
	errWrongPeer  = errors.New("endpoint: datagram for an address other than the peer")
	errConnClosed = errors.New("endpoint: connection closed")
)

// The Conn methods below make it a net.PacketConn whose only peer is
// Remote, so it can carry hysteria2 or any datagram protocol.

// ReadFrom reads the next datagram from the peer, which is always reported
// as Remote whatever path it came over.
func (c *Conn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := c.p.read(b)
	if err != nil {
		return 0, nil, err
	}
	return n, net.UDPAddrFromAddrPort(c.Remote), nil
}

// WriteTo sends b to the peer; addr must be Remote.
func (c *Conn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if ua, ok := addr.(*net.UDPAddr); !ok || netip.AddrPortFrom(ua.AddrPort().Addr().Unmap(), ua.AddrPort().Port()) != c.Remote {
		return 0, errWrongPeer
	}
	return c.p.write(b)
}

// Send writes b to the peer.
func (c *Conn) Send(b []byte) error {
	_, err := c.p.write(b)
	return err
}

// Recv reads the next datagram from the peer, skipping leftover
// hole-punching control traffic (KRPC, first byte 'd').
func (c *Conn) Recv(b []byte) (int, error) {
	for {
		n, err := c.p.read(b)
		if err != nil {
			return 0, err
		}
		if n > 0 && b[0] == 'd' {
			continue
		}
		return n, nil
	}
}

// Close closes the connection and its current socket.
func (c *Conn) Close() error {
	if c.e != nil {
		c.e.forget(c)
	}
	return c.p.close()
}

// LocalAddr is the current socket's address; it changes when the
// connection migrates.
func (c *Conn) LocalAddr() net.Addr {
	sock, _, _ := c.p.current()
	return sock.LocalAddr()
}

// DontFragment reports false, though the sockets underneath set it: layers
// above use it to decide on path MTU discovery, and a migration can move
// the connection onto a path with a smaller MTU without QUIC noticing (the
// peer address it sees never changes), so a size discovered on one network
// would be dropped on the next. Packets stay at QUIC's safe initial size.
func (c *Conn) DontFragment() bool { return false }

func (c *Conn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	c.p.mu.Lock()
	defer c.p.mu.Unlock()
	if c.p.closed {
		return os.ErrClosed
	}
	c.p.readDeadline = t
	return c.p.sock.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.p.mu.Lock()
	defer c.p.mu.Unlock()
	if c.p.closed {
		return os.ErrClosed
	}
	c.p.writeDeadline = t
	return c.p.sock.SetWriteDeadline(t)
}
