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
	// waiting is when the first datagram written since the peer was last
	// heard from went out (Unix nanoseconds), or zero: how long the peer
	// has been silent while we expected an answer.
	waiting atomic.Int64
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
	p.waiting.Store(0) // a fresh path starts unjudged
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
		if p.waiting.Load() != 0 {
			p.waiting.Store(0)
		}
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
			p.sent()
			return len(b), nil
		}
		n, err := sock.WriteToUDPAddrPort(b, real)
		if err == nil {
			p.sent()
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
		// installs a working path.
		return len(b), nil
	}
}

// sent notes a datagram went out, starting the wait for an answer if none
// is running.
func (p *path) sent() {
	if p.waiting.Load() == 0 {
		p.waiting.CompareAndSwap(0, time.Now().UnixNano())
	}
}

// silentFor reports how long the peer has been silent since a datagram we
// sent, or zero when nothing is awaiting an answer.
func (p *path) silentFor(now time.Time) time.Duration {
	w := p.waiting.Load()
	if w == 0 {
		return 0
	}
	return now.Sub(time.Unix(0, w))
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
