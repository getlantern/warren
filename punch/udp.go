package punch

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"
)

type packet struct {
	socket int
	from   netip.AddrPort
	data   []byte
}

// Runner drives a Session over real UDP sockets. Socket 0 is the caller's;
// the runner opens the rest on demand, on the same IP.
type Runner struct {
	once    sync.Once
	relayed bool
	s       *Session
	conns   []*net.UDPConn
	inbox   chan packet
	stop    chan struct{}
	wg      sync.WaitGroup
	mu      sync.Mutex
	stopped map[int]bool
}

func NewRunner(s *Session, base *net.UDPConn) *Runner {
	r := &Runner{s: s, inbox: make(chan packet, 256), stop: make(chan struct{}), stopped: map[int]bool{}}
	r.add(base)
	return r
}

func (r *Runner) add(c *net.UDPConn) {
	i := len(r.conns)
	r.conns = append(r.conns, c)
	r.wg.Go(func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := c.ReadFromUDPAddrPort(buf)
			if err != nil {
				r.mu.Lock()
				done := r.stopped[i]
				r.mu.Unlock()
				if done || errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
			p := packet{socket: i, from: netip.AddrPortFrom(from.Addr().Unmap(), from.Port()), data: append([]byte(nil), buf[:n]...)}
			select {
			case r.inbox <- p:
			case <-r.stop:
				return
			}
		}
	})
}

func (r *Runner) flush() (Event, error) {
	base := r.conns[0].LocalAddr().(*net.UDPAddr)
	network := "udp6"
	if base.IP.To4() != nil {
		network = "udp4"
	}
	for len(r.conns) < r.s.Sockets() {
		c, err := net.ListenUDP(network, &net.UDPAddr{IP: base.IP, Zone: base.Zone})
		if err != nil {
			return nil, err
		}
		r.add(c)
	}
	sends, events := r.s.Drain()
	for _, snd := range sends {
		if snd.Socket < len(r.conns) {
			r.conns[snd.Socket].WriteToUDPAddrPort(snd.Data, snd.To)
		}
	}
	for _, e := range events {
		switch e.(type) {
		case Connected, Failed:
			return e, nil
		}
	}
	return nil, nil
}

// Gather sends reflection pings and waits until a reflector answers or wait
// elapses.
func (r *Runner) Gather(ctx context.Context, reflectors []netip.AddrPort, wait time.Duration) error {
	r.s.Reflect(reflectors)
	if _, err := r.flush(); err != nil {
		return err
	}
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	for {
		select {
		case p := <-r.inbox:
			r.s.HandlePacket(time.Now(), p.socket, p.from, p.data)
			_, events := r.s.Drain()
			for _, e := range events {
				if _, ok := e.(Reflected); ok {
					return nil
				}
			}
		case <-deadline.C:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// Punch runs the session against the peer's offer. On success it returns
// the nominated socket and peer address; every other socket is closed and
// the runner stops reading, handing the socket to the caller.
func (r *Runner) Punch(ctx context.Context, remote Offer) (*net.UDPConn, netip.AddrPort, error) {
	r.s.Start(time.Now(), remote)
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		ev, err := r.flush()
		if err != nil {
			r.close(-1)
			return nil, netip.AddrPort{}, err
		}
		switch e := ev.(type) {
		case Connected:
			r.relayed = e.Relayed
			r.close(e.Socket)
			return r.conns[e.Socket], e.Remote, nil
		case Failed:
			r.close(-1)
			return nil, netip.AddrPort{}, e.Err
		}
		if w := r.s.NextWakeup(); !w.IsZero() {
			timer.Reset(max(time.Until(w), 0))
		}
		select {
		case p := <-r.inbox:
			r.s.HandlePacket(time.Now(), p.socket, p.from, p.data)
		case <-timer.C:
			r.s.Tick(time.Now())
		case <-ctx.Done():
			r.close(-1)
			return nil, netip.AddrPort{}, ctx.Err()
		}
	}
}

// Relayed reports whether Punch returned a relayed path.
func (r *Runner) Relayed() bool { return r.relayed }

// Abort stops the runner without punching, for callers that give up
// between Gather and Punch: it stops the readers (which may be blocked
// handing a packet to an inbox nobody drains) and closes the extra sockets.
// Socket 0 stays open for the caller to close. Safe to call more than once.
func (r *Runner) Abort() { r.close(-1) }

// close stops all readers, closing every opened socket except keep. Socket
// 0 belongs to the caller and is never closed here. Only the first call acts.
func (r *Runner) close(keep int) {
	r.once.Do(func() { r.closeOnce(keep) })
}

func (r *Runner) closeOnce(keep int) {
	r.mu.Lock()
	for i := range r.conns {
		r.stopped[i] = true
	}
	r.mu.Unlock()
	close(r.stop)
	for i, c := range r.conns {
		if i == keep || i == 0 {
			c.SetReadDeadline(time.Now()) // unblock the reader without closing
			continue
		}
		c.Close()
	}
	r.wg.Wait()
	for i, c := range r.conns {
		if i == keep || i == 0 {
			c.SetReadDeadline(time.Time{})
		}
	}
}
