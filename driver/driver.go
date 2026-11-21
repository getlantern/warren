// Package driver runs a dht.Node over a real UDP socket. One goroutine owns
// the node: packets, operations, and timers are serialized through it, so the
// sans-IO core stays single-threaded exactly as in the simulator.
package driver

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/getlantern/warren/dht"
	"github.com/getlantern/warren/krpc"
)

const (
	inboxSize  = 128 // datagrams queued between the reader and the loop
	eventsSize = 32
	maxPacket  = 2048
)

var ErrClosed = errors.New("driver: closed")

type packet struct {
	from netip.AddrPort
	data []byte
}

type Node struct {
	conn   *net.UDPConn
	addr   netip.AddrPort
	inbox  chan packet
	ops    chan func(*dht.Node, time.Time)
	events chan dht.Event
	done   chan struct{}
	once   sync.Once
	wg     sync.WaitGroup
	// waiters is owned by the loop goroutine; operation closures run there
	// and register before any of their events can be delivered.
	waiters map[dht.OpID]chan dht.Event
}

// Listen binds an IPv4 UDP socket (e.g. ":6881" or "127.0.0.1:0") and starts
// the node.
func Listen(addr string, cfg dht.Config) (*Node, error) {
	ua, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp4", ua)
	if err != nil {
		return nil, err
	}
	n := &Node{
		conn:   conn,
		addr:   conn.LocalAddr().(*net.UDPAddr).AddrPort(),
		inbox:  make(chan packet, inboxSize),
		ops:    make(chan func(*dht.Node, time.Time)),
		events: make(chan dht.Event, eventsSize),
		done:   make(chan struct{}),

		waiters: map[dht.OpID]chan dht.Event{},
	}
	n.wg.Add(2)
	go n.read()
	go n.loop(dht.New(cfg))
	return n, nil
}

func (n *Node) Addr() netip.AddrPort { return n.addr }

// Events delivers events not tied to a caller's operation, such as
// PartitionChanged and IsolationChanged. Events are dropped if not consumed.
func (n *Node) Events() <-chan dht.Event { return n.events }

func (n *Node) Close() error {
	n.once.Do(func() {
		close(n.done)
		n.conn.Close()
	})
	n.wg.Wait()
	return nil
}

// read copies each datagram to an exact-size buffer and drops it if the loop
// is behind, bounding memory under load.
func (n *Node) read() {
	defer n.wg.Done()
	buf := make([]byte, maxPacket)
	for {
		sz, from, err := n.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			select {
			case <-n.done:
				return
			default:
				continue
			}
		}
		p := packet{from: from, data: append([]byte(nil), buf[:sz]...)}
		select {
		case n.inbox <- p:
		default:
		}
	}
}

func (n *Node) loop(node *dht.Node) {
	defer n.wg.Done()
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		select {
		case <-n.done:
			return
		case p := <-n.inbox:
			node.HandlePacket(time.Now(), p.from, p.data)
		case f := <-n.ops:
			f(node, time.Now())
		case <-timer.C:
			node.Tick(time.Now())
		}
		sends, events := node.Drain()
		for _, s := range sends {
			n.conn.WriteToUDPAddrPort(s.Data, s.To)
		}
		for _, e := range events {
			op, ok := opOf(e)
			if ch := n.waiters[op]; ok && ch != nil {
				ch <- e
				delete(n.waiters, op)
				continue
			}
			select {
			case n.events <- e:
			default:
			}
		}
		if w := node.NextWakeup(); !w.IsZero() {
			timer.Reset(max(time.Until(w), 0))
		}
	}
}

func opOf(e dht.Event) (dht.OpID, bool) {
	switch e := e.(type) {
	case dht.LookupDone:
		return e.Op, true
	case dht.GetDone:
		return e.Op, true
	case dht.PutDone:
		return e.Op, true
	case dht.Answered:
		return e.Op, true
	case dht.SignalFailed:
		return e.Op, true
	}
	return 0, false
}

// do runs f on the loop goroutine.
func (n *Node) do(ctx context.Context, f func(*dht.Node, time.Time)) error {
	select {
	case n.ops <- f:
		return nil
	case <-n.done:
		return ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

// call starts an operation and waits for its completion event.
func (n *Node) call(ctx context.Context, start func(*dht.Node, time.Time) (dht.OpID, error)) (dht.Event, error) {
	ch := make(chan dht.Event, 1)
	errc := make(chan error, 1)
	err := n.do(ctx, func(d *dht.Node, now time.Time) {
		op, err := start(d, now)
		if err == nil {
			n.waiters[op] = ch
		}
		errc <- err
	})
	if err != nil {
		return nil, err
	}
	if err := <-errc; err != nil {
		return nil, err
	}
	select {
	case e := <-ch:
		return e, nil
	case <-n.done:
		return nil, ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (n *Node) Bootstrap(ctx context.Context, seeds []netip.AddrPort) (dht.LookupDone, error) {
	e, err := n.call(ctx, func(d *dht.Node, now time.Time) (dht.OpID, error) { return d.Bootstrap(now, seeds) })
	if err != nil {
		return dht.LookupDone{}, err
	}
	return e.(dht.LookupDone), nil
}

func (n *Node) Rejoin(ctx context.Context, contacts []krpc.NodeInfo) (dht.LookupDone, error) {
	e, err := n.call(ctx, func(d *dht.Node, now time.Time) (dht.OpID, error) { return d.Rejoin(now, contacts) })
	if err != nil {
		return dht.LookupDone{}, err
	}
	return e.(dht.LookupDone), nil
}

// Get returns the immutable value stored under target, or nil if not found.
func (n *Node) Get(ctx context.Context, target krpc.NodeID) ([]byte, error) {
	e, err := n.call(ctx, func(d *dht.Node, now time.Time) (dht.OpID, error) { return d.Get(now, target) })
	if err != nil {
		return nil, err
	}
	return e.(dht.GetDone).Value, nil
}

func (n *Node) Put(ctx context.Context, v []byte) (krpc.NodeID, dht.PutDone, error) {
	var target krpc.NodeID
	e, err := n.call(ctx, func(d *dht.Node, now time.Time) (dht.OpID, error) {
		t, op, err := d.Put(now, v)
		target = t
		return op, err
	})
	if err != nil {
		return target, dht.PutDone{}, err
	}
	return target, e.(dht.PutDone), nil
}

// GetMutable returns the newest verified item, or nil if none was found.
func (n *Node) GetMutable(ctx context.Context, key [32]byte, salt []byte) (*dht.MutableItem, error) {
	e, err := n.call(ctx, func(d *dht.Node, now time.Time) (dht.OpID, error) { return d.GetMutable(now, key, salt) })
	if err != nil {
		return nil, err
	}
	return e.(dht.GetDone).Item, nil
}

func (n *Node) PutMutable(ctx context.Context, m dht.MutableItem, cas *int64) (dht.PutDone, error) {
	e, err := n.call(ctx, func(d *dht.Node, now time.Time) (dht.OpID, error) { return d.PutMutable(now, m, cas) })
	if err != nil {
		return dht.PutDone{}, err
	}
	return e.(dht.PutDone), nil
}

// Publish keeps an immutable value stored until Unpublish.
func (n *Node) Publish(ctx context.Context, v []byte) (krpc.NodeID, error) {
	var target krpc.NodeID
	errc := make(chan error, 1)
	if err := n.do(ctx, func(d *dht.Node, now time.Time) {
		var err error
		target, err = d.Publish(now, v)
		errc <- err
	}); err != nil {
		return target, err
	}
	return target, <-errc
}

// PublishMutable keeps a signed item stored; publish a higher seq to update.
func (n *Node) PublishMutable(ctx context.Context, m dht.MutableItem) error {
	errc := make(chan error, 1)
	if err := n.do(ctx, func(d *dht.Node, now time.Time) {
		_, err := d.PublishMutable(now, m)
		errc <- err
	}); err != nil {
		return err
	}
	return <-errc
}

// Snapshot returns the node's saved-state encoding; see dht.Node.Snapshot.
func (n *Node) Snapshot(ctx context.Context) ([]byte, error) {
	out := make(chan []byte, 1)
	if err := n.do(ctx, func(d *dht.Node, _ time.Time) { out <- d.Snapshot() }); err != nil {
		return nil, err
	}
	return <-out, nil
}

// Listen makes this node reachable for signaling under priv's key. Offers
// arrive as dht.Incoming on Events; reply with Answer.
func (n *Node) Listen(ctx context.Context, priv ed25519.PrivateKey) error {
	errc := make(chan error, 1)
	if err := n.do(ctx, func(d *dht.Node, now time.Time) { errc <- d.Listen(now, priv) }); err != nil {
		return err
	}
	return <-errc
}

func (n *Node) Answer(ctx context.Context, s dht.SessionID, payload []byte) error {
	errc := make(chan error, 1)
	if err := n.do(ctx, func(d *dht.Node, now time.Time) { errc <- d.Answer(now, s, payload) }); err != nil {
		return err
	}
	return <-errc
}

// Signal sends payload to provider through the DHT and returns its answer.
func (n *Node) Signal(ctx context.Context, priv ed25519.PrivateKey, provider [32]byte, payload []byte) ([]byte, error) {
	e, err := n.call(ctx, func(d *dht.Node, now time.Time) (dht.OpID, error) { return d.Signal(now, priv, provider, payload) })
	if err != nil {
		return nil, err
	}
	switch e := e.(type) {
	case dht.Answered:
		return e.Payload, nil
	case dht.SignalFailed:
		return nil, e.Err
	}
	return nil, errors.New("driver: unexpected signaling event")
}

// Inspect runs f against the node on its own goroutine, for status queries.
func (n *Node) Inspect(ctx context.Context, f func(*dht.Node)) error {
	done := make(chan struct{})
	if err := n.do(ctx, func(d *dht.Node, _ time.Time) { f(d); close(done) }); err != nil {
		return err
	}
	<-done
	return nil
}
