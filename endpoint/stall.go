package endpoint

import (
	"context"
	"time"
)

const (
	// defaultStallTimeout is how long a peer may stay silent after we sent
	// it something that expects an answer before the path counts as dead.
	// QUIC acknowledges ack-eliciting packets within a round trip, and bare
	// acknowledgments, which get no answer, are ignored (see ackGrace), so
	// a live path answers well inside it; a migration still has time to
	// finish before QUIC's 30-second idle timeout ends the session.
	defaultStallTimeout = 5 * time.Second
	// maxStallBackoff caps the wait between failed stall migrations, for a
	// peer that is gone rather than moved.
	maxStallBackoff = 30 * time.Second
	stallCheck      = time.Second
)

// startStallWatch runs the stall watcher while outbound connections exist,
// so an endpoint with none, such as a provider, wakes for nothing.
func (e *Endpoint) startStallWatch() {
	if e.stallTimeout.Load() < 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.stallWatching {
		return
	}
	e.stallWatching = true
	e.wg.Go(e.watchStalls)
}

// watchStalls migrates outbound connections whose peer has gone silent:
// the path died without the network changing under us (the provider
// moved, a NAT dropped its mapping, a relay went away), which Rebind never
// hears about.
func (e *Endpoint) watchStalls() {
	tick := time.NewTicker(stallCheck)
	defer tick.Stop()
	for {
		select {
		case <-e.done:
			return
		case <-tick.C:
		}
		e.mu.Lock()
		e.connsMu.Lock()
		if len(e.outConns) == 0 {
			e.stallWatching = false
			e.connsMu.Unlock()
			e.mu.Unlock()
			return
		}
		out := make([]*Conn, 0, len(e.outConns))
		for _, c := range e.outConns {
			out = append(out, c)
		}
		e.connsMu.Unlock()
		e.mu.Unlock()
		timeout := time.Duration(e.stallTimeout.Load())
		now := time.Now()
		for _, c := range out {
			c.checkStall(now, timeout)
		}
	}
}

// checkStall starts a migration if c's peer has been silent past timeout
// and no stall migration is running or backing off.
func (c *Conn) checkStall(now time.Time, timeout time.Duration) {
	_, _, gen := c.p.current()
	wait := c.p.waiting.Load()
	if timeout <= 0 || wait == 0 || now.Sub(time.Unix(0, wait)) < timeout {
		return
	}
	sameWait := wait == c.stallFailedWait.Load() && int64(gen) == c.stallFailedGen.Load()
	if (sameWait && now.UnixNano() < c.stallNext.Load()) || !c.stallBusy.CompareAndSwap(false, true) {
		return
	}
	e := c.e
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		c.stallBusy.Store(false)
		return
	}
	e.wg.Add(1)
	e.mu.Unlock()
	go func() {
		defer e.wg.Done()
		defer c.stallBusy.Store(false)
		ctx, cancel := context.WithTimeout(context.Background(), maxStallBackoff)
		defer cancel()
		if err := c.migrate(ctx, moveStall, stallMark{gen, wait}); err != nil {
			// The peer may be gone rather than moved: back off, doubling up to
			// the cap while the same wait goes unanswered, so a dead session
			// doesn't signal the DHT every second until the layer above gives
			// up on it. A new wait (the peer answered meanwhile) or a new path
			// starts again from the timeout.
			if !sameWait {
				c.stallBackoff = 0
			}
			c.stallBackoff = min(max(2*c.stallBackoff, timeout), maxStallBackoff)
			c.stallFailedGen.Store(int64(gen))
			c.stallFailedWait.Store(wait)
			c.stallNext.Store(time.Now().Add(c.stallBackoff).UnixNano())
			return
		}
		c.stallBackoff = 0
		c.stallNext.Store(0)
		c.stallFailedWait.Store(0)
	}()
}
