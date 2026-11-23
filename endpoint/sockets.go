package endpoint

import "sync"

// sockets bounds the extra sockets every punch in flight holds at once. The
// open and birthday strategies want up to punch.MaxExtraSockets each, and
// with MaxInbound concurrent inbound punches over two address families an
// unbounded endpoint could ask for more than a thousand descriptors, in a
// process (an iOS Network Extension) that shares its open-file limit with
// the rest of the VPN.
type sockets struct {
	mu   sync.Mutex
	free int
}

// take reserves up to want sockets and returns how many it got.
func (s *sockets) take(want int) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := min(want, s.free)
	s.free -= n
	return n
}

func (s *sockets) put(n int) {
	s.mu.Lock()
	s.free += n
	s.mu.Unlock()
}

// defaultPunchSockets is a quarter of the soft open-file limit, between 16
// and 512: the rest of the process (the DHT, live connections, the VPN's
// own datapath) keeps the other three quarters.
func defaultPunchSockets() int {
	return min(max(openFileLimit()/4, 16), 512)
}
