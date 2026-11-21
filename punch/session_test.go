package punch

import (
	"math/rand/v2"
	"net/netip"
	"testing"
	"time"
)

// A responder acting on a stranger's offer must never spray a non-public
// address: that would port-scan its own LAN or localhost on request.
func TestResponderNeverSpraysPrivate(t *testing.T) {
	for _, cand := range []string{"192.168.1.1:9", "127.0.0.1:9", "10.0.0.5:9"} {
		s := New(Config{Local: Profile{Mapping: MappingIndependent}, Rand: rand.New(rand.NewPCG(1, 1))})
		now := time.Unix(1_800_000_000, 0)
		s.Start(now, Offer{
			Secret:     []byte("0123456789abcdef"),
			Candidates: []netip.AddrPort{netip.MustParseAddrPort(cand)},
			Profile:    Profile{Mapping: MappingDependent, Allocation: AllocRandom},
		})
		for range 50 {
			now = now.Add(20 * time.Millisecond)
			s.Tick(now)
		}
		sends, events := s.Drain()
		ports := map[uint16]bool{}
		for _, snd := range sends {
			ports[snd.To.Port()] = true
		}
		if len(ports) > 1 {
			t.Errorf("%s: responder probed %d ports", cand, len(ports))
		}
		if len(events) == 0 {
			t.Errorf("%s: no outcome", cand)
		} else if f, ok := events[0].(Failed); !ok || f.Err != ErrRelayNeeded {
			t.Errorf("%s: outcome %+v, want ErrRelayNeeded without a relay", cand, events[0])
		}
	}
}
