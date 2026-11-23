package endpoint

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/getlantern/warren/punch"
)

// A punch whose strategy wants many extra sockets takes what the endpoint's
// budget allows and gives it back when the punch is over; with none to
// spare it still connects from its own socket.
func TestPunchSocketBudget(t *testing.T) {
	for _, budget := range []int{5, 0} {
		seed := network(t, 8)
		provider := phone(t, seed)
		// A dependent, randomly allocating caller facing an independent
		// provider plans the open strategy, which wants punch.MaxExtraSockets.
		dependent := punch.Profile{Mapping: punch.MappingDependent, Allocation: punch.AllocRandom}
		caller, err := New(Config{DHT: member(true), DHTAddr: "127.0.0.1:0", DataIP: net.IPv4(127, 0, 0, 1), Profile: &dependent, MaxPunchSockets: 1})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { caller.Close() })
		caller.sockets.free = budget // before any punch, so unraced
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		if _, err := caller.DHT().Bootstrap(ctx, []netip.AddrPort{seed}); err != nil {
			t.Fatal(err)
		}
		pk := key("budget-provider")
		listenAndWait(t, provider, pk)
		go func() {
			if c, _ := provider.Accept(ctx); c != nil {
				defer c.Close()
				<-ctx.Done()
			}
		}()
		out, err := caller.Connect(ctx, key("budget-caller"), pub(pk))
		if err != nil {
			cancel()
			t.Fatalf("budget %d: %v", budget, err)
		}
		out.Close()
		cancel()
		caller.sockets.mu.Lock()
		granted := caller.sockets.granted
		caller.sockets.mu.Unlock()
		if granted != budget {
			t.Fatalf("budget %d: the punch was granted %d sockets", budget, granted)
		}
		if free := caller.sockets.take(1 << 20); free != budget {
			t.Fatalf("budget %d: %d free after the punch", budget, free)
		}
	}
}

// The default punch-socket budget is a quarter of the soft open-file limit,
// kept between 16 and 512.
func TestDefaultPunchSockets(t *testing.T) {
	limit, budget := openFileLimit(), defaultPunchSockets()
	t.Logf("soft RLIMIT_NOFILE %d, punch-socket budget %d", limit, budget)
	if want := min(max(limit/4, 16), 512); budget != want || budget < 16 || budget > 512 {
		t.Fatalf("budget %d for limit %d", budget, limit)
	}
}
