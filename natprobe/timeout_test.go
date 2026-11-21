package natprobe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/getlantern/warren/krpc"
)

func gapResult(gap time.Duration, changed bool) GapResult {
	before := netip.MustParseAddrPort("203.0.113.7:40000")
	after := before
	if changed {
		after = netip.MustParseAddrPort("203.0.113.7:51234")
	}
	return GapResult{Gap: gap, Before: before, After: after, OK: true, Changed: changed}
}

func TestCarrierTimeoutDetected(t *testing.T) {
	r := analyzeTimeouts([]GapResult{
		gapResult(20*time.Second, false),
		gapResult(40*time.Second, false),
		gapResult(60*time.Second, true),
		gapResult(90*time.Second, true),
	})
	if !r.Detectable || r.Expired != 60*time.Second || r.AliveAt != 40*time.Second {
		t.Fatalf("got %+v", r)
	}
	if k := KeepaliveFor(r, 25*time.Second); k != 32*time.Second {
		t.Errorf("keepalive %v, want 32s (80%% of the longest surviving gap)", k)
	}
}

func TestShortTimeoutFloor(t *testing.T) {
	r := analyzeTimeouts([]GapResult{gapResult(20*time.Second, true)})
	if k := KeepaliveFor(r, 25*time.Second); k != 10*time.Second {
		t.Errorf("keepalive %v, want the 10s floor", k)
	}
}

func TestPreservingNATIsUndetectable(t *testing.T) {
	r := analyzeTimeouts([]GapResult{gapResult(20*time.Second, false), gapResult(180*time.Second, false)})
	if r.Detectable || KeepaliveFor(r, 25*time.Second) != 25*time.Second {
		t.Fatalf("got %+v", r)
	}
}

func TestFailedGapsIgnored(t *testing.T) {
	r := analyzeTimeouts([]GapResult{{Gap: 20 * time.Second}, gapResult(40*time.Second, true)})
	if r.Expired != 40*time.Second || r.AliveAt != 0 {
		t.Fatalf("got %+v", r)
	}
}

// If a later socket fails to open, MappingTimeout must stop and join the
// gap probes it already started instead of leaving them running.
func TestMappingTimeoutJoinsProbesOnOpenError(t *testing.T) {
	refl, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer refl.Close()
	go func() { // answers every ping with the sender's address
		buf := make([]byte, 2048)
		for {
			n, from, err := refl.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			var q krpc.Msg
			if krpc.Unmarshal(buf[:n], &q) != nil {
				continue
			}
			r := krpc.Msg{T: q.T, Y: krpc.Response, IP: from}
			refl.WriteToUDPAddrPort(krpc.AppendMarshal(nil, &r), from)
		}
	}()
	opened := 0
	listenUDP = func(network string, laddr *net.UDPAddr) (*net.UDPConn, error) {
		if opened++; opened > 2 {
			return nil, errors.New("too many open files")
		}
		return net.ListenUDP(network, laddr)
	}
	defer func() { listenUDP = net.ListenUDP }()
	before := runtime.NumGoroutine()
	start := time.Now()
	_, err = MappingTimeout(context.Background(), refl.LocalAddr().(*net.UDPAddr).AddrPort(), []time.Duration{time.Hour, time.Hour, time.Hour})
	if err == nil {
		t.Fatal("expected the open error")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("returned after %v: earlier probes were not canceled", d)
	}
	time.Sleep(100 * time.Millisecond) // let read loops observe their closed sockets
	if g := runtime.NumGoroutine() - before; g > 1 {
		t.Fatalf("%d goroutines left running after MappingTimeout returned", g)
	}
}
