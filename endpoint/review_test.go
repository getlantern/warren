package endpoint

import (
	"context"
	"crypto/rand"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/getlantern/warren/dht"
	"github.com/getlantern/warren/driver"
	"github.com/getlantern/warren/punch"
)

// rawProvider listens with a bare DHT node and answers every offer with the
// given punch offer, letting tests control what the caller punches toward.
func rawProvider(t *testing.T, seed netip.AddrPort, answer punch.Offer) [32]byte {
	t.Helper()
	n, err := driver.Listen("127.0.0.1:0", member(true))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	n.Bootstrap(ctx, []netip.AddrPort{seed})
	pk := key("raw provider")
	if err := n.Listen(ctx, pk); err != nil {
		t.Fatal(err)
	}
	go func() {
		for e := range n.Events() {
			if in, ok := e.(dht.Incoming); ok {
				n.Answer(context.Background(), in.Session, answer.Marshal())
			}
		}
	}()
	for {
		var holders int
		n.Inspect(ctx, func(d *dht.Node) { holders = len(d.Holders()) })
		if holders > 0 {
			return pub(pk)
		}
		if ctx.Err() != nil {
			t.Fatal("raw provider's record never stored")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Close must stop an outbound Connect that is mid-punch.
func TestCloseStopsOutboundPunch(t *testing.T) {
	seed := network(t, 10)
	unreachable := punch.Offer{Candidates: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:9")}, Profile: punch.Profile{Mapping: punch.MappingIndependent}}
	provider := rawProvider(t, seed, unreachable)
	caller, err := New(Config{DHT: member(true), DHTAddr: "127.0.0.1:0", DataIP: net.IPv4(127, 0, 0, 1), PunchDeadline: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	caller.DHT().Bootstrap(ctx, []netip.AddrPort{seed})
	result := make(chan error, 1)
	go func() {
		_, err := caller.Connect(context.Background(), key("c"), provider)
		result <- err
	}()
	time.Sleep(500 * time.Millisecond) // signaling done, punching toward nowhere
	closed := make(chan struct{})
	go func() { caller.Close(); close(closed) }()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("Connect succeeded on a closed endpoint")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Connect kept punching after Close")
	}
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not return")
	}
}

// A relay-only listener must not contact a relay it has never
// authenticated, even when a validly signed offer names one: a caller could
// otherwise pick its own router and learn the listener's address.
func TestRelayOnlyRejectsUnknownRelay(t *testing.T) {
	seed := network(t, 10)
	provider, err := New(Config{DHT: member(true), DHTAddr: "127.0.0.1:0", DataIP: net.IPv4(127, 0, 0, 1), RelayOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	provider.DHT().Bootstrap(ctx, []netip.AddrPort{seed})
	pk := key("relay-only provider")
	listenAndWait(t, provider, pk)

	spy, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer spy.Close()
	caller, err := driver.Listen("127.0.0.1:0", member(true))
	if err != nil {
		t.Fatal(err)
	}
	defer caller.Close()
	caller.Bootstrap(ctx, []netip.AddrPort{seed})
	secret := make([]byte, 32)
	rand.Read(secret)
	offer := punch.Offer{Secret: secret, Relay: spy.LocalAddr().(*net.UDPAddr).AddrPort(), Profile: punch.Profile{Mapping: punch.MappingIndependent}}
	if _, err := caller.Signal(ctx, key("c"), pub(pk), offer.Marshal()); err != nil {
		t.Fatalf("signal: %v", err)
	}
	spy.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, from, err := spy.ReadFromUDPAddrPort(make([]byte, 2048)); err == nil {
		t.Fatalf("relay-only provider contacted an unauthenticated relay (from %s)", from)
	}
}
