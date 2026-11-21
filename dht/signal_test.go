package dht

import (
	"net/netip"
	"testing"
	"time"

	"github.com/getlantern/warren/krpc"
)

func TestOfferSaltRouting(t *testing.T) {
	rec := krpc.NodeID{1, 2, 3}
	other := krpc.NodeID{9}
	salt := offerSalt(make([]byte, 16), rec)
	if len(salt) != 32 || !saltMatchesRecord(salt, rec) {
		t.Fatal("offer salt does not route to its record")
	}
	if saltMatchesRecord(salt, other) {
		t.Fatal("offer salt routes to an unrelated record")
	}
	salt[20] ^= 1
	if saltMatchesRecord(salt, rec) {
		t.Fatal("tampered salt still routes")
	}
}

// Replaying the provider's signed put from another address must not move
// the binding while the provider keeps it fresh.
func TestBindingResistsReplay(t *testing.T) {
	var f forwarder
	target := krpc.NodeID{7}
	provider := netip.MustParseAddrPort("2.176.0.1:4000")
	attacker := netip.MustParseAddrPort("6.6.6.6:6666")
	salt := offerSalt(make([]byte, 16), target)

	f.bind(target, provider, 100, t0)
	f.bind(target, attacker, 100, t0.Add(time.Second))
	if dst, _ := f.offerDest(salt, t0.Add(2*time.Second)); dst != provider {
		t.Fatalf("replay rebound the record to %v", dst)
	}
	f.touch(target, attacker, t0.Add(90*time.Second)) // attacker's gets don't refresh
	f.touch(target, provider, t0.Add(90*time.Second))
	f.bind(target, attacker, 100, t0.Add(100*time.Second))
	if dst, _ := f.offerDest(salt, t0.Add(100*time.Second)); dst != provider {
		t.Fatalf("replay after keepalive rebound to %v", dst)
	}
	// A provider whose NAT mapping changed re-signs with a higher seq.
	moved := netip.MustParseAddrPort("2.176.0.1:5000")
	f.bind(target, moved, 101, t0.Add(110*time.Second))
	if dst, _ := f.offerDest(salt, t0.Add(110*time.Second)); dst != moved {
		t.Fatalf("newer signed put did not rebind: %v", dst)
	}
	// A binding nobody refreshes stops forwarding.
	if _, ok := f.offerDest(salt, t0.Add(110*time.Second+forwardTTL)); ok {
		t.Fatal("stale binding still forwards")
	}
}

func TestAnswerRoutesOnce(t *testing.T) {
	var f forwarder
	caller := netip.MustParseAddrPort("2.176.0.9:1234")
	a := answerSalt([]byte("offer"))
	f.expect(a, caller, t0)
	if dst, ok := f.answerDest(a, t0.Add(time.Second)); !ok || dst != caller {
		t.Fatal("answer not routed to caller")
	}
	if _, ok := f.answerDest(a, t0.Add(2*time.Second)); ok {
		t.Fatal("answer routed twice")
	}
	f.expect(a, caller, t0)
	if _, ok := f.answerDest(a, t0.Add(pendingAnswerTTL)); ok {
		t.Fatal("expired answer routed")
	}
}
