package sim

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/getlantern/warren/dht"
	"github.com/getlantern/warren/krpc"
)

func key(seed string) ed25519.PrivateKey {
	s := sha256.Sum256([]byte(seed))
	return ed25519.NewKeyFromSeed(s[:])
}

type signalResult struct {
	answered *dht.Answered
	failed   *dht.SignalFailed
	incoming *dht.Incoming
	took     time.Duration
}

// signal has caller send an offer to provider, which answers automatically.
func signal(t *testing.T, w *world, caller, provider *Node, providerKey ed25519.PrivateKey) signalResult {
	t.Helper()
	var res signalResult
	var op dht.OpID
	var started time.Time
	w.s.OnEvent = func(n *Node, e dht.Event) {
		switch e := e.(type) {
		case dht.Incoming:
			if n == provider {
				res.incoming = &e
				w.s.Do(n, func(now time.Time) {
					if err := n.DHT.Answer(now, e.Session, append([]byte("answer to "), e.Payload...)); err != nil {
						t.Errorf("answer: %v", err)
					}
				})
			}
		case dht.Answered:
			if n == caller && e.Op == op {
				res.answered, res.took = &e, w.s.Now.Sub(started)
			}
		case dht.SignalFailed:
			if n == caller && e.Op == op {
				res.failed = &e
			}
		}
	}
	callerKey := key("caller")
	w.s.Do(caller, func(now time.Time) {
		started = now
		var err error
		if op, err = caller.DHT.Signal(now, callerKey, [32]byte(providerKey.Public().(ed25519.PublicKey)), []byte("offer")); err != nil {
			t.Fatal(err)
		}
	})
	w.s.RunUntil(w.s.Now.Add(45 * time.Second))
	if res.incoming != nil && res.incoming.Caller != [32]byte(callerKey.Public().(ed25519.PublicKey)) {
		t.Errorf("provider saw caller %x", res.incoming.Caller)
	}
	return res
}

func listen(t *testing.T, w *world, n *Node, priv ed25519.PrivateKey) {
	t.Helper()
	w.s.Do(n, func(now time.Time) {
		if err := n.DHT.Listen(now, priv); err != nil {
			t.Fatal(err)
		}
	})
	w.s.RunUntil(w.s.Now.Add(2 * time.Minute))
	if len(n.DHT.Holders()) == 0 {
		t.Fatal("provider has no record holders")
	}
}

// Two read-only phones behind NAT reach each other through record holders.
func TestSignalPhoneToPhone(t *testing.T) {
	w := build(11, scenarios[0], sizes{ir: 80, abroad: 30, readers: 20})
	w.join(30 * time.Minute)
	provider, caller := w.readersIR[0], w.readersIR[7]
	pk := key("provider")
	listen(t, w, provider, pk)

	res := signal(t, w, caller, provider, pk)
	if res.answered == nil {
		t.Fatalf("no answer: %+v", res.failed)
	}
	if string(res.answered.Payload) != "answer to offer" || string(res.incoming.Payload) != "offer" {
		t.Fatalf("payloads: offer %q answer %q", res.incoming.Payload, res.answered.Payload)
	}
	t.Logf("offer→answer in %v (including record lookup) via %s", res.took, res.answered.Via)
	if res.took > 3*time.Second {
		t.Errorf("signaling took %v", res.took)
	}
}

func TestSignalFailsOverDeadHolder(t *testing.T) {
	w := build(12, scenarios[0], sizes{ir: 80, abroad: 30, readers: 20})
	w.join(30 * time.Minute)
	provider, caller := w.readersIR[1], w.readersIR[9]
	pk := key("provider-2")
	listen(t, w, provider, pk)

	// Kill the holder a caller tries first: the one closest to the record.
	var dead []*Node
	for _, h := range provider.DHT.Holders()[:1] {
		for _, n := range w.s.Nodes() {
			if n.Addr == h {
				n.Offline = true
				dead = append(dead, n)
			}
		}
	}
	res := signal(t, w, caller, provider, pk)
	if res.answered == nil {
		t.Fatalf("no answer after holder loss: %+v", res.failed)
	}
	if slices.ContainsFunc(dead, func(n *Node) bool { return n.Addr == res.answered.Via }) {
		t.Fatal("answer came through the dead holder")
	}
	t.Logf("failover answer in %v via %s", res.took, res.answered.Via)
}

// Signaling between two domestic phones keeps working an hour into a
// shutdown, through domestic holders.
func TestSignalDuringShutdown(t *testing.T) {
	w := build(13, scenarios[3], sizes{ir: 60, abroad: 180, readers: 40})
	w.join(45 * time.Minute)
	provider, caller := w.readersIR[2], w.readersIR[20]
	pk := key("provider-3")
	listen(t, w, provider, pk)

	w.s.Border = true
	w.s.RunUntil(w.s.Now.Add(time.Hour))
	for _, h := range provider.DHT.Holders() {
		if !domestic(h.Addr()) {
			t.Errorf("provider still keeps foreign holder %s alive", h)
		}
	}
	res := signal(t, w, caller, provider, pk)
	if res.answered == nil {
		t.Fatalf("no answer during shutdown: %+v", res.failed)
	}
	t.Logf("shutdown signaling in %v", res.took)
}

func TestSignalUnknownProvider(t *testing.T) {
	w := build(14, scenarios[0], sizes{ir: 40, abroad: 10, readers: 10})
	w.join(20 * time.Minute)
	res := signal(t, w, w.readersIR[0], w.readersIR[1], key("nobody"))
	if res.failed == nil || res.failed.Err != dht.ErrNoRecord {
		t.Fatalf("want ErrNoRecord, got %+v %+v", res.failed, res.answered)
	}
}

// Listen before Bootstrap publishes into an empty table; the record must
// reach holders soon after routing becomes available, not at the next
// 30-minute republish.
func TestListenBeforeBootstrap(t *testing.T) {
	w := build(15, scenarios[0], sizes{ir: 60, abroad: 20, readers: 10})
	w.join(20 * time.Minute)
	n := w.s.Add(netip.MustParseAddrPort("2.190.1.1:6881"), true, dht.Config{
		ID: farsi.Tag(krpc.SecureID(netip.MustParseAddr("2.190.1.1"), krpc.NodeID{1, 2, 3})), Community: &farsi, ReadOnly: true,
	})
	pk := key("early listener")
	w.s.Do(n, func(now time.Time) { n.DHT.Listen(now, pk) })
	w.s.RunUntil(w.s.Now.Add(time.Second))
	w.s.Do(n, func(now time.Time) { n.DHT.Bootstrap(now, []netip.AddrPort{w.routersIR[0].Addr}) })
	w.s.RunUntil(w.s.Now.Add(2 * time.Minute))
	if len(n.DHT.Holders()) == 0 {
		t.Fatal("record not stored within 2 minutes of bootstrapping")
	}
}

// If the provider's answer is lost, the caller's retry through another
// holder must still get it.
func TestLostAnswerRecovered(t *testing.T) {
	w := build(16, scenarios[0], sizes{ir: 80, abroad: 30, readers: 20})
	w.join(30 * time.Minute)
	provider, caller := w.readersIR[3], w.readersIR[11]
	pk := key("provider-lost-answer")
	listen(t, w, provider, pk)
	dropped := false
	w.s.OnSend = func(from *Node, to netip.AddrPort, data []byte) {
		if from == provider && !dropped && bytes.Contains(data, []byte("3:put")) {
			dropped = true
			from.Offline = true // drop just this datagram
			w.s.At(w.s.Now, func() { from.Offline = false })
		}
	}
	res := signal(t, w, caller, provider, pk)
	if !dropped {
		t.Fatal("test did not drop the answer")
	}
	if res.answered == nil {
		t.Fatalf("no answer after the first was lost: %+v", res.failed)
	}
}
