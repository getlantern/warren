package punch

import (
	"context"
	"math/rand/v2"
	"net"
	"net/netip"
	"testing"
	"time"
)

func loopbackConn(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func addrOf(c *net.UDPConn) netip.AddrPort { return c.LocalAddr().(*net.UDPAddr).AddrPort() }

type punchResult struct {
	conn   *net.UDPConn
	remote netip.AddrPort
	err    error
}

func punchPair(t *testing.T, aProfile, bProfile Profile) (punchResult, punchResult) {
	t.Helper()
	secret := []byte("0123456789abcdef0123456789abcdef")
	ca, cb := loopbackConn(t), loopbackConn(t)
	sa := New(Config{Initiator: true, Secret: secret, Local: aProfile, Rand: rand.New(rand.NewPCG(1, 1)), Deadline: 3 * time.Second})
	sb := New(Config{Local: bProfile, Rand: rand.New(rand.NewPCG(2, 2)), Deadline: 3 * time.Second})
	ra, rb := NewRunner(sa, ca), NewRunner(sb, cb)
	oa, ob := sa.Offer([]netip.AddrPort{addrOf(ca)}), sb.Offer([]netip.AddrPort{addrOf(cb)})
	if bProfile.Mapping == MappingDependent {
		// A sprays B's claimed range; pin it to B's own socket so the test
		// never probes unrelated local services.
		ob.Profile.BlockLo, ob.Profile.BlockHi = addrOf(cb).Port(), addrOf(cb).Port()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	results := make(chan punchResult, 2)
	var out [2]punchResult
	go func() { c, r, err := rb.Punch(ctx, oa); results <- punchResult{c, r, err} }()
	c, r, err := ra.Punch(ctx, ob)
	out[0] = punchResult{c, r, err}
	out[1] = <-results
	return out[0], out[1]
}

func exchange(t *testing.T, a, b punchResult) {
	t.Helper()
	if _, err := a.conn.WriteToUDPAddrPort([]byte("ping over punched path"), a.remote); err != nil {
		t.Fatal(err)
	}
	b.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, from, err := b.conn.ReadFromUDPAddrPort(buf)
	if err != nil || string(buf[:n]) != "ping over punched path" {
		t.Fatalf("data over the path: %v %q", err, buf[:n])
	}
	if from != b.remote {
		t.Errorf("data from %s, nominated %s", from, b.remote)
	}
}

func TestDirectOverUDP(t *testing.T) {
	a, b := punchPair(t, Profile{Mapping: MappingIndependent}, Profile{Mapping: MappingIndependent})
	if a.err != nil || b.err != nil {
		t.Fatalf("punch: %v / %v", a.err, b.err)
	}
	exchange(t, a, b)
	exchange(t, b, a)
}

// B claims dependent mapping, so it opens extra sockets toward A; the
// runner must hand back the winning socket and close the rest.
func TestOpenStrategyOverUDP(t *testing.T) {
	a, b := punchPair(t, Profile{Mapping: MappingIndependent}, Profile{Mapping: MappingDependent, Allocation: AllocBlock})
	if a.err != nil || b.err != nil {
		t.Fatalf("punch: %v / %v", a.err, b.err)
	}
	exchange(t, a, b)
	exchange(t, b, a)
}

func TestRelayNeededFailsFast(t *testing.T) {
	random := Profile{Mapping: MappingDependent, Allocation: AllocRandom}
	start := time.Now()
	a, b := punchPair(t, random, random)
	if a.err != ErrRelayNeeded || b.err != ErrRelayNeeded {
		t.Fatalf("errors: %v / %v", a.err, b.err)
	}
	if time.Since(start) > time.Second {
		t.Errorf("relay-needed took %v; should fail without probing", time.Since(start))
	}
}

// Abort must stop a runner whose reader is blocked handing packets to an
// inbox nobody drains (between Gather and Punch).
func TestAbortUnblocksReader(t *testing.T) {
	c := loopbackConn(t)
	r := NewRunner(New(Config{Rand: rand.New(rand.NewPCG(4, 4))}), c)
	flood := loopbackConn(t)
	for range 400 {
		flood.WriteToUDPAddrPort([]byte("x"), addrOf(c))
	}
	time.Sleep(100 * time.Millisecond) // let the reader fill the inbox and block
	done := make(chan struct{})
	go func() { r.Abort(); r.Abort(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Abort did not stop a blocked reader")
	}
}

// Extra sockets open on the base socket's IP and family, IPv6 included.
func TestExtraSocketsMatchIPv6Base(t *testing.T) {
	base, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skip("no IPv6 loopback:", err)
	}
	defer base.Close()
	s := New(Config{Initiator: true, Secret: []byte("0123456789abcdef0123456789abcdef"), Local: Profile{Mapping: MappingDependent, Allocation: AllocRandom}, Rand: rand.New(rand.NewPCG(9, 9))})
	s.Start(time.Now(), Offer{Candidates: []netip.AddrPort{netip.MustParseAddrPort("[2001:db8::1]:40000")}, Profile: Profile{Mapping: MappingIndependent}})
	if s.Sockets() < 2 {
		t.Fatalf("plan opens %d sockets; the test needs extras", s.Sockets())
	}
	r := NewRunner(s, base)
	defer r.Abort()
	if _, err := r.flush(); err != nil {
		t.Fatalf("opening extra sockets on an IPv6 base: %v", err)
	}
	for i, c := range r.conns {
		if ip := c.LocalAddr().(*net.UDPAddr).IP; !ip.Equal(net.IPv6loopback) {
			t.Fatalf("socket %d bound to %v, want ::1", i, ip)
		}
	}
}

// On a dual-stack wildcard base, extra sockets must still reach IPv4 peers.
// (Linux rejects IPv4 sends on v6-only sockets; macOS may not, so this
// guards the fix where it matters.)
func TestExtraSocketsOnDualStackBaseReachIPv4(t *testing.T) {
	base, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	if ip := base.LocalAddr().(*net.UDPAddr).IP; ip.To4() != nil {
		t.Skip("no dual-stack wildcard socket here")
	}
	peer := loopbackConn(t)
	defer peer.Close()
	s := New(Config{Initiator: true, Secret: []byte("0123456789abcdef0123456789abcdef"), Local: Profile{Mapping: MappingDependent, Allocation: AllocRandom}, Rand: rand.New(rand.NewPCG(10, 10))})
	s.Start(time.Now(), Offer{Candidates: []netip.AddrPort{addrOf(peer)}, Profile: Profile{Mapping: MappingIndependent}})
	r := NewRunner(s, base)
	defer r.Abort()
	if _, err := r.flush(); err != nil {
		t.Fatal(err)
	}
	for i, c := range r.conns[1:] {
		if _, err := c.WriteToUDPAddrPort([]byte("x"), addrOf(peer)); err != nil {
			t.Fatalf("extra socket %d can't send to an IPv4 peer: %v", i+1, err)
		}
	}
}
