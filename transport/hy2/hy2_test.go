package hy2

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func key(seed string) ed25519.PrivateKey {
	s := sha256.Sum256([]byte(seed))
	return ed25519.NewKeyFromSeed(s[:])
}

func udp(t testing.TB) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var modes = []struct {
	name string
	obfs Obfs
}{{"none", ObfsNone}, {"salamander", ObfsSalamander}, {"utp", ObfsUTP}}

// echoOrCount echoes "echo" streams and counts "sink" streams, replying with
// the byte count.
func echoOrCount(conn net.Conn, dst string) {
	switch dst {
	case "echo:1":
		io.Copy(conn, conn)
	case "sink:1":
		// Length-prefixed: hysteria2 streams have no half-close.
		var want int64
		if binary.Read(conn, binary.BigEndian, &want) != nil {
			return
		}
		n, _ := io.CopyN(io.Discard, conn, want)
		binary.Write(conn, binary.BigEndian, n)
	}
}

func setup(t testing.TB, obfs Obfs, clientPeer [32]byte, clientPassword string) (*Client, func()) {
	t.Helper()
	srvKey := key("server")
	sc, cc := udp(t), udp(t)
	opts := Options{Obfs: obfs, ObfsKey: []byte("shared obfs"), Password: "pw"}
	srv, err := Serve(context.Background(), sc, srvKey, opts, echoOrCount)
	if err != nil {
		t.Fatal(err)
	}
	copts := opts
	copts.Password = clientPassword
	cl, err := Dial(context.Background(), cc, sc.LocalAddr().(*net.UDPAddr).AddrPort(), clientPeer, copts)
	if err != nil {
		t.Fatal(err)
	}
	return cl, func() { cl.Close(); srv.Close() }
}

func serverKey() [32]byte { return [32]byte(key("server").Public().(ed25519.PublicKey)) }

func TestEcho(t *testing.T) {
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			cl, done := setup(t, m.obfs, serverKey(), "pw")
			defer done()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			conn, err := cl.DialConn(ctx, "echo:1")
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			msg := bytes.Repeat([]byte("warren "), 5000)
			go conn.Write(msg)
			got := make([]byte, len(msg))
			conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, msg) {
				t.Fatalf("echo: %v", err)
			}
		})
	}
}

func dialFails(t *testing.T, peer [32]byte, password string) {
	t.Helper()
	cl, done := setup(t, ObfsUTP, peer, password)
	defer done()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := cl.DialConn(ctx, "echo:1")
	if err == nil {
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err = conn.Write([]byte("x")); err == nil {
			_, err = conn.Read(make([]byte, 1))
		}
		conn.Close()
	}
	if err == nil {
		t.Fatal("connection succeeded")
	}
	t.Logf("rejected: %v", err)
}

func TestRejectsWrongServerKey(t *testing.T) {
	dialFails(t, [32]byte(key("impostor").Public().(ed25519.PublicKey)), "pw")
}

func TestRejectsWrongPassword(t *testing.T) { dialFails(t, serverKey(), "wrong") }

// TestThroughput sends 64 MiB through hysteria2 over loopback in each mode.
// Loopback has no loss or delay, so this measures CPU cost, not congestion
// behavior.
func TestThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("throughput run")
	}
	const total = 64 << 20
	chunk := make([]byte, 32<<10)
	var report string
	for _, m := range modes {
		cl, done := setup(t, m.obfs, serverKey(), "pw")
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		conn, err := cl.DialConn(ctx, "sink:1")
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		binary.Write(conn, binary.BigEndian, int64(total))
		for sent := 0; sent < total; sent += len(chunk) {
			if _, err := conn.Write(chunk); err != nil {
				t.Fatal(err)
			}
		}
		var n int64
		if err := binary.Read(conn, binary.BigEndian, &n); err != nil || n != total {
			t.Fatalf("%s: server counted %d (%v)", m.name, n, err)
		}
		el := time.Since(start)
		report += fmt.Sprintf("  %-11s %6.0f MB/s  (%v for 64 MiB)\n", m.name, total/el.Seconds()/1e6, el.Round(time.Millisecond))
		conn.Close()
		cancel()
		done()
	}
	t.Log("\nhysteria2 over loopback UDP\n" + report)
}

// quic-go assumes Don't Fragment on any wrapped socket, so MTU discovery
// must be off whenever we could not set it, in every mode. Loopback's large
// MTU would hide the resulting fragmentation, so check the options directly.
func TestMTUDiscoveryRequiresDontFragment(t *testing.T) {
	for _, m := range modes {
		o := Options{Obfs: m.obfs}
		if !o.quic(nil, false).DisablePathMTUDiscovery {
			t.Errorf("%s: MTU discovery enabled without Don't Fragment", m.name)
		}
		if o.quic(nil, true).DisablePathMTUDiscovery {
			t.Errorf("%s: MTU discovery disabled despite Don't Fragment", m.name)
		}
	}
	c := udp(t)
	defer c.Close()
	if !dontFragment(c) {
		t.Log("Don't Fragment unsupported on this platform; MTU discovery stays off")
	}
}

// The receive-window caps are what keep a transfer inside the iOS network
// extension's budget; hysteria2's own defaults are 8 and 20 MiB.
func TestReceiveWindowCaps(t *testing.T) {
	q := (&Options{}).quic(nil, true)
	if q.StreamReceiveWindow != 1<<20 || q.ConnectionReceiveWindow != 5<<19 {
		t.Fatalf("default windows %d / %d, want 1 MiB / 2.5 MiB", q.StreamReceiveWindow, q.ConnectionReceiveWindow)
	}
	q = (&Options{StreamWindow: 3 << 20, ConnWindow: 6 << 20}).quic(nil, true)
	if q.StreamReceiveWindow != 3<<20 || q.ConnectionReceiveWindow != 6<<20 {
		t.Fatalf("explicit windows not honored: %d / %d", q.StreamReceiveWindow, q.ConnectionReceiveWindow)
	}
}
