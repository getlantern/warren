package endpoint

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/getlantern/warren/transport/hy2"
)

func heap() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapInuse + m.StackInuse
}

func mib(b uint64) string { return fmt.Sprintf("%.2f MiB", float64(b)/(1<<20)) }

// TestPhoneMemory measures Go memory growth for the phone configuration: a
// read-only DHT node listening as a provider, then two such phones moving
// data over hysteria2. Both phones share this process, so the transfer
// figure covers both ends of one connection. Routers run in the process too
// but are created before the baseline.
func TestPhoneMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("memory measurement")
	}
	seed := network(t, 10)
	base := heap()

	provider := phone(t, seed)
	idle := heap()
	pk, ck := key("provider"), key("caller")
	listenAndWait(t, provider, pk)
	listening := heap()

	caller := phone(t, seed)
	twoPhones := heap()

	report := fmt.Sprintf("\nGo heap+stack growth over baseline\n  one phone, bootstrapped, idle    %s\n  ...listening as a provider       %s\n  two phones (one more idle)       %s\n",
		mib(idle-base), mib(listening-base), mib(twoPhones-base))

	for _, tc := range []struct {
		name string
		opts func(hy2.Options) hy2.Options
	}{
		{"capped windows (1 / 2.5 MiB)", func(o hy2.Options) hy2.Options { return o }},
		{"hysteria2 defaults (8 / 20 MiB)", func(o hy2.Options) hy2.Options {
			o.StreamWindow, o.ConnWindow = 8<<20, 20<<20
			return o
		}},
	} {
		peak := transferPeak(t, provider, caller, pk, ck, tc.opts)
		report += fmt.Sprintf("  64 MiB over uTP hysteria2, %-30s peak %s\n", tc.name+":", mib(peak-base))
	}
	t.Log(report)
}

// transferPeak connects caller to provider, runs hysteria2 over uTP with a
// deliberately slow reader so receive windows fill, and samples peak memory
// (without forcing GC, so garbage counts, as it would against jetsam).
func transferPeak(t *testing.T, provider, caller *Endpoint, pk, ck ed25519.PrivateKey, opts func(hy2.Options) hy2.Options) uint64 {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	accepted := make(chan *Conn, 1)
	go func() {
		c, _ := provider.Accept(ctx)
		accepted <- c
	}()
	out, err := caller.Connect(ctx, ck, pub(pk))
	if err != nil {
		t.Fatal(err)
	}
	in := <-accepted
	if in == nil {
		t.Fatal("nothing accepted")
	}
	srv, err := hy2.Serve(ctx, in, pk, opts(hy2.FromSecret(in.Secret, hy2.ObfsUTP)), func(c net.Conn, _ string) {
		var want int64
		if binary.Read(c, binary.BigEndian, &want) != nil {
			return
		}
		buf := make([]byte, 64<<10)
		var got int64
		for got < want {
			n, err := c.Read(buf[:min(int64(len(buf)), want-got)])
			got += int64(n)
			if err != nil {
				break
			}
			time.Sleep(2 * time.Millisecond) // a slow consumer: ~32 MB/s
		}
		binary.Write(c, binary.BigEndian, got)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	cl, err := hy2.Dial(ctx, out, out.Remote, out.PeerKey, opts(hy2.FromSecret(out.Secret, hy2.ObfsUTP)))
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()

	var peak atomic.Uint64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		var m runtime.MemStats
		for {
			select {
			case <-stop:
				return
			case <-time.After(10 * time.Millisecond):
			}
			runtime.ReadMemStats(&m)
			if v := m.HeapInuse + m.StackInuse; v > peak.Load() {
				peak.Store(v)
			}
		}
	})
	stream, err := cl.DialConn(ctx, "sink:1")
	if err != nil {
		t.Fatal(err)
	}
	const total = 64 << 20
	binary.Write(stream, binary.BigEndian, int64(total))
	chunk := make([]byte, 32<<10)
	for sent := 0; sent < total; sent += len(chunk) {
		if _, err := stream.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	var got int64
	if err := binary.Read(stream, binary.BigEndian, &got); err != nil || got != total {
		t.Fatalf("transfer: %d bytes, %v", got, err)
	}
	stream.Close()
	close(stop)
	wg.Wait()
	return peak.Load()
}
