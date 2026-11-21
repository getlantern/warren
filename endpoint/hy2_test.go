package endpoint

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/getlantern/warren/transport/hy2"
)

// Connect by public key, then run hysteria2 shaped as BitTorrent uTP over
// the punched socket, authenticated against both ends' keys.
func TestConnectThenHysteria2(t *testing.T) {
	seed := network(t, 10)
	provider, caller := phone(t, seed), phone(t, seed)
	pk, ck := key("provider"), key("caller")
	listenAndWait(t, provider, pk)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
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

	srv, err := hy2.Serve(ctx, in.UDPConn, pk, hy2.FromSecret(in.Secret, hy2.ObfsUTP), func(c net.Conn, _ string) {
		io.Copy(c, c)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	cl, err := hy2.Dial(ctx, out.UDPConn, out.Remote, out.PeerKey, hy2.FromSecret(out.Secret, hy2.ObfsUTP))
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()

	stream, err := cl.DialConn(ctx, "echo:1")
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	msg := bytes.Repeat([]byte("over a punched, uTP-shaped hysteria2 path "), 2000)
	go stream.Write(msg)
	got := make([]byte, len(msg))
	stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(stream, got); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("echo over hysteria2: %v", err)
	}
}
