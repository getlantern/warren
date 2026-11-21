package utpshape

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// tap records every datagram written through a PacketConn.
type tap struct {
	net.PacketConn
	mu   sync.Mutex
	sent [][]byte
	drop func(b []byte) bool
}

func (t *tap) WriteTo(b []byte, addr net.Addr) (int, error) {
	t.mu.Lock()
	t.sent = append(t.sent, append([]byte(nil), b...))
	drop := t.drop != nil && t.drop(b)
	t.mu.Unlock()
	if drop {
		return len(b), nil
	}
	return t.PacketConn.WriteTo(b, addr)
}

func (t *tap) packets() [][]byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([][]byte(nil), t.sent...)
}

func pair(t testing.TB) (a, b *Conn, ta, tb *tap) {
	t.Helper()
	ua, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ub, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ua.Close(); ub.Close() })
	ta, tb = &tap{PacketConn: ua}, &tap{PacketConn: ub}
	return New(ta, []byte("shared")), New(tb, []byte("shared")), ta, tb
}

func recv(t testing.TB, c *Conn) ([]byte, net.Addr) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	n, from, err := c.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n], from
}

func TestRoundTrip(t *testing.T) {
	a, b, _, _ := pair(t)
	for _, size := range []int{0, 1, 100, 1200, 1452} {
		msg := bytes.Repeat([]byte{byte(size)}, size)
		if _, err := a.WriteTo(msg, b.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		got, from := recv(t, b)
		if !bytes.Equal(got, msg) {
			t.Fatalf("size %d: got %d bytes", size, len(got))
		}
		if _, err := b.WriteTo(append(msg, 'r'), from); err != nil {
			t.Fatal(err)
		}
		if got, _ := recv(t, a); !bytes.Equal(got, append(msg, 'r')) {
			t.Fatalf("reply size %d mismatch", size)
		}
	}
}

func TestWrongKeyGarbles(t *testing.T) {
	a, b, _, _ := pair(t)
	b.block = New(nil, []byte("other key")).block
	a.WriteTo([]byte("secret message"), b.LocalAddr())
	if got, _ := recv(t, b); bytes.Equal(got, []byte("secret message")) {
		t.Fatal("decrypted with the wrong key")
	}
}

type hdr struct {
	typ, ver   byte
	connID     uint16
	ts, tsDiff uint32
	wnd        uint32
	seq, ack   uint16
}

func parse(b []byte) hdr {
	return hdr{
		typ: b[0] >> 4, ver: b[0] & 0x0f, connID: binary.BigEndian.Uint16(b[2:]),
		ts: binary.BigEndian.Uint32(b[4:]), tsDiff: binary.BigEndian.Uint32(b[8:]),
		wnd: binary.BigEndian.Uint32(b[12:]), seq: binary.BigEndian.Uint16(b[16:]), ack: binary.BigEndian.Uint16(b[18:]),
	}
}

// The header sequence follows BEP 29's connection rules.
func TestBEP29Conversation(t *testing.T) {
	a, b, ta, tb := pair(t)
	for i := range 5 {
		a.WriteTo(fmt.Append(nil, "ping ", i), b.LocalAddr())
		_, from := recv(t, b)
		b.WriteTo(fmt.Append(nil, "pong ", i), from)
		recv(t, a)
	}
	pa, pb := ta.packets(), tb.packets()
	syn := parse(pa[0])
	if syn.typ != stSyn || syn.ver != 1 || len(pa[0]) != HeaderLen {
		t.Fatalf("first packet %+v (len %d), want an empty ST_SYN", syn, len(pa[0]))
	}
	state := parse(pb[0])
	if state.typ != stState || state.connID != syn.connID || state.ack != syn.seq {
		t.Fatalf("reply %+v, want ST_STATE on the SYN's id acking its seq", state)
	}
	var lastSeq uint16
	for i, p := range pa[1:] {
		h := parse(p)
		if h.typ != stData || h.connID != syn.connID+1 {
			t.Fatalf("initiator packet %d: %+v, want ST_DATA on id+1", i, h)
		}
		if i > 0 && h.seq != lastSeq+1 {
			t.Fatalf("initiator seq %d after %d", h.seq, lastSeq)
		}
		lastSeq = h.seq
		if h.wnd != advertisedWindow {
			t.Fatalf("wnd %d", h.wnd)
		}
	}
	for i, p := range pb[1:] {
		h := parse(p)
		if h.typ != stData || h.connID != syn.connID {
			t.Fatalf("responder packet %d: %+v, want ST_DATA on the SYN's id", i, h)
		}
		if want := parse(pa[1+i]).seq; h.ack != want {
			t.Fatalf("responder ack %d, want initiator's seq %d", h.ack, want)
		}
	}
}

func TestSurvivesLostSyn(t *testing.T) {
	a, b, ta, _ := pair(t)
	ta.drop = func(p []byte) bool { return p[0]>>4 == stSyn }
	a.WriteTo([]byte("first"), b.LocalAddr())
	got, from := recv(t, b)
	if string(got) != "first" {
		t.Fatalf("got %q", got)
	}
	b.WriteTo([]byte("back"), from)
	if got, _ := recv(t, a); string(got) != "back" {
		t.Fatalf("got %q", got)
	}
}

// Encrypted payloads must not repeat or leak structure, even for identical
// plaintexts: here, 500 copies of a QUIC long-header-like packet.
func TestPayloadLooksRandom(t *testing.T) {
	a, b, ta, _ := pair(t)
	quicish := append([]byte{0xc0, 0, 0, 0, 1, 8}, bytes.Repeat([]byte{0}, 1194)...)
	for range 500 {
		a.WriteTo(quicish, b.LocalAddr())
		recv(t, b)
	}
	var counts [256]int
	seen := map[string]bool{}
	total := 0
	for _, p := range ta.packets()[1:] {
		body := p[HeaderLen:]
		if seen[string(body[:16])] {
			t.Fatal("two packets share a keystream prefix")
		}
		seen[string(body[:16])] = true
		for _, c := range body {
			counts[c]++
			total++
		}
	}
	// Chi-square against uniform bytes; 255 degrees of freedom, p≈0.001 at 330.
	exp := float64(total) / 256
	chi := 0.0
	for _, n := range counts {
		d := float64(n) - exp
		chi += d * d / exp
	}
	if chi > 330 {
		t.Fatalf("payload bytes are not uniform: chi-square %.0f", chi)
	}
}

// Wireshark's BitTorrent uTP dissector, a protocol classifier like those in
// DPI equipment, must recognize the traffic as uTP.
func TestWiresharkSeesUTP(t *testing.T) {
	tshark := "/Applications/Wireshark.app/Contents/MacOS/tshark"
	if _, err := os.Stat(tshark); err != nil {
		if tshark, err = exec.LookPath("tshark"); err != nil {
			t.Skip("tshark not installed")
		}
	}
	a, b, ta, tb := pair(t)
	for i := range 4 {
		a.WriteTo(bytes.Repeat([]byte{byte(i)}, 1200), b.LocalAddr())
		_, from := recv(t, b)
		b.WriteTo(bytes.Repeat([]byte{byte(i)}, 300), from)
		recv(t, a)
	}
	path := filepath.Join(t.TempDir(), "utp.pcap")
	writePcap(t, path, ta.packets(), tb.packets(),
		a.LocalAddr().(*net.UDPAddr).AddrPort().Port(), b.LocalAddr().(*net.UDPAddr).AddrPort().Port())
	out, err := exec.Command(tshark, "-r", path, "-o", "bt-utp.enable:TRUE", "-T", "fields", "-e", "_ws.col.Protocol", "-e", "bt-utp.type").CombinedOutput()
	if err != nil {
		t.Fatalf("tshark: %v\n%s", err, out)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	types := map[string]int{}
	for _, l := range lines {
		f := strings.Fields(l)
		// The protocol column names the top layer: uTP, or BitTorrent when the
		// dissector also hands the payload to its BitTorrent parser.
		if len(f) < 2 || (f[0] != "BT-uTP" && f[0] != "BitTorrent") {
			t.Fatalf("tshark classified a packet as %q:\n%s", l, out)
		}
		types[f[0]+" type "+f[1]]++
	}
	t.Logf("tshark: %d packets, all parsed as uTP: %v", len(lines), types)
}

// writePcap writes the two sides' datagrams, interleaved, as IPv4/UDP.
func writePcap(t *testing.T, path string, aSent, bSent [][]byte, aPort, bPort uint16) {
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, []uint32{0xa1b2c3d4, 0x00040002, 0, 0, 65535, 101}) // DLT_RAW
	ts := uint32(1_800_000_000)
	emit := func(p []byte, src, dst byte, sport, dport uint16) {
		pkt := make([]byte, 28+len(p))
		pkt[0], pkt[8], pkt[9] = 0x45, 64, 17
		binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
		copy(pkt[12:], []byte{10, 0, 0, src})
		copy(pkt[16:], []byte{10, 0, 0, dst})
		var sum uint32
		for i := 0; i < 20; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(pkt[i:]))
		}
		binary.BigEndian.PutUint16(pkt[10:], ^uint16(sum+sum>>16))
		binary.BigEndian.PutUint16(pkt[20:], sport)
		binary.BigEndian.PutUint16(pkt[22:], dport)
		binary.BigEndian.PutUint16(pkt[24:], uint16(8+len(p)))
		copy(pkt[28:], p)
		ts++
		binary.Write(&buf, binary.LittleEndian, []uint32{ts, 0, uint32(len(pkt)), uint32(len(pkt))})
		buf.Write(pkt)
	}
	for i := 0; i < max(len(aSent), len(bSent)); i++ {
		if i < len(aSent) {
			emit(aSent[i], 1, 2, aPort, bPort)
		}
		if i < len(bSent) {
			emit(bSent[i], 2, 1, bPort, aPort)
		}
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

// discard is a PacketConn whose writes vanish, isolating shaping cost.
type discard struct{ net.PacketConn }

func (discard) WriteTo(b []byte, _ net.Addr) (int, error) { return len(b), nil }

func BenchmarkWrite1200(b *testing.B) {
	c := New(discard{}, []byte("k"))
	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 6881}
	msg := make([]byte, 1200)
	b.SetBytes(int64(len(msg)))
	b.ReportAllocs()
	for b.Loop() {
		c.WriteTo(msg, addr)
	}
}

func BenchmarkRoundTripUDP(b *testing.B) {
	a, c, _, _ := pair(b)
	msg := make([]byte, 1200)
	buf := make([]byte, 2048)
	b.SetBytes(int64(len(msg)))
	b.ReportAllocs()
	for b.Loop() {
		a.WriteTo(msg, c.LocalAddr())
		c.ReadFrom(buf)
	}
}

// An oversized datagram must be dropped, not surfaced as an error: QUIC
// treats read errors as fatal, so one crafted packet would kill the transport.
func TestOversizedDatagramDropped(t *testing.T) {
	a, b, _, _ := pair(t)
	a.WriteTo(make([]byte, 3000), b.LocalAddr())
	a.WriteTo([]byte("after"), b.LocalAddr())
	b.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := b.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "after" {
		t.Fatalf("got %q, %v; want the oversized datagram skipped", buf[:n], err)
	}
}

// Two packets in the same microsecond, with consecutive sequence numbers,
// must not share keystream: before the fix, packet N's second block used
// the counter of packet N+1's first.
func TestSameTimestampNoKeystreamReuse(t *testing.T) {
	c := New(nopConn{}, []byte("key"))
	h1 := make([]byte, HeaderLen)
	binary.BigEndian.PutUint16(h1[2:], 7)
	binary.BigEndian.PutUint32(h1[4:], 123456)
	binary.BigEndian.PutUint32(h1[12:], advertisedWindow)
	binary.BigEndian.PutUint16(h1[16:], 100)
	h2 := append([]byte(nil), h1...)
	binary.BigEndian.PutUint16(h2[16:], 101)
	zeros := make([]byte, 4*aes.BlockSize)
	k1, k2 := make([]byte, len(zeros)), make([]byte, len(zeros))
	c.xor(k1, zeros, h1)
	c.xor(k2, zeros, h2)
	for i := 0; i < len(k1); i += aes.BlockSize {
		for j := 0; j < len(k2); j += aes.BlockSize {
			if bytes.Equal(k1[i:i+aes.BlockSize], k2[j:j+aes.BlockSize]) {
				t.Fatalf("packet %d block %d reuses packet %d block %d keystream", 100, i/aes.BlockSize, 101, j/aes.BlockSize)
			}
		}
	}
}

type nopConn struct{ net.PacketConn }
