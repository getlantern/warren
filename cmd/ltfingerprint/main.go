// Command ltfingerprint compares our KRPC wire shape with real libtorrent.
//
// It runs a dht.Node with a packet tap next to libtorrent nodes started by
// tools/ltfingerprint/lt_peers.py, records every datagram in both directions,
// and prints the shape of each message kind for both implementations: key
// sets, transaction and token lengths, version strings, node counts, and the
// BEP 42 ip field. Any difference is a fingerprint a censor could use.
//
//	go run ./cmd/ltfingerprint -python /path/to/venv/bin/python
package main

import (
	"bufio"
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/getlantern/warren/bencode"
	"github.com/getlantern/warren/dht"
	"github.com/getlantern/warren/krpc"
)

type capture struct {
	from, to netip.AddrPort
	ours     bool // sent by our node
	data     []byte
}

func main() {
	python := flag.String("python", "python3", "interpreter with libtorrent installed")
	script := flag.String("script", "tools/ltfingerprint/lt_peers.py", "libtorrent peer script")
	seconds := flag.Int("seconds", 20, "how long libtorrent runs")
	flag.Parse()

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		log.Fatal(err)
	}
	self := conn.LocalAddr().(*net.UDPAddr).AddrPort()
	var id krpc.NodeID
	rand.Read(id[:])
	node := dht.New(dht.Config{ID: id, Unrestricted: true, QueryTimeout: time.Second})

	var mu sync.Mutex
	var caps []capture
	ops := make(chan func(time.Time), 8)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			b := append([]byte(nil), buf[:n]...)
			ops <- func(now time.Time) {
				mu.Lock()
				caps = append(caps, capture{from: from, to: self, data: b})
				mu.Unlock()
				node.HandlePacket(now, from, b)
			}
		}
	}()
	go func() {
		t := time.NewTimer(time.Second)
		for {
			select {
			case f := <-ops:
				f(time.Now())
			case <-t.C:
				node.Tick(time.Now())
			}
			sends, _ := node.Drain()
			for _, s := range sends {
				mu.Lock()
				caps = append(caps, capture{from: self, to: s.To, ours: true, data: s.Data})
				mu.Unlock()
				conn.WriteToUDPAddrPort(s.Data, s.To)
			}
			if w := node.NextWakeup(); !w.IsZero() {
				t.Reset(max(time.Until(w), 0))
			}
		}
	}()

	cmd := exec.Command(*python, "-I", *script, strconv.Itoa(int(self.Port())), strconv.Itoa(*seconds))
	cmd.Stderr = os.Stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}
	sc := bufio.NewScanner(out)
	var peers []netip.AddrPort
	ltVersion := "?"
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) > 1 && f[0] == "VERSION" {
			ltVersion = f[1]
			break
		}
		if len(f) > 1 && f[0] == "PORTS" {
			for _, p := range f[1:] {
				n, _ := strconv.Atoi(p)
				peers = append(peers, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(n)))
			}
		}
	}
	go func() {
		for sc.Scan() {
		}
	}()

	// Exercise our client side against libtorrent: bootstrap, put, get.
	ops <- func(now time.Time) {
		if _, err := node.Bootstrap(now, peers); err != nil {
			log.Print(err)
		}
	}
	time.Sleep(3 * time.Second)
	ops <- func(now time.Time) {
		if _, _, err := node.Put(now, dht.ImmutableValue([]byte("from the go node"))); err != nil {
			log.Print(err)
		}
	}
	time.Sleep(2 * time.Second)
	ops <- func(now time.Time) {
		if _, err := node.Get(now, krpc.NodeID{1, 2, 3}); err != nil {
			log.Print(err)
		}
	}
	if err := cmd.Wait(); err != nil {
		log.Printf("libtorrent peers: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if report(caps, ltVersion) > 0 {
		os.Exit(1)
	}
}

func report(caps []capture, ltVersion string) int {
	// Pair responses with the query kind by (requester, transaction id).
	type key struct {
		requester netip.AddrPort
		t         string
	}
	queryKind := map[key]string{}
	seen := map[[2]string]map[string]int{}
	add := func(impl, kind, desc string) {
		k := [2]string{kind, impl}
		if seen[k] == nil {
			seen[k] = map[string]int{}
		}
		seen[k][desc]++
	}
	for _, c := range caps {
		v, err := bencode.Decode(c.data)
		if err != nil {
			continue
		}
		y, _ := v.Get("y")
		t, _ := v.Get("t")
		impl := "libtorrent"
		if c.ours {
			impl = "ours"
		}
		switch string(y.Str) {
		case "q":
			q, _ := v.Get("q")
			queryKind[key{c.from, string(t.Str)}] = string(q.Str)
			add(impl, "query "+string(q.Str), describe(v, "a"))
		case "r", "e":
			kind := queryKind[key{c.to, string(t.Str)}]
			if kind == "" {
				kind = "?"
			}
			label := "response "
			if string(y.Str) == "e" {
				label = "error "
			}
			add(impl, label+kind, describe(v, "r"))
		}
	}
	var kinds []string
	for k := range seen {
		if !slices.Contains(kinds, k[0]) {
			kinds = append(kinds, k[0])
		}
	}
	slices.Sort(kinds)
	fmt.Printf("libtorrent %s vs ours: wire shapes by message kind (count × shape)\n\n", ltVersion)
	mismatches := 0
	for _, k := range kinds {
		lt, ours := seen[[2]string{k, "libtorrent"}], seen[[2]string{k, "ours"}]
		match := "  "
		if len(lt) > 0 && len(ours) > 0 && !sameShapes(lt, ours) {
			match = "≠ "
			mismatches++
		}
		fmt.Printf("%s%s\n", match, k)
		for _, impl := range []struct {
			name string
			m    map[string]int
		}{{"libtorrent", lt}, {"ours", ours}} {
			if len(impl.m) == 0 {
				fmt.Printf("      %-10s (not observed)\n", impl.name)
				continue
			}
			for _, d := range sortedKeys(impl.m) {
				fmt.Printf("      %-10s %3d × %s\n", impl.name, impl.m[d], d)
			}
		}
	}
	fmt.Printf("\n%d message kinds differ\n", mismatches)
	if os.Getenv("LTF_RAW") != "" {
		for _, c := range caps {
			if !c.ours {
				fmt.Printf("raw from %s: %q\n", c.from, c.data)
			}
		}
	}
	return mismatches
}

var counts = regexp.MustCompile(`\((\d+)\)`)

// sameShapes compares shapes ignoring node and value counts, which depend on
// how many peers each node happens to know.
func sameShapes(a, b map[string]int) bool {
	norm := func(m map[string]int) []string {
		var out []string
		for _, k := range sortedKeys(m) {
			k = counts.ReplaceAllString(k, "(n)")
			if !slices.Contains(out, k) {
				out = append(out, k)
			}
		}
		return out
	}
	return slices.Equal(norm(a), norm(b))
}

func sortedKeys(m map[string]int) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// describe renders the fingerprint-relevant shape of a message.
func describe(v bencode.Value, inner string) string {
	var parts []string
	var top []string
	for _, p := range v.Dict {
		top = append(top, string(p.Key))
	}
	slices.Sort(top)
	parts = append(parts, "keys{"+strings.Join(top, ",")+"}")
	if t, ok := v.Get("t"); ok {
		parts = append(parts, fmt.Sprintf("t:%dB", len(t.Str)))
	}
	if ver, ok := v.Get("v"); ok {
		parts = append(parts, fmt.Sprintf("v:%q", ver.Str[:min(2, len(ver.Str))])+fmt.Sprintf("+%dB", max(0, len(ver.Str)-2)))
	}
	if ip, ok := v.Get("ip"); ok {
		parts = append(parts, fmt.Sprintf("ip:%dB", len(ip.Str)))
	}
	if ro, ok := v.Get("ro"); ok {
		parts = append(parts, fmt.Sprintf("ro:%d", ro.Int))
	}
	d, ok := v.Get(inner)
	if !ok {
		if e, ok := v.Get("e"); ok && len(e.List) == 2 {
			parts = append(parts, fmt.Sprintf("e[%d,%q]", e.List[0].Int, e.List[1].Str))
		}
		return strings.Join(parts, " ")
	}
	var ik []string
	for _, p := range d.Dict {
		k := string(p.Key)
		switch k {
		case "token":
			k += fmt.Sprintf("(%dB)", len(p.Value.Str))
		case "nodes":
			k += fmt.Sprintf("(%d)", len(p.Value.Str)/26)
		case "nodes6":
			k += fmt.Sprintf("(%d)", len(p.Value.Str)/38)
		case "values":
			k += fmt.Sprintf("(%d)", len(p.Value.List))
		case "want":
			var w []string
			for _, x := range p.Value.List {
				w = append(w, string(x.Str))
			}
			k += "(" + strings.Join(w, ",") + ")"
		}
		ik = append(ik, k)
	}
	slices.Sort(ik)
	parts = append(parts, inner+"{"+strings.Join(ik, ",")+"}")
	return strings.Join(parts, " ")
}
