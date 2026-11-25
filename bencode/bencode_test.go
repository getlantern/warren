package bencode

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestRoundTrip(t *testing.T) {
	for _, in := range []string{
		"i0e", "i-42e", "i9223372036854775807e", "0:", "4:spam",
		"le", "de", "l4:spami42ee",
		"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe",
	} {
		v, err := Decode([]byte(in))
		if err != nil {
			t.Fatalf("Decode(%q): %v", in, err)
		}
		if string(v.Raw) != in {
			t.Errorf("Raw = %q, want %q", v.Raw, in)
		}
		if out := Append(nil, v); string(out) != in {
			t.Errorf("Append(Decode(%q)) = %q", in, out)
		}
	}
}

func TestRejects(t *testing.T) {
	for _, in := range []string{
		"", "i", "ie", "i-0e", "i03e", "i-e", "i1x2e", "i99999999999999999999e",
		"01:a", "5:abc", "l", "d", "d1:ae", "di1ei2ee",
		"d1:ai1e1:ai2ee", // duplicate key
		"i1ei2e",         // trailing
		"x",
	} {
		if _, err := Decode([]byte(in)); err == nil {
			t.Errorf("Decode(%q) succeeded, want error", in)
		}
	}
}

func TestUnsortedKeysAccepted(t *testing.T) {
	v, err := Decode([]byte("d1:bi2e1:ai1ee"))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(Append(nil, v)); got != "d1:ai1e1:bi2ee" {
		t.Errorf("canonical re-encode = %q", got)
	}
}

func TestBounds(t *testing.T) {
	deep := strings.Repeat("l", MaxDepth+2) + strings.Repeat("e", MaxDepth+2)
	if _, err := Decode([]byte(deep)); err != ErrDepth {
		t.Errorf("deep nesting: err = %v, want ErrDepth", err)
	}
	wide := "l" + strings.Repeat("i1e", MaxElements+1) + "e"
	if _, err := Decode([]byte(wide)); err != ErrTooLarge {
		t.Errorf("wide list: err = %v, want ErrTooLarge", err)
	}
}

func FuzzDecode(f *testing.F) {
	for _, s := range []string{"i1e", "4:spam", "l4:spami42ee", "d1:ai1e1:bl0:ee"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		v, err := Decode(b)
		if err != nil {
			return
		}
		if !bytes.Equal(v.Raw, b) {
			t.Fatalf("Raw does not cover input")
		}
		// A canonical re-encoding must decode to the same canonical form.
		c := Append(nil, v)
		v2, err := Decode(c)
		if err != nil {
			t.Fatalf("re-decode of %q: %v", c, err)
		}
		if c2 := Append(nil, v2); !bytes.Equal(c, c2) {
			t.Fatalf("canonical form unstable: %q vs %q", c, c2)
		}
	})
}

func TestLargeDictDuplicateCheck(t *testing.T) {
	build := func(n int, dupAt int) []byte {
		b := []byte{'d'}
		for i := range n {
			k := i
			if i == dupAt {
				k = 0
			}
			key := []byte(fmt.Sprintf("k%07d", k))
			b = AppendBytes(b, key)
			b = AppendInt(b, 1)
		}
		return append(b, 'e')
	}
	start := time.Now()
	if _, err := DecodeLimit(build(100000, -1), 1<<20); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("a 100,000-key dictionary took %v", d)
	}
	for _, at := range []int{1, smallDict, smallDict + 1, 99999} {
		if _, err := DecodeLimit(build(100000, at), 1<<20); err != ErrDupKey {
			t.Fatalf("a duplicate at %d: %v", at, err)
		}
	}
}
