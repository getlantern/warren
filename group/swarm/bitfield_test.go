package swarm

import (
	"bytes"
	"errors"
	"testing"
)

func TestBitfield(t *testing.T) {
	f := NewBitfield(11)
	for _, i := range []uint32{0, 7, 8, 10} {
		f.Set(i)
	}
	if !f.Has(0) || !f.Has(10) || f.Has(1) || f.Has(11) || f.Count() != 4 || f.Full() {
		t.Fatal("set membership")
	}
	enc := f.Encode()
	if !bytes.Equal(enc, []byte{0x81, 0xa0}) {
		t.Fatalf("encoding %x", enc)
	}
	g, err := DecodeBitfield(enc, 11)
	if err != nil || !bytes.Equal(g.Encode(), enc) {
		t.Fatalf("round trip: %v", err)
	}
	for name, b := range map[string][]byte{
		"short":      {0x81},
		"long":       {0x81, 0xa0, 0},
		"spare bits": {0x81, 0xa1},
	} {
		if _, err := DecodeBitfield(b, 11); !errors.Is(err, ErrBitfield) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if !full(9).Full() || full(9).Count() != 9 {
		t.Fatal("a full bitfield")
	}
	if _, err := DecodeBitfield(nil, 0); err != nil {
		t.Fatalf("an empty blob's bitfield: %v", err)
	}
}

func FuzzDecodeBitfield(f *testing.F) {
	f.Add([]byte{0x81, 0xa0}, uint32(11))
	f.Fuzz(func(t *testing.T, b []byte, n uint32) {
		n %= 1 << 16
		g, err := DecodeBitfield(b, n)
		if err != nil {
			return
		}
		if !bytes.Equal(g.Encode(), b) {
			t.Fatal("a decoded bitfield doesn't encode back to its bytes")
		}
		for i := n; i < uint32(len(b))*8; i++ {
			if g.Has(i) {
				t.Fatalf("piece %d past the end is set", i)
			}
		}
	})
}
