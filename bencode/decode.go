// Package bencode is a small, bounded bencode codec sized for KRPC datagrams.
//
// Decoded strings alias the input buffer rather than copying it, so a Value is
// only valid while the buffer it was decoded from is unchanged.
package bencode

import (
	"bytes"
	"errors"
	"strconv"
)

var (
	ErrSyntax   = errors.New("bencode: syntax error")
	ErrDepth    = errors.New("bencode: nesting too deep")
	ErrTooLarge = errors.New("bencode: too many elements")
	ErrTrailing = errors.New("bencode: trailing data")
	ErrDupKey   = errors.New("bencode: duplicate dictionary key")
)

const (
	// MaxDepth bounds nesting. KRPC needs four levels; BEP 44 values may nest a
	// little further.
	MaxDepth = 16
	// MaxElements bounds the total number of values in one document, so a
	// datagram of tiny elements cannot force a large allocation.
	MaxElements = 1024
)

type Kind uint8

const (
	Invalid Kind = iota
	Int
	String
	List
	Dict
)

type Value struct {
	Kind Kind
	Int  int64
	Str  []byte
	List []Value
	Dict []Pair
	// Raw is the exact encoding of this value within the input.
	Raw []byte
}

type Pair struct {
	Key   []byte
	Value Value
}

// Get returns the value for key in a dictionary.
func (v Value) Get(key string) (Value, bool) {
	if v.Kind != Dict {
		return Value{}, false
	}
	for _, p := range v.Dict {
		if string(p.Key) == key {
			return p.Value, true
		}
	}
	return Value{}, false
}

// Decode parses exactly one bencoded value occupying all of b.
func Decode(b []byte) (Value, error) { return DecodeLimit(b, MaxElements) }

// DecodeLimit is Decode with a caller's bound on the number of values, for
// documents larger than a datagram. A bound of zero or less admits
// nothing.
func DecodeLimit(b []byte, maxElements int) (Value, error) {
	if maxElements <= 0 {
		return Value{}, ErrTooLarge
	}
	d := decoder{buf: b, limit: maxElements}
	v, err := d.value(0)
	if err != nil {
		return Value{}, err
	}
	if d.pos != len(b) {
		return Value{}, ErrTrailing
	}
	return v, nil
}

// smallDict is how many keys a dictionary holds before the duplicate check
// switches from a pairwise scan to a set.
const smallDict = 16

type decoder struct {
	buf      []byte
	pos      int
	elements int
	limit    int
}

func (d *decoder) value(depth int) (Value, error) {
	if depth > MaxDepth {
		return Value{}, ErrDepth
	}
	if d.elements++; d.elements > d.limit {
		return Value{}, ErrTooLarge
	}
	if d.pos >= len(d.buf) {
		return Value{}, ErrSyntax
	}
	start := d.pos
	var v Value
	var err error
	switch c := d.buf[d.pos]; {
	case c == 'i':
		v, err = d.integer()
	case c >= '0' && c <= '9':
		v, err = d.str()
	case c == 'l':
		v, err = d.list(depth)
	case c == 'd':
		v, err = d.dict(depth)
	default:
		return Value{}, ErrSyntax
	}
	if err != nil {
		return Value{}, err
	}
	v.Raw = d.buf[start:d.pos]
	return v, nil
}

func (d *decoder) integer() (Value, error) {
	d.pos++ // 'i'
	end := bytes.IndexByte(d.buf[d.pos:], 'e')
	if end < 0 {
		return Value{}, ErrSyntax
	}
	digits := d.buf[d.pos : d.pos+end]
	if !canonicalInt(digits) {
		return Value{}, ErrSyntax
	}
	n, err := strconv.ParseInt(string(digits), 10, 64)
	if err != nil {
		return Value{}, ErrSyntax
	}
	d.pos += end + 1
	return Value{Kind: Int, Int: n}, nil
}

// canonicalInt rejects empty, "-0", "-", and leading zeros.
func canonicalInt(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	digits := b
	if b[0] == '-' {
		digits = b[1:]
		if len(digits) == 0 || digits[0] == '0' {
			return false
		}
	}
	if len(digits) > 1 && digits[0] == '0' {
		return false
	}
	for _, c := range digits {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func (d *decoder) str() (Value, error) {
	colon := bytes.IndexByte(d.buf[d.pos:], ':')
	if colon < 0 || colon > 7 { // a datagram can't hold a string longer than 7 digits
		return Value{}, ErrSyntax
	}
	digits := d.buf[d.pos : d.pos+colon]
	if len(digits) > 1 && digits[0] == '0' {
		return Value{}, ErrSyntax
	}
	n := 0
	for _, c := range digits {
		if c < '0' || c > '9' {
			return Value{}, ErrSyntax
		}
		n = n*10 + int(c-'0')
	}
	d.pos += colon + 1
	if n > len(d.buf)-d.pos {
		return Value{}, ErrSyntax
	}
	s := d.buf[d.pos : d.pos+n : d.pos+n]
	d.pos += n
	return Value{Kind: String, Str: s}, nil
}

func (d *decoder) list(depth int) (Value, error) {
	d.pos++ // 'l'
	var items []Value
	for {
		if d.pos >= len(d.buf) {
			return Value{}, ErrSyntax
		}
		if d.buf[d.pos] == 'e' {
			d.pos++
			return Value{Kind: List, List: items}, nil
		}
		item, err := d.value(depth + 1)
		if err != nil {
			return Value{}, err
		}
		items = append(items, item)
	}
}

// dict accepts keys in any order (real-world encoders are not all canonical)
// but rejects duplicates, which would make the meaning implementation-defined.
func (d *decoder) dict(depth int) (Value, error) {
	d.pos++ // 'd'
	var pairs []Pair
	var seen map[string]struct{}
	for {
		if d.pos >= len(d.buf) {
			return Value{}, ErrSyntax
		}
		if d.buf[d.pos] == 'e' {
			d.pos++
			return Value{Kind: Dict, Dict: pairs}, nil
		}
		if c := d.buf[d.pos]; c < '0' || c > '9' {
			return Value{}, ErrSyntax
		}
		key, err := d.value(depth + 1)
		if err != nil {
			return Value{}, err
		}
		// A pairwise scan is cheapest for the small dictionaries KRPC
		// carries; past that, a set keeps a large dictionary linear.
		if seen != nil {
			if _, dup := seen[string(key.Str)]; dup {
				return Value{}, ErrDupKey
			}
			seen[string(key.Str)] = struct{}{}
		} else {
			for _, p := range pairs {
				if bytes.Equal(p.Key, key.Str) {
					return Value{}, ErrDupKey
				}
			}
			if len(pairs) == smallDict {
				seen = make(map[string]struct{}, 2*smallDict)
				for _, p := range pairs {
					seen[string(p.Key)] = struct{}{}
				}
				seen[string(key.Str)] = struct{}{}
			}
		}
		val, err := d.value(depth + 1)
		if err != nil {
			return Value{}, err
		}
		pairs = append(pairs, Pair{Key: key.Str, Value: val})
	}
}
