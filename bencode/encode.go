package bencode

import (
	"bytes"
	"slices"
	"strconv"
)

// The Append* functions write directly into a caller-owned buffer so the KRPC
// encoder can build a datagram with a single, reusable allocation. Callers
// writing dictionaries by hand must emit keys in ascending byte order.

func AppendInt(b []byte, n int64) []byte {
	b = append(b, 'i')
	b = strconv.AppendInt(b, n, 10)
	return append(b, 'e')
}

func AppendBytes(b, s []byte) []byte {
	b = strconv.AppendInt(b, int64(len(s)), 10)
	b = append(b, ':')
	return append(b, s...)
}

func AppendString(b []byte, s string) []byte {
	b = strconv.AppendInt(b, int64(len(s)), 10)
	b = append(b, ':')
	return append(b, s...)
}

// Append encodes v canonically, sorting dictionary keys.
func Append(b []byte, v Value) []byte {
	switch v.Kind {
	case Int:
		return AppendInt(b, v.Int)
	case String:
		return AppendBytes(b, v.Str)
	case List:
		b = append(b, 'l')
		for _, item := range v.List {
			b = Append(b, item)
		}
		return append(b, 'e')
	case Dict:
		pairs := slices.Clone(v.Dict)
		slices.SortFunc(pairs, func(x, y Pair) int { return bytes.Compare(x.Key, y.Key) })
		b = append(b, 'd')
		for _, p := range pairs {
			b = AppendBytes(b, p.Key)
			b = Append(b, p.Value)
		}
		return append(b, 'e')
	}
	return b
}
