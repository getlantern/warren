package krpc

import (
	"encoding/binary"
	"encoding/hex"
	"net/netip"
)

type NodeID [20]byte

func (id NodeID) String() string { return hex.EncodeToString(id[:]) }

type NodeInfo struct {
	ID   NodeID
	Addr netip.AddrPort
}

const (
	compactAddr4 = 6
	compactAddr6 = 18
	compactNode4 = 20 + compactAddr4
	compactNode6 = 20 + compactAddr6
)

// AppendCompactAddr writes the BEP 5 compact form: IP bytes then a big-endian port.
func AppendCompactAddr(b []byte, ap netip.AddrPort) []byte {
	ip := ap.Addr().Unmap()
	if ip.Is4() {
		a := ip.As4()
		b = append(b, a[:]...)
	} else {
		a := ip.As16()
		b = append(b, a[:]...)
	}
	return binary.BigEndian.AppendUint16(b, ap.Port())
}

// ParseCompactAddr parses a 6- or 18-byte compact address.
func ParseCompactAddr(b []byte) (netip.AddrPort, bool) {
	var ip netip.Addr
	switch len(b) {
	case compactAddr4:
		ip = netip.AddrFrom4([4]byte(b[:4]))
	case compactAddr6:
		ip = netip.AddrFrom16([16]byte(b[:16]))
	default:
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ip, binary.BigEndian.Uint16(b[len(b)-2:])), true
}

// parseCompactNodes splits a "nodes"/"nodes6" string. A trailing partial entry
// is ignored rather than rejecting the whole reply, matching common clients.
func parseCompactNodes(b []byte, size int) []NodeInfo {
	nodes := make([]NodeInfo, 0, len(b)/size)
	for ; len(b) >= size; b = b[size:] {
		ap, _ := ParseCompactAddr(b[20:size])
		if !ap.Addr().IsValid() || ap.Port() == 0 {
			continue
		}
		nodes = append(nodes, NodeInfo{ID: NodeID(b[:20]), Addr: ap})
	}
	return nodes
}

func appendCompactNodes(b []byte, nodes []NodeInfo) []byte {
	for _, n := range nodes {
		b = append(b, n.ID[:]...)
		b = AppendCompactAddr(b, n.Addr)
	}
	return b
}

// ParseNodes parses a compact "nodes" (IPv4) or "nodes6" (IPv6) string.
func ParseNodes(b []byte, ipv6 bool) []NodeInfo {
	if ipv6 {
		return parseCompactNodes(b, compactNode6)
	}
	return parseCompactNodes(b, compactNode4)
}

// AppendNodes appends nodes in compact form. Callers keep IPv4 and IPv6
// nodes in separate strings.
func AppendNodes(b []byte, nodes []NodeInfo) []byte { return appendCompactNodes(b, nodes) }
