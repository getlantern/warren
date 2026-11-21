package krpc

import (
	"hash/crc32"
	"net/netip"
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// BEP 42 masks: only these bits of the IP feed the hash, so a node keeps its
// ID while its address varies within the low bits.
var (
	mask4 = [4]byte{0x03, 0x0f, 0x3f, 0xff}
	mask6 = [8]byte{0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f, 0xff}
)

func bep42Prefix(ip netip.Addr, r byte) uint32 {
	ip = ip.Unmap()
	var buf []byte
	if ip.Is4() {
		a := ip.As4()
		for i := range a {
			a[i] &= mask4[i]
		}
		buf = a[:]
	} else {
		a16 := ip.As16()
		var a [8]byte
		for i := range a {
			a[i] = a16[i] & mask6[i]
		}
		buf = a[:]
	}
	buf[0] |= (r & 0x7) << 5
	return crc32.Checksum(buf, castagnoli)
}

// SecureID makes id BEP 42 compliant for ip, keeping its random tail. The low
// three bits of id[19] choose the hash salt, and id[19] is kept as is.
func SecureID(ip netip.Addr, id NodeID) NodeID {
	crc := bep42Prefix(ip, id[19])
	id[0] = byte(crc >> 24)
	id[1] = byte(crc >> 16)
	id[2] = byte(crc>>8)&0xf8 | id[2]&0x07
	return id
}

// IsSecureID reports whether id satisfies BEP 42 for ip. Local and private
// addresses are exempt per the BEP.
func IsSecureID(ip netip.Addr, id NodeID) bool {
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return true
	}
	crc := bep42Prefix(ip, id[19])
	return id[0] == byte(crc>>24) && id[1] == byte(crc>>16) && id[2]&0xf8 == byte(crc>>8)&0xf8
}
