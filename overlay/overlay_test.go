package overlay

import (
	"crypto/rand"
	"net/netip"
	"testing"

	"github.com/getlantern/warren/krpc"
)

func TestMemberIDs(t *testing.T) {
	fa, ru := NewKey("fa"), NewKey("ru")
	ip := netip.MustParseAddr("5.160.12.34")
	for range 1000 {
		id := fa.NewID(ip)
		if !fa.IsMember(id) {
			t.Fatal("own member ID rejected")
		}
		if !krpc.IsSecureID(ip, id) {
			t.Fatal("member ID not BEP 42 compliant")
		}
		if ru.IsMember(id) {
			t.Fatal("member of fa accepted by ru")
		}
	}
}

func TestTamperedIDRejected(t *testing.T) {
	k := NewKey("fa")
	id := k.NewID(netip.MustParseAddr("5.160.12.34"))
	for i := range id {
		bad := id
		bad[i] ^= 0x01
		if k.IsMember(bad) {
			t.Fatalf("flip in byte %d still a member", i)
		}
	}
}

func TestRandomIDsAreNotMembers(t *testing.T) {
	k := NewKey("fa")
	for range 100000 {
		var id krpc.NodeID
		rand.Read(id[:])
		if k.IsMember(id) {
			t.Fatal("random ID accepted")
		}
	}
}

// Rewriting a member's ID for a new address keeps it a member.
func TestRetagAfterAddressChange(t *testing.T) {
	k := NewKey("fa")
	id := k.NewID(netip.MustParseAddr("5.160.12.34"))
	moved := netip.MustParseAddr("2.176.1.1")
	id = k.Tag(krpc.SecureID(moved, id))
	if !k.IsMember(id) || !krpc.IsSecureID(moved, id) {
		t.Fatal("re-tagged ID invalid")
	}
}

func BenchmarkIsMember(b *testing.B) {
	k := NewKey("fa")
	id := k.NewID(netip.MustParseAddr("5.160.12.34"))
	for b.Loop() {
		k.IsMember(id)
	}
}
