// Package dht is a sans-IO Mainline DHT node. It consumes datagrams and
// caller-supplied time and produces datagrams to send, events, and the time it
// next needs to be woken. It opens no sockets, starts no goroutines, and reads
// no clock, so the same code runs over UDP and in the deterministic simulator.
//
// A node with a community key runs a community overlay (see package overlay)
// alongside a Mainline personality: queriers whose IDs carry the community tag
// are answered from the community routing table, everyone else from the
// Mainline table, so outsiders see an ordinary BitTorrent node.
package dht

import (
	"math/rand/v2"
	"net/netip"
	"time"

	"github.com/getlantern/warren/krpc"
	"github.com/getlantern/warren/overlay"
)

// DefaultVersion is the KRPC "v" string: libtorrent's "LT", then major and
// minor<<4|patch. libtorrent sends it in every message, so omitting it is a
// fingerprint. 2.1.1 is the version whose wire behavior cmd/ltfingerprint
// verifies we match.
var DefaultVersion = []byte("LT\x02\x11")

type Config struct {
	ID krpc.NodeID
	// Community, when set, makes this node a member of that overlay. Its ID
	// must carry the community tag.
	Community *overlay.Key
	// ReadOnly nodes (BEP 43) query but never answer and never enter
	// routing tables. Phones behind CGNAT run this way.
	ReadOnly bool
	// Domestic reports whether an address is inside the community's home
	// country. With DomesticCopies, every put also goes to the K closest
	// domestic nodes, so records survive when the border closes.
	Domestic       func(netip.Addr) bool
	DomesticCopies bool
	// PartitionDetection reacts to a sudden rise in failures from routing
	// contacts by evicting faster, refreshing buckets, and republishing.
	PartitionDetection bool
	// IsolationMode detects when the border has closed (domestic contacts
	// answer, foreign ones don't). While isolated, lookups skip foreign
	// candidates and holders re-put the community records they store, so
	// records whose publisher is abroad or offline survive a shutdown.
	// Requires Domestic.
	IsolationMode bool
	// Unrestricted disables the per-IP and per-prefix routing limits. Only
	// for tests and private networks, such as many nodes on one loopback IP.
	Unrestricted bool
	Version      []byte
	Rand         *rand.Rand

	K            int
	Alpha        int
	MaxInflight  int
	QueryTimeout time.Duration
	// ShortTimeout is the most a lookup query may go unanswered before the
	// lookup stops counting it as active and widens: the node adapts it to
	// measured round trips, down to 250 ms.
	ShortTimeout        time.Duration
	LookupTimeout       time.Duration
	MaxLookups          int
	MaxCandidates       int
	MaxTransactions     int
	MaxItems            int
	ItemLifetime        time.Duration
	RepublishInterval   time.Duration
	RefreshInterval     time.Duration
	QuestionableAfter   time.Duration
	MaintenanceInterval time.Duration
	TokenRotation       time.Duration
	EvictAfterFailures  int
	// KeepaliveInterval is how often a listening provider polls its record
	// holders, holding its NAT mappings to them open. It must beat the NAT's
	// UDP mapping timeout; longer looks more like ordinary DHT traffic.
	KeepaliveInterval time.Duration
	// Routers relay for peer pairs that cannot punch a direct path, unless
	// DisableRelay is set. RelayRate caps each pair's bytes per second and
	// MaxRelayPairs the pairs relayed at once, bounding a volunteer's cost.
	DisableRelay  bool
	RelayRate     int
	MaxRelayPairs int
}

func (c *Config) setDefaults() {
	def := func(v *int, d int) {
		if *v == 0 {
			*v = d
		}
	}
	dur := func(v *time.Duration, d time.Duration) {
		if *v == 0 {
			*v = d
		}
	}
	def(&c.K, 8)
	def(&c.Alpha, 3)
	def(&c.MaxInflight, 16)
	def(&c.MaxLookups, 16)
	def(&c.MaxCandidates, 128)
	def(&c.MaxTransactions, 256)
	def(&c.MaxItems, 4096)
	def(&c.EvictAfterFailures, 2)
	dur(&c.QueryTimeout, 3*time.Second)
	dur(&c.ShortTimeout, time.Second)
	dur(&c.LookupTimeout, 30*time.Second)
	dur(&c.ItemLifetime, 2*time.Hour)
	dur(&c.RepublishInterval, 30*time.Minute)
	dur(&c.RefreshInterval, 15*time.Minute)
	dur(&c.QuestionableAfter, 15*time.Minute)
	dur(&c.MaintenanceInterval, 5*time.Second)
	dur(&c.TokenRotation, 5*time.Minute)
	dur(&c.KeepaliveInterval, 25*time.Second)
	def(&c.RelayRate, 512<<10)
	def(&c.MaxRelayPairs, 16)
	if c.Version == nil {
		c.Version = DefaultVersion
	}
	if c.Rand == nil {
		c.Rand = rand.New(rand.NewChaCha8(cryptoSeed()))
	}
}
