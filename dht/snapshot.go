package dht

import (
	"errors"

	"github.com/getlantern/warren/bencode"
	"github.com/getlantern/warren/krpc"
)

const maxSnapshotNodes = 256

var ErrBadSnapshot = errors.New("dht: malformed snapshot")

// Snapshot encodes our ID and live routing contacts in the shape of
// libtorrent's saved DHT state: {"id", "nodes", "nodes6"}. Save it
// periodically and pass its contacts to Rejoin after a restart, so a node can
// rejoin through domestic peers during a shutdown without any bootstrap
// server.
func (n *Node) Snapshot() []byte {
	var v4, v6 []krpc.NodeInfo
	for _, t := range []*table{n.comm, n.main} {
		if t == nil {
			continue
		}
		t.each(func(e *entry) {
			if e.fails > 0 || len(v4)+len(v6) >= maxSnapshotNodes {
				return
			}
			ni := krpc.NodeInfo{ID: e.id, Addr: e.addr}
			if e.addr.Addr().Unmap().Is4() {
				v4 = append(v4, ni)
			} else {
				v6 = append(v6, ni)
			}
		})
	}
	b := []byte{'d'}
	b = bencode.AppendString(b, "id")
	b = bencode.AppendBytes(b, n.cfg.ID[:])
	b = bencode.AppendString(b, "nodes")
	b = bencode.AppendBytes(b, krpc.AppendNodes(nil, v4))
	b = bencode.AppendString(b, "nodes6")
	b = bencode.AppendBytes(b, krpc.AppendNodes(nil, v6))
	return append(b, 'e')
}

// ParseSnapshot decodes a Snapshot. The contacts are unverified candidates
// for Rejoin.
func ParseSnapshot(b []byte) (krpc.NodeID, []krpc.NodeInfo, error) {
	v, err := bencode.Decode(b)
	if err != nil {
		return krpc.NodeID{}, nil, err
	}
	id, ok := v.Get("id")
	if !ok || id.Kind != bencode.String || len(id.Str) != 20 {
		return krpc.NodeID{}, nil, ErrBadSnapshot
	}
	var nodes []krpc.NodeInfo
	if s, ok := v.Get("nodes"); ok && s.Kind == bencode.String {
		nodes = append(nodes, krpc.ParseNodes(s.Str, false)...)
	}
	if s, ok := v.Get("nodes6"); ok && s.Kind == bencode.String {
		nodes = append(nodes, krpc.ParseNodes(s.Str, true)...)
	}
	return krpc.NodeID(id.Str), nodes[:min(len(nodes), maxSnapshotNodes)], nil
}
