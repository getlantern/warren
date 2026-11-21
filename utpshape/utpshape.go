// Package utpshape makes UDP traffic look like encrypted BitTorrent over uTP
// (BEP 29). It wraps a net.PacketConn, so it slots underneath any datagram
// protocol: hysteria2 as an alternative to Salamander or Gecko obfuscation,
// or the connections warren punches between peers that met on the DHT.
//
// Every datagram gets a real 20-byte uTP header with consistent connection
// IDs, incrementing sequence numbers, acknowledgements of the peer's
// sequence, and microsecond timestamps. Connections open with an empty
// ST_SYN answered by ST_STATE, as uTP's do. The payload is encrypted with
// AES-CTR, so it looks like BitTorrent's encrypted (MSE) streams. The nonce
// is the header's own connection ID, timestamps and sequence number, so the
// only overhead is the header itself.
//
// The layer hides; it does not authenticate. It is meant to carry protocols
// that authenticate every packet themselves, such as QUIC. Packets that fail
// to parse are dropped silently, as a uTP stack would.
//
// Overhead is 20 bytes per datagram. When wrapping a *net.UDPConn, New sets
// the Don't Fragment bit, so an inner protocol's path MTU probes measure the
// real path including the header: a probe of size S succeeds only if S+20
// fits. Check DontFragment; without it, keep inner datagrams at or below
// 1212 bytes (the 1232-byte IPv6 minimum less the header).
package utpshape

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	HeaderLen = 20
	version   = 1

	stData  = 0
	stFin   = 1
	stState = 2
	stReset = 3
	stSyn   = 4

	// advertisedWindow is the wnd_size field: a plausible receive buffer.
	advertisedWindow = 1 << 20
	maxPeers         = 4096
	maxDatagram      = 64 * 1024
)

var errShort = errors.New("utpshape: buffer too small")

type peer struct {
	sendID, recvID uint16
	seq, ack       uint16
	tsDiff         uint32
	seen           time.Time
	synSent        bool
}

// Conn shapes datagrams on an underlying PacketConn. It is safe for
// concurrent use, and keeps per-remote state so one socket can serve many
// peers.
type Conn struct {
	net.PacketConn
	block cipher.Block
	start time.Time
	df    bool

	mu    sync.Mutex
	peers map[netip.AddrPort]*peer
	rng   *rand.Rand

	bufs sync.Pool
}

// New wraps pc. Both ends must use the same key; any length works.
func New(pc net.PacketConn, key []byte) *Conn {
	k := sha256.Sum256(append([]byte("warren/utpshape/v1 "), key...))
	block, _ := aes.NewCipher(k[:])
	var seed [32]byte
	copy(seed[:], k[:]) // per-connection randomness for IDs and initial sequence numbers
	binary.LittleEndian.PutUint64(seed[:], uint64(time.Now().UnixNano()))
	c := &Conn{
		PacketConn: pc, block: block, start: time.Now(),
		peers: map[netip.AddrPort]*peer{}, rng: rand.New(rand.NewChaCha8(seed)),
	}
	c.bufs.New = func() any { b := make([]byte, maxDatagram); return &b }
	if uc, ok := pc.(*net.UDPConn); ok {
		c.df = SetDontFragment(uc)
	}
	return c
}

// SetDontFragment sets the Don't Fragment bit on c, so oversized datagrams
// are dropped instead of fragmented, and reports whether it succeeded. QUIC
// path MTU discovery depends on it: quic-go assumes it is set on any socket
// it cannot reach through syscall.Conn, so every wrapped socket needs it, or
// MTU discovery must be disabled.
func SetDontFragment(c *net.UDPConn) bool { return setDontFragment(c) }

// DontFragment reports whether the socket drops oversized datagrams rather
// than fragmenting them, which makes path MTU discovery safe above this
// layer.
func (c *Conn) DontFragment() bool { return c.df }

func (c *Conn) micros() uint32 { return uint32(time.Since(c.start).Microseconds()) }

func toAddrPort(a net.Addr) (netip.AddrPort, bool) {
	switch a := a.(type) {
	case *net.UDPAddr:
		ap := a.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
	}
	ap, err := netip.ParseAddrPort(a.String())
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), err == nil
}

// header writes a uTP header into h for a packet to p, advancing state.
func (c *Conn) header(h []byte, p *peer, typ byte, connID uint16) {
	h[0] = typ<<4 | version
	h[1] = 0 // no extensions
	binary.BigEndian.PutUint16(h[2:], connID)
	binary.BigEndian.PutUint32(h[4:], c.micros())
	binary.BigEndian.PutUint32(h[8:], p.tsDiff)
	binary.BigEndian.PutUint32(h[12:], advertisedWindow)
	binary.BigEndian.PutUint16(h[16:], p.seq)
	binary.BigEndian.PutUint16(h[18:], p.ack)
}

// xor applies the payload keystream. The counter block is a 12-byte packet
// nonce (the header's connection ID, timestamp, timestamp difference and
// sequence number) followed by a 4-byte block counter starting at zero, so
// packets that share a timestamp never share keystream: the sequence
// number sits in the nonce, not in the bits CTR increments.
func (c *Conn) xor(dst, src, h []byte) {
	var iv [aes.BlockSize]byte
	copy(iv[0:10], h[2:12])
	copy(iv[10:12], h[16:18])
	cipher.NewCTR(c.block, iv[:]).XORKeyStream(dst, src)
}

func (c *Conn) peer(addr netip.AddrPort, now time.Time) *peer {
	p := c.peers[addr]
	if p == nil {
		if len(c.peers) >= maxPeers {
			c.evict()
		}
		p = &peer{}
		c.peers[addr] = p
	}
	p.seen = now
	return p
}

func (c *Conn) evict() {
	var oldest netip.AddrPort
	var at time.Time
	for a, p := range c.peers {
		if at.IsZero() || p.seen.Before(at) {
			oldest, at = a, p.seen
		}
	}
	delete(c.peers, oldest)
}

// WriteTo sends b as a uTP data packet. The first packet to a new peer is
// preceded by an empty ST_SYN, as a uTP connection opens.
func (c *Conn) WriteTo(b []byte, addr net.Addr) (int, error) {
	ap, ok := toAddrPort(addr)
	if !ok {
		return 0, errors.New("utpshape: unsupported address")
	}
	if len(b)+HeaderLen > maxDatagram {
		return 0, errShort
	}
	bp := c.bufs.Get().(*[]byte)
	defer c.bufs.Put(bp)
	buf := (*bp)[:HeaderLen+len(b)]

	c.mu.Lock()
	p := c.peer(ap, time.Now())
	var syn [HeaderLen]byte
	sendSyn := false
	if !p.synSent && p.sendID == 0 && p.recvID == 0 {
		// We open the connection: SYN carries our receive ID, later packets
		// recv+1, and the peer replies on our receive ID.
		p.recvID = uint16(c.rng.Uint32())
		p.sendID = p.recvID + 1
		p.seq = uint16(c.rng.Uint32())
		p.synSent, sendSyn = true, true
		c.header(syn[:], p, stSyn, p.recvID)
	}
	p.seq++
	c.header(buf, p, stData, p.sendID)
	c.mu.Unlock()

	if sendSyn {
		if _, err := c.PacketConn.WriteTo(syn[:], addr); err != nil {
			return 0, err
		}
	}
	c.xor(buf[HeaderLen:], b, buf)
	if _, err := c.PacketConn.WriteTo(buf, addr); err != nil {
		return 0, err
	}
	return len(b), nil
}

// ReadFrom returns the next data payload, answering and consuming uTP
// control packets.
func (c *Conn) ReadFrom(b []byte) (int, net.Addr, error) {
	bp := c.bufs.Get().(*[]byte)
	defer c.bufs.Put(bp)
	buf := *bp
	for {
		n, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, nil, err
		}
		if n < HeaderLen || buf[0]&0x0f != version {
			continue
		}
		ap, ok := toAddrPort(addr)
		if !ok {
			continue
		}
		typ, h := buf[0]>>4, buf[:HeaderLen]
		connID := binary.BigEndian.Uint16(h[2:])
		ts := binary.BigEndian.Uint32(h[4:])
		seq := binary.BigEndian.Uint16(h[16:])

		c.mu.Lock()
		p := c.peer(ap, time.Now())
		p.tsDiff = c.micros() - ts
		var reply [HeaderLen]byte
		answer := false
		switch typ {
		case stSyn:
			// The peer opens: reply on its receive ID, expect recv+1.
			p.sendID, p.recvID, p.synSent = connID, connID+1, true
			if p.seq == 0 {
				p.seq = uint16(c.rng.Uint32())
			}
			p.ack = seq
			c.header(reply[:], p, stState, p.sendID)
			answer = true
		case stData:
			if p.sendID == 0 && p.recvID == 0 {
				// The SYN was lost; adopt the connection from its data.
				p.recvID, p.sendID, p.synSent = connID, connID-1, true
				p.seq = uint16(c.rng.Uint32())
			}
			p.ack = seq
		case stState:
			p.ack = seq
		}
		c.mu.Unlock()

		if answer {
			c.PacketConn.WriteTo(reply[:], addr)
		}
		if typ != stData {
			continue
		}
		payload := buf[HeaderLen:n]
		if len(payload) > len(b) {
			// Drop it, as a uTP stack would. Returning an error here would let
			// one oversized datagram from anyone tear down the QUIC transport
			// above, which treats read errors as fatal.
			continue
		}
		c.xor(b[:len(payload)], payload, h)
		return len(payload), addr, nil
	}
}
