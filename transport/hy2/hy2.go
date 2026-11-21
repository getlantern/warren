// Package hy2 runs hysteria2 (sing-quic) over an existing UDP socket, such as
// the one package endpoint punches, with uTP shaping as an obfuscation option
// alongside hysteria2's Salamander.
//
// Both ends are authenticated against warren keys: the server's TLS
// certificate is generated from its ed25519 identity and the client pins
// that key, and the hysteria2 password is derived from the session secret
// both ends got through signaling.
package hy2

import (
	"context"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"time"

	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing-quic/hysteria2"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"

	"github.com/getlantern/warren/utpshape"
)

type Obfs int

const (
	// ObfsUTP shapes datagrams as encrypted BitTorrent over uTP, matching
	// the cover of peers that met on the DHT.
	ObfsUTP Obfs = iota
	// ObfsSalamander is hysteria2's keystream scrambling: random-looking
	// datagrams at their natural sizes.
	ObfsSalamander
	// ObfsNone leaves plain QUIC on the wire.
	ObfsNone
)

const serverName = "warren"

// Shaper transforms the datagrams under hysteria2: utpshape today, the
// spec-driven shaping engine later. Both ends must use matching shapers.
type Shaper interface {
	// Wrap returns the socket hysteria2 should use instead of pc.
	Wrap(pc net.PacketConn, key []byte) net.PacketConn
	// Overhead is the bytes the shaper adds to each datagram.
	Overhead() int
}

// DontFragmenter is implemented by shaped sockets that set Don't Fragment,
// which makes QUIC's path MTU discovery account for the shaper's overhead.
type DontFragmenter interface{ DontFragment() bool }

// UTP shapes datagrams as encrypted BitTorrent over uTP.
type UTP struct{}

func (UTP) Wrap(pc net.PacketConn, key []byte) net.PacketConn { return utpshape.New(pc, key) }
func (UTP) Overhead() int                                     { return utpshape.HeaderLen }

type Options struct {
	Obfs Obfs
	// Shaper, when set, replaces Obfs with a custom datagram transform.
	Shaper  Shaper
	ObfsKey []byte
	// Password authenticates the client; derive it from the session secret.
	Password string
	// Receive windows. hysteria2 defaults to 8 MiB per stream and 20 MiB
	// per connection, too much for an iOS network extension.
	StreamWindow, ConnWindow uint64
	// SendBPS and ReceiveBPS select Brutal congestion control with these
	// rates; zero leaves BBR, the safer choice between phones.
	SendBPS, ReceiveBPS uint64
	Logger              logger.ContextLogger
}

// quic builds the QUIC options. df reports whether the raw socket drops
// oversized datagrams; quic-go assumes it does for any socket it reaches
// through a wrapper, so without it MTU discovery would trust probes that IP
// silently fragmented.
func (o *Options) quic(shaped net.PacketConn, df bool) qtls.QUICOptions {
	q := qtls.QUICOptions{
		StreamReceiveWindow:     o.StreamWindow,
		ConnectionReceiveWindow: o.ConnWindow,
	}
	if q.StreamReceiveWindow == 0 {
		q.StreamReceiveWindow = 1 << 20
	}
	if q.ConnectionReceiveWindow == 0 {
		q.ConnectionReceiveWindow = 5 << 19 // 2.5 MiB
	}
	if s := o.shaper(); s != nil && s.Overhead() > 0 {
		// Start at QUIC's 1200-byte minimum, which plus the (validated)
		// overhead fits the 1232-byte IPv6 minimum path MTU; MTU discovery
		// then measures the real path including the overhead.
		q.InitialPacketSize = 1200 // QUIC's minimum; validate caps the overhead to fit
		if d, ok := shaped.(DontFragmenter); ok {
			df = df || d.DontFragment()
		}
	}
	q.DisablePathMTUDiscovery = !df
	return q
}

func (o *Options) logger() logger.ContextLogger {
	if o.Logger != nil {
		return o.Logger
	}
	return logger.NOP()
}

// shape returns the socket hysteria2 should use, plus a Salamander password
// when hysteria2 should scramble it itself.
// maxShaperOverhead is the most a shaper may add: QUIC's Initial packets are
// at least 1200 bytes, and 1200 plus the overhead must fit the 1232-byte
// IPv6 minimum path MTU.
const maxShaperOverhead = 32

var errShaperOverhead = errors.New("hy2: shaper overhead exceeds 32 bytes, which QUIC's 1200-byte Initials cannot absorb within the IPv6 minimum MTU")

func (o *Options) validate() error {
	if s := o.shaper(); s != nil && s.Overhead() > maxShaperOverhead {
		return errShaperOverhead
	}
	return nil
}

func (o *Options) shaper() Shaper {
	if o.Shaper != nil {
		return o.Shaper
	}
	if o.Obfs == ObfsUTP {
		return UTP{}
	}
	return nil
}

func (o *Options) shape(pc net.PacketConn) (net.PacketConn, string) {
	if s := o.shaper(); s != nil {
		return s.Wrap(pc, o.ObfsKey), ""
	}
	if o.Obfs == ObfsSalamander {
		return pc, string(o.ObfsKey)
	}
	return pc, ""
}

// Handler receives each stream a client opens, with the destination the
// client named.
type Handler func(conn net.Conn, destination string)

type Server struct {
	svc *hysteria2.Service[int]
	pc  net.PacketConn
}

func (s *Server) Close() error {
	err := s.svc.Close()
	s.pc.Close()
	return err
}

// Serve runs a hysteria2 server on pc whose certificate is identity's key.
func Serve(ctx context.Context, pc net.PacketConn, identity ed25519.PrivateKey, opts Options, h Handler) (*Server, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}
	cert, err := certificate(identity)
	if err != nil {
		return nil, err
	}
	df := dontFragment(pc)
	shaped, salamander := opts.shape(pc)
	svc, err := hysteria2.NewService[int](hysteria2.ServiceOptions{
		Context:            ctx,
		Logger:             opts.logger(),
		SendBPS:            opts.SendBPS,
		ReceiveBPS:         opts.ReceiveBPS,
		SalamanderPassword: salamander,
		TLSConfig:          &stdTLS{cfg: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}},
		QUICOptions:        opts.quic(shaped, df),
		UDPDisabled:        true,
		Handler:            handler{h},
	})
	if err != nil {
		return nil, err
	}
	svc.UpdateUsers([]int{1}, []string{opts.Password})
	if err := svc.Start(shaped); err != nil {
		return nil, err
	}
	return &Server{svc: svc, pc: pc}, nil
}

type Client struct {
	c  *hysteria2.Client
	pc net.PacketConn
}

// Dial prepares a client that reaches the server at remote over pc and
// accepts only a certificate for peerKey. The QUIC connection opens with the
// first DialConn.
func Dial(ctx context.Context, pc net.PacketConn, remote netip.AddrPort, peerKey [32]byte, opts Options) (*Client, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}
	df := dontFragment(pc)
	shaped, salamander := opts.shape(pc)
	tc := &tls.Config{
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // replaced by pinning the peer's warren key
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("hy2: no certificate")
			}
			leaf, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			if k, ok := leaf.PublicKey.(ed25519.PublicKey); !ok || [32]byte(k) != peerKey {
				return errors.New("hy2: certificate is not the peer's key")
			}
			return nil
		},
	}
	c, err := hysteria2.NewClient(hysteria2.ClientOptions{
		Context:            ctx,
		Dialer:             socketDialer{pc: shaped, remote: net.UDPAddrFromAddrPort(remote)},
		Logger:             opts.logger(),
		ServerAddress:      M.SocksaddrFromNetIP(remote),
		SendBPS:            opts.SendBPS,
		ReceiveBPS:         opts.ReceiveBPS,
		SalamanderPassword: salamander,
		Password:           opts.Password,
		TLSConfig:          &stdTLS{cfg: tc},
		QUICOptions:        opts.quic(shaped, df),
		UDPDisabled:        true,
	})
	if err != nil {
		return nil, err
	}
	return &Client{c: c, pc: pc}, nil
}

// DialConn opens a stream to destination through the server.
func (c *Client) DialConn(ctx context.Context, destination string) (net.Conn, error) {
	return c.c.DialConn(ctx, M.ParseSocksaddr(destination))
}

func (c *Client) Close() error {
	err := c.c.CloseWithError(nil)
	c.pc.Close()
	return err
}

// certificate is a self-signed TLS 1.3 certificate for an ed25519 identity.
func certificate(identity ed25519.PrivateKey) (tls.Certificate, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: serverName},
		DNSNames:     []string{serverName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, identity.Public(), identity)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: identity}, nil
}

// socketDialer hands hysteria2 the existing socket, bound to the peer.
type socketDialer struct {
	pc     net.PacketConn
	remote net.Addr
}

func (d socketDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return &boundConn{PacketConn: d.pc, remote: d.remote}, nil
}

func (d socketDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return d.pc, nil
}

// boundConn is a PacketConn used as a connected net.Conn: writes go to the
// peer, and datagrams from anyone else are dropped.
type boundConn struct {
	net.PacketConn
	remote net.Addr
}

func (c *boundConn) Read(b []byte) (int, error) {
	for {
		n, from, err := c.ReadFrom(b)
		if err != nil {
			return 0, err
		}
		if from.String() == c.remote.String() {
			return n, nil
		}
	}
}

func (c *boundConn) Write(b []byte) (int, error) { return c.WriteTo(b, c.remote) }
func (c *boundConn) RemoteAddr() net.Addr        { return c.remote }

type handler struct{ h Handler }

func (h handler) NewConnectionEx(_ context.Context, conn net.Conn, _ M.Socksaddr, dst M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		h.h(conn, dst.String())
		conn.Close()
		if onClose != nil {
			onClose(nil)
		}
	}()
}

func (handler) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _ M.Socksaddr, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	_ = conn.Close() // rejecting the stream; nothing to do with the error
	if onClose != nil {
		onClose(errors.New("hy2: UDP relay disabled"))
	}
}

// stdTLS adapts crypto/tls to sing's TLS interfaces. sing-quic only reads
// the standard config, so the stream-handshake methods are unused.
type stdTLS struct{ cfg *tls.Config }

var (
	_ aTLS.Config       = (*stdTLS)(nil)
	_ aTLS.ServerConfig = (*stdTLS)(nil)
)

func (s *stdTLS) ServerName() string                { return s.cfg.ServerName }
func (s *stdTLS) SetServerName(n string)            { s.cfg.ServerName = n }
func (s *stdTLS) NextProtos() []string              { return s.cfg.NextProtos }
func (s *stdTLS) SetNextProtos(p []string)          { s.cfg.NextProtos = p }
func (s *stdTLS) HandshakeTimeout() time.Duration   { return 10 * time.Second }
func (s *stdTLS) SetHandshakeTimeout(time.Duration) {}
func (s *stdTLS) STDConfig() (*aTLS.STDConfig, error) {
	return s.cfg, nil
}
func (s *stdTLS) Client(net.Conn) (aTLS.Conn, error) { return nil, errors.New("hy2: QUIC only") }
func (s *stdTLS) Server(net.Conn) (aTLS.Conn, error) { return nil, errors.New("hy2: QUIC only") }
func (s *stdTLS) Clone() aTLS.Config                 { return &stdTLS{cfg: s.cfg.Clone()} }
func (s *stdTLS) Start() error                       { return nil }
func (s *stdTLS) Close() error                       { return nil }

// FromSecret derives a connection's obfuscation key and password from the
// session secret both ends got through signaling (endpoint.Conn.Secret).
func FromSecret(secret []byte, obfs Obfs) Options {
	obfsKey, _ := hkdf.Key(sha256.New, secret, nil, "warren/hy2/v1 obfs", 32)
	password, _ := hkdf.Key(sha256.New, secret, nil, "warren/hy2/v1 password", 32)
	return Options{Obfs: obfs, ObfsKey: obfsKey, Password: hex.EncodeToString(password)}
}

// dontFragment sets Don't Fragment on the raw socket when pc is one.
func dontFragment(pc net.PacketConn) bool {
	uc, ok := pc.(*net.UDPConn)
	return ok && utpshape.SetDontFragment(uc)
}
