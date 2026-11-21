package dht

import (
	"crypto/ecdh"

	"github.com/getlantern/warren/bencode"
)

func ecdhX25519(seed []byte) (*ecdh.PrivateKey, error) { return ecdh.X25519().NewPrivateKey(seed) }

func bencodeBytes(b []byte) []byte { return bencode.AppendBytes(nil, b) }
