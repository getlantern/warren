package content

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/getlantern/warren/group/memberlog"
)

// announceVersion is the Announcement encoding's version.
const announceVersion = 1

// announceHeader is an encoded Announcement's length before Meta: the
// version, ID, size, piece size and key.
const announceHeader = 1 + 32 + 8 + 4 + 32

// MaxMeta bounds an Announcement's Meta, so its encoding fits a log entry
// (memberlog.MaxBody).
const MaxMeta = memberlog.MaxBody - announceHeader

// ErrAnnouncement means an Announcement's encoding is malformed or names
// an impossible blob.
var ErrAnnouncement = errors.New("content: malformed announcement")

// Announcement is a blob's announcement, the body of a memberlog.Blob
// entry in its author's log. The entry is encrypted under the epoch key,
// which is what wraps Key (*Content*: "the per-blob key wrapped under the
// current epochKey"). Meta is the app's: title, thumbnail, MIME type.
type Announcement struct {
	ID        ID
	Size      uint64
	PieceSize uint32
	Key       Key
	Meta      []byte
}

// Announce is the Announcement for s with meta.
func (s *Sealed) Announce(meta []byte) *Announcement {
	return &Announcement{ID: s.ID, Size: s.Size, PieceSize: s.PieceSize, Key: s.Key, Meta: meta}
}

// Encode encodes a: ErrAnnouncement if it names an impossible blob or its
// Meta is over MaxMeta.
func (a *Announcement) Encode() ([]byte, error) {
	if _, err := Pieces(a.Size, a.PieceSize); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAnnouncement, err)
	}
	if len(a.Meta) > MaxMeta {
		return nil, fmt.Errorf("%w: meta of %d bytes is over MaxMeta", ErrAnnouncement, len(a.Meta))
	}
	b := make([]byte, announceHeader, announceHeader+len(a.Meta))
	b[0] = announceVersion
	copy(b[1:33], a.ID[:])
	binary.BigEndian.PutUint64(b[33:41], a.Size)
	binary.BigEndian.PutUint32(b[41:45], a.PieceSize)
	copy(b[45:77], a.Key[:])
	return append(b, a.Meta...), nil
}

// DecodeAnnouncement decodes an Announcement Encode made (ErrAnnouncement).
func DecodeAnnouncement(b []byte) (*Announcement, error) {
	if len(b) < announceHeader || b[0] != announceVersion || len(b)-announceHeader > MaxMeta {
		return nil, ErrAnnouncement
	}
	a := &Announcement{
		Size:      binary.BigEndian.Uint64(b[33:41]),
		PieceSize: binary.BigEndian.Uint32(b[41:45]),
		Meta:      append([]byte(nil), b[announceHeader:]...),
	}
	copy(a.ID[:], b[1:33])
	copy(a.Key[:], b[45:77])
	if _, err := Pieces(a.Size, a.PieceSize); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAnnouncement, err)
	}
	return a, nil
}
