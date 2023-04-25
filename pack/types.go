package pack

import (
	"errors"
	"io"
)

// Tag is used to determine the binary block type.
type Tag byte

// available tags.
const (
	TagInvalid       Tag = 0x00
	TagMessage       Tag = 0x01
	TagPublicKeyset  Tag = 0x02
	TagPrivateKeyset Tag = 0x03
)

// ErrUnknownTag is returned when a tag is unknown.
var ErrUnknownTag = errors.New("unknown tag")

// Type returns the type of the tag.
func (t Tag) Type() (MsgType, error) {
	typ, ok := tagToType[t]
	if !ok {
		return typ, ErrUnknownTag
	}
	return typ, nil
}

func (t Tag) String() string {
	typ, err := t.Type()
	if err != nil {
		return "INVALID"
	}
	return typ.BlockType
}

// Unpacker returns the unpacker for the tag.
func (t Tag) Unpacker() (Unpacker, error) {
	typ, err := t.Type()
	if err != nil {
		return nil, err
	}
	return typ.Unpacker, nil
}

var tagToType = map[Tag]MsgType{
	TagMessage:       typeMessage,
	TagPublicKeyset:  typePublic,
	TagPrivateKeyset: typePrivate,
}

// MsgType represents a binary message type.
type MsgType struct {
	Tag       Tag
	BlockType string
	Unpacker  Unpacker
}

// Packer represents a packer function.
type Packer[T any] func(io.Writer, T) error

// Unpacker represents an unpacker function.
type Unpacker func(in io.Reader) (any, error)
