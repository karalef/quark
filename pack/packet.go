package pack

import (
	"errors"
	"reflect"
)

// Packable represents a packable object.
type Packable interface {
	PacketTag() Tag
}

// Packet is a binary packet.
type Packet[T any] struct {
	_msgpack struct{} `msgpack:",as_array"`

	Tag    Tag
	Object T
}

// Tag is used to determine the binary packet type.
type Tag byte

// TagInvalid is used to indicate an invalid tag.
const TagInvalid Tag = 0x00

// ErrUnknownTag is returned when a tag is unknown.
var ErrUnknownTag = errors.New("unknown tag")

// Type returns the type of the tag.
func (t Tag) Type() (PacketType, error) {
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
	return typ.Name
}

// BlockType returns the block type of the tag.
func (t Tag) BlockType() string {
	typ, err := t.Type()
	if err != nil {
		return "INVALID"
	}
	return typ.BlockType
}

var packableType = reflect.TypeOf((*Packable)(nil)).Elem()

// RegisterPacketType registers a packet type.
func RegisterPacketType(typ PacketType) {
	if typ.Tag == TagInvalid {
		panic("tag cannot be zero")
	}
	if typ.Name == "" {
		panic("name cannot be empty")
	}
	if typ.BlockType == "" {
		panic("block type cannot be empty")
	}

	if _, ok := tagToType[typ.Tag]; ok {
		panic("duplicate tag")
	}

	tagToType[typ.Tag] = typ
}

var tagToType = make(map[Tag]PacketType)

// NewType creates a new packet type.
// Even if v is a typed nil pointer it must be able to return the packet tag.
func NewType(v Packable, name, blockType string) PacketType {
	return PacketType{
		Tag:       v.PacketTag(),
		Name:      name,
		BlockType: blockType,
	}
}

// PacketType represents a binary packet type.
type PacketType struct {
	Tag       Tag
	Name      string
	BlockType string
}
