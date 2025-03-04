package pack

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
)

// Packable represents a packable object.
type Packable interface {
	PacketTag() Tag
}

// Packet is a binary packet.
type Packet[T any] struct {
	Tag    Tag
	Object T
}

// Tag is used to determine the binary packet type.
type Tag uint16

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
	return MAGIC + " " + strings.ToUpper(typ.Name)
}

var packableType = reflect.TypeOf((*Packable)(nil)).Elem()

// RegisterPacketType registers a packet type.
func RegisterPacketType(typ PacketType) {
	if typ.Tag == TagInvalid {
		panic("tag cannot be zero")
	}
	if !reflect.PointerTo(typ.Type).Implements(packableType) {
		panic("type does not implement Packable")
	}
	if typ.Name == "" {
		panic("name cannot be empty")
	}

	tagToTypeMut.Lock()
	defer tagToTypeMut.Unlock()
	if reged, ok := tagToType[typ.Tag]; ok {
		panic(fmt.Sprintf("pack: duplicate tag 0x%x (%s); already registered as %s", typ.Tag, typ.Name, reged.Name))
	}

	tagToType[typ.Tag] = typ
}

// RegisteredTypes returns all registered packet types.
func RegisteredTypes() []PacketType {
	types := make([]PacketType, 0, len(tagToType))
	for _, typ := range tagToType {
		types = append(types, typ)
	}
	return types
}

var (
	tagToTypeMut sync.Mutex
	tagToType    = make(map[Tag]PacketType)
)

// NewType creates a new packet type.
// v must be a pointer.
// Even if v is a typed nil pointer it must be able to return the packet tag.
func NewType(v Packable, name string) PacketType {
	return PacketType{
		Tag:  v.PacketTag(),
		Type: reflect.TypeOf(v).Elem(),
		Name: name,
	}
}

// PacketType represents a binary packet type.
type PacketType struct {
	Tag  Tag
	Type reflect.Type
	Name string
}

func (t PacketType) new() Packable {
	return reflect.New(t.Type).Interface().(Packable)
}
