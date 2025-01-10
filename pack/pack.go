package pack

import (
	"errors"
	"fmt"
	"io"
)

// MAGIC is a magic bytes.
const MAGIC = "QUARK"

// NewHeader creates a new packet header.
func NewHeader(tag Tag) Header {
	var h Header
	copy(h[:5], MAGIC)
	h[5] = byte(tag & 0xff)
	h[6] = byte(tag >> 8)
	return h
}

// Header is a packet header.
type Header [7]byte

// Tag extracts the tag from the header.
func (h Header) Tag() Tag { return Tag(h[5]) | Tag(h[6])<<8 }

// WriteTo writes the header to the writer.
func (h Header) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(h[:])
	return int64(n), err
}

// ReadFrom reads the header from the reader.
func (h Header) ReadFrom(r io.Reader) (int64, error) {
	n, err := io.ReadFull(r, h[:])
	return int64(n), err
}

// Validate checks if the header is valid.
func (h Header) Validate() error {
	if string(h[:5]) != MAGIC {
		return ErrMagic
	}
	_, err := h.Tag().Type()
	return err
}

// ErrMagic is returned when the magic bytes are wrong.
var ErrMagic = errors.New("wrong magic bytes")

// Pack encodes the packet contains the object into binary format.
func Pack(out io.Writer, v Packable) error {
	tag := v.PacketTag()
	if _, err := tag.Type(); err != nil {
		return err
	}

	if _, err := NewHeader(tag).WriteTo(out); err != nil {
		return err
	}

	return EncodeBinary(out, v)
}

// DecodePacket decodes the packet header from binary format.
// Returns RawPacket even if the tag is unknown (with ErrUnknownTag error).
func DecodePacket(in io.Reader) (*RawPacket, error) {
	var header Header
	if _, err := header.ReadFrom(in); err != nil {
		return nil, err
	}

	return &RawPacket{
		Tag:    header.Tag(),
		Object: GetDecoder(in),
	}, header.Validate()
}

// Unpack decodes the packet and unpacks the binary formatted object.
// If the binary object cannot be unpacked, returns the *RawPacket with ErrUnknownTag error.
func Unpack(in io.Reader) (Packable, error) {
	p, err := DecodePacket(in)
	if err != nil {
		return p, err
	}

	return UnpackObject(p)
}

// UnpackObject unpacks the binary formatted object from the decoded packet.
// Puts the decoder to the pool if the error is not ErrUnknownTag.
// Panics if r is nil.
func UnpackObject(r *RawPacket) (Packable, error) {
	if r == nil {
		panic("pack.UnpackObject: nil argument")
	}

	typ, err := r.Tag.Type()
	if err != nil {
		return nil, ErrUnknownTag
	}

	v := typ.new()
	return v, r.unpack(v)
}

// ErrMismatchType is returned when the object type mismatches the expected one.
type ErrMismatchType struct {
	Expected Tag
	Got      Tag
}

func (e ErrMismatchType) Error() string {
	return fmt.Sprintf("object type mismatches the expected %s (got %s)", e.Expected.String(), e.Got.String())
}

var _ Packable = RawPacket{}

// RawPacket represents a not unpacked binary packet.
type RawPacket Packet[*Decoder]

// PacketTag implements pack.Packable interface.
func (p RawPacket) PacketTag() Tag { return p.Tag }

// Unpack unpacks the binary object.
func (p RawPacket) Unpack(v Packable) error {
	if p.Tag != v.PacketTag() {
		return ErrMismatchType{Expected: p.Tag, Got: v.PacketTag()}
	}
	return p.unpack(v)
}

func (p RawPacket) unpack(v Packable) error {
	defer PutDecoder(p.Object)
	return p.Object.Decode(v)
}
