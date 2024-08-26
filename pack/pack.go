package pack

import (
	"fmt"
	"io"
)

// Pack creates a packet and encodes it into binary format.
func Pack(out io.Writer, v Packable) error {
	tag := v.PacketTag()
	if _, err := tag.Type(); err != nil {
		return err
	}

	return EncodeBinary(out, Packet[Packable]{
		Tag:    tag,
		Object: v,
	})
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

// DecodePacket decodes the packet header from binary format.
// Returns RawPacket even if the tag is unknown (with ErrUnknownTag error).
func DecodePacket(in io.Reader) (*RawPacket, error) {
	dec := GetDecoder(in)

	p := new(Packet[rawObject])
	err := dec.Decode(p)
	if err != nil {
		return nil, err
	}

	_, err = p.Tag.Type()
	return &RawPacket{
		Tag:    p.Tag,
		Object: p.Object.Decoder,
	}, err
}

// UnpackObject unpacks the binary formatted object from the decoded packet.
// Puts the decoder to the pool if the error is not ErrUnknownTag.
// Panics if r is nil.
func UnpackObject(r *RawPacket) (Packable, error) {
	if r == nil {
		panic("pack.Unpack: nil argument")
	}

	typ, err := r.Tag.Type()
	if err != nil {
		return nil, ErrUnknownTag
	}

	v := typ.new()
	return v, r.Unpack(v)
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

	defer PutDecoder(p.Object)
	return p.Object.Decode(v)
}

var _ CustomDecoder = (*rawObject)(nil)

type rawObject struct{ *Decoder }

func (r *rawObject) DecodeMsgpack(dec *Decoder) error {
	r.Decoder = dec
	return nil
}
