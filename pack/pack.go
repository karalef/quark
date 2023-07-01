package pack

import (
	"fmt"
	"io"

	"github.com/vmihailenco/msgpack/v5"
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

// DecodePacket decodes the packet from binary format.
// Returns the decoded packet even if the tag is unknown (with ErrUnknownTag error).
func DecodePacket(in io.Reader) (*Packet[*Decoder], error) {
	dec := msgpack.GetDecoder()
	dec.Reset(in)

	p := new(Packet[rawObject])
	err := dec.Decode(p)
	if err != nil {
		return nil, err
	}

	_, err = p.Tag.Type()
	return &Packet[*Decoder]{
		Tag:    p.Tag,
		Object: p.Object.Decoder,
	}, err
}

var _ CustomDecoder = (*rawObject)(nil)

type rawObject struct {
	*Decoder
}

func (r *rawObject) DecodeMsgpack(dec *Decoder) error {
	r.Decoder = dec
	return nil
}

// Unpack unpacks the binary formatted object from the packet.
// Puts the decoder to the pool if the error is not ErrMismatchType.
// Panics if one of the arguments is nil.
func Unpack(p *Packet[*Decoder], v Packable) error {
	if p == nil || v == nil {
		panic("pack.Unpack: nil argument")
	}
	if p.Tag != v.PacketTag() {
		return ErrMismatchType{expected: p.Tag, got: v.PacketTag()}
	}

	defer msgpack.PutDecoder(p.Object)
	return p.Object.Decode(v)
}

// ErrMismatchType is returned when the object type mismatches the expected one.
type ErrMismatchType struct {
	expected Tag
	got      Tag
}

func (e ErrMismatchType) Error() string {
	return fmt.Sprintf("object type mismatches the expected %s (got %s)", e.expected.String(), e.got.String())
}

// UnpackExact decodes the packet and unpacks the binary formatted object.
// If the tag does not match the tag of the provided object, returns ErrMismatchType.
// It always puts the decoder to the pool.
func UnpackExact(in io.Reader, v Packable) error {
	p, err := DecodePacket(in)
	if err != nil && err != ErrUnknownTag {
		return err
	}

	err = Unpack(p, v)
	if _, ok := err.(ErrMismatchType); ok {
		msgpack.PutDecoder(p.Object)
	}
	return err
}
