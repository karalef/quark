package pack

import (
	"fmt"
	"io"
	"reflect"

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

// UnpackPacket unpacks the binary formatted object from the packet.
// Returns a RawObject (with ErrUnknownTag error) if the tag is unknown.
// Puts the decoder to the pool if the error is not ErrUnknownTag.
func UnpackPacket(p *Packet[*Decoder]) (Packable, error) {
	if p == nil {
		return nil, nil
	}

	typ, err := p.Tag.Type()
	if err != nil {
		return &RawObject{
			Tag:     p.Tag,
			Decoder: p.Object,
		}, err
	}

	defer msgpack.PutDecoder(p.Object)

	v := typ.new()
	err = p.Object.Decode(v)
	if err != nil {
		return nil, err
	}
	return v, err
}

// Unpack decodes the packet and unpacks the binary formatted object.
// Returns a RawObject (with ErrUnknownTag error) if the tag is unknown.
func Unpack(in io.Reader) (Tag, Packable, error) {
	p, err := DecodePacket(in)
	if err != nil && err != ErrUnknownTag {
		return TagInvalid, nil, err
	}

	v, err := UnpackPacket(p)
	return p.Tag, v, err
}

// ErrMismatchType is returned when the object type mismatches the expected one.
type ErrMismatchType struct {
	expected Packable
	got      Tag
}

func (e ErrMismatchType) Error() string {
	got := e.got.String()
	if reflect.TypeOf(e.expected) == nil { // type parameter is interface
		return fmt.Sprintf("object type (%s) does not implement the specified interface", got)
	}
	return fmt.Sprintf("object type mismatches the expected %s (got %s)", e.expected.PacketTag().String(), got)
}

// UnpackExact decodes an object from binary format and casts it to specified type.
func UnpackExact[T Packable](in io.Reader) (val T, err error) {
	tag, v, err := Unpack(in)
	if err != nil {
		return
	}
	val, ok := v.(T)
	if !ok {
		return val, ErrMismatchType{expected: val, got: tag}
	}
	return
}
