package pack

import (
	"errors"
	"fmt"
	"io"
)

// MAGIC is a magic bytes.
const MAGIC = "QUARK"

// ErrMagic is returned when the magic bytes are wrong.
var ErrMagic = errors.New("wrong magic bytes")

// Pack encodes the packet contains the object into binary format.
func Pack(out io.Writer, v Packable) error {
	tag := v.PacketTag()
	if _, err := tag.Type(); err != nil {
		return err
	}

	var header [6]byte
	copy(header[:5], []byte(MAGIC))
	header[5] = byte(tag)
	if _, err := out.Write(header[:]); err != nil {
		return err
	}

	return EncodeBinary(out, v)
}

// PackArmored creates an armored encoder and packs the object.
func PackArmored(out io.Writer, v Packable, headers map[string]string) error {
	wc, err := ArmoredEncoder(out, v.PacketTag().BlockType(), headers)
	if err != nil {
		return err
	}

	return errors.Join(Pack(wc, v), wc.Close())
}

// DecodePacket decodes the packet header from binary format.
// Returns RawPacket even if the tag is unknown (with ErrUnknownTag error).
func DecodePacket(in io.Reader) (*RawPacket, error) {
	var header [6]byte
	if _, err := io.ReadFull(in, header[:]); err != nil {
		return nil, err
	}
	if string(header[:5]) != MAGIC {
		return nil, ErrMagic
	}

	tag := Tag(header[5])
	_, err := tag.Type()
	return &RawPacket{
		Tag:    tag,
		Object: GetDecoder(in),
	}, err
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

// UnpackArmored decodes an armored block and unpacks the object.
func UnpackArmored(in io.Reader) (Packable, map[string]string, error) {
	block, err := DecodeArmored(in)
	if err != nil {
		return nil, nil, err
	}

	v, err := Unpack(block.Body)
	if err != nil {
		return nil, nil, err
	}

	if v.PacketTag().BlockType() != block.Type {
		return nil, nil, errors.New("wrong armor block type")
	}

	return v, block.Header, nil
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
