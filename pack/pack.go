package pack

import (
	"errors"
	"fmt"
	"io"

	"github.com/karalef/quark/pack/binary"
)

// MAGIC is a magic bytes.
const MAGIC = "QUARK"

// NewHeader creates a new packet header.
func NewHeader(tag Tag) Header {
	var h Header
	copy(h[:5], MAGIC)
	h[6] = byte(tag >> 8)
	h[7] = byte(tag & 0xff)
	return h
}

// ReadHeader reads the packet header from the reader.
func ReadHeader(in io.Reader) (Header, error) {
	var h Header
	if _, err := io.ReadFull(in, h[:]); err != nil {
		return h, err
	}
	return h, nil
}

// Header is a packet header.
type Header [8]byte

// Tag extracts the tag from the header.
func (h Header) Tag() Tag { return Tag(h[6])<<8 | Tag(h[7]) }

// WriteTo writes the header to the writer.
func (h Header) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(h[:])
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

// NewPacker returns a new packer.
func NewPacker(w io.Writer) *Packer { return (*Packer)(binary.GetEncoder(w)) }

// Packer encodes several packets with one encoder.
type Packer binary.Encoder

func (p *Packer) encoder() *binary.Encoder { return (*binary.Encoder)(p) }

// Close returns the underlying encoder to the pool.
func (p *Packer) Close() { binary.PutEncoder(p.encoder()) }

// Pack packs the next packet.
func (p *Packer) Pack(v Packable) error {
	tag := v.PacketTag()
	if _, err := tag.Type(); err != nil {
		return err
	}

	enc := p.encoder()
	if _, err := NewHeader(tag).WriteTo(enc.Writer()); err != nil {
		return err
	}
	return enc.Encode(v)
}

// NewUnpacker returns a new unpacker.
func NewUnpacker(r io.Reader) *Unpacker { return (*Unpacker)(binary.GetDecoder(r)) }

// Unpacker decodes several packets with one decoder.
type Unpacker binary.Decoder

func (p *Unpacker) decoder() *binary.Decoder { return (*binary.Decoder)(p) }

func (p *Unpacker) reader() binary.ByteReader {
	return p.decoder().Buffered().(binary.ByteReader)
}

// Close returns the underlying decoder to the pool.
func (p *Unpacker) Close() { binary.PutDecoder(p.decoder()) }

// ReadHeader reads the next packet header.
func (p *Unpacker) ReadHeader() (Header, error) { return ReadHeader(p.reader()) }

// DecodePacket decodes the packet header from binary format.
// Returns RawPacket even if the tag is unknown (with ErrUnknownTag error).
func (p *Unpacker) DecodePacket() (*RawPacket, error) {
	header, err := p.ReadHeader()
	if err != nil {
		return nil, err
	}

	return &RawPacket{
		Tag:    header.Tag(),
		Object: binary.GetDecoder(p.reader()),
	}, header.Validate()
}

// Unpack decodes the packet and unpacks the binary formatted object.
// If the binary object cannot be unpacked, returns the *RawPacket with ErrUnknownTag error.
func (p *Unpacker) Unpack() (Packable, error) {
	raw, err := p.DecodePacket()
	if err != nil {
		return raw, err
	}

	return UnpackObject(raw)
}

// Pack encodes the packet contains the object into binary format.
func Pack(out io.Writer, v Packable) error {
	p := NewPacker(out)
	defer p.Close()
	return p.Pack(v)
}

// DecodePacket decodes the packet header from binary format.
// Returns RawPacket even if the tag is unknown (with ErrUnknownTag error).
func DecodePacket(in io.Reader) (*RawPacket, error) {
	u := NewUnpacker(in)
	defer u.Close()
	return u.DecodePacket()
}

// Unpack decodes the packet and unpacks the binary formatted object.
// If the binary object cannot be unpacked, returns the *RawPacket with ErrUnknownTag error.
func Unpack(in io.Reader) (Packable, error) {
	u := NewUnpacker(in)
	defer u.Close()
	return u.Unpack()
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
type RawPacket Packet[*binary.Decoder]

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
	defer binary.PutDecoder(p.Object)
	return p.Object.Decode(v)
}
