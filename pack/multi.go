package pack

import (
	"io"
)

// NewPacker returns a new packer.
func NewPacker(w io.Writer) *Packer { return (*Packer)(GetEncoder(w)) }

// Packer encodes several packets with one encoder.
type Packer Encoder

func (p *Packer) encoder() *Encoder { return (*Encoder)(p) }

// Close returns the underlying encoder to the pool.
func (p *Packer) Close() { PutEncoder(p.encoder()) }

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
func NewUnpacker(r io.Reader) *Unpacker { return (*Unpacker)(GetDecoder(r)) }

// Unpacker decodes several packets with one decoder.
type Unpacker Decoder

func (p *Unpacker) decoder() *Decoder { return (*Decoder)(p) }

type byteReader interface {
	io.Reader
	io.ByteReader
}

func (p *Unpacker) reader() byteReader {
	return p.decoder().Buffered().(byteReader)
}

// Close returns the underlying decoder to the pool.
func (p *Unpacker) Close() { PutDecoder(p.decoder()) }

// ReadHeader reads the next packet header.
func (p *Unpacker) ReadHeader() (Header, error) {
	var h Header
	if _, err := io.ReadFull(p.reader(), h[:]); err != nil {
		return h, err
	}
	return h, nil
}

// DecodePacket decodes the packet header from binary format.
// Returns RawPacket even if the tag is unknown (with ErrUnknownTag error).
func (p *Unpacker) DecodePacket() (*RawPacket, error) {
	r := p.reader()
	header, err := ReadHeader(r)
	if err != nil {
		return nil, err
	}

	return &RawPacket{
		Tag:    header.Tag(),
		Object: GetDecoder(r),
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
