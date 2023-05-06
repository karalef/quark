package pack

import (
	"io"

	"github.com/vmihailenco/msgpack/v5"
)

// Packet is a binary packet.
type Packet struct {
	Tag    Tag
	Header struct {
		Encryption  *Encryption `msgpack:"encryption,omitempty"`
		Compression Compression `msgpack:"compression,omitempty"`
	}
	Object io.Reader
}

// EncodeMsgpack implements msgpack.CustomEncoder.
func (p *Packet) EncodeMsgpack(enc *msgpack.Encoder) error {
	err := enc.EncodeUint8(uint8(p.Tag))
	if err != nil {
		return err
	}
	enc.SetOmitEmpty(true)
	err = enc.Encode(p.Header)
	if err != nil {
		return err
	}
	_, err = io.Copy(enc.Writer(), p.Object)
	return err
}

// DecodeMsgpack implements msgpack.CustomDecoder.
func (p *Packet) DecodeMsgpack(dec *msgpack.Decoder) error {
	tag, err := dec.DecodeUint8()
	if err != nil {
		return err
	}
	p.Tag = Tag(tag)
	err = dec.Decode(&p.Header)
	if err != nil {
		return err
	}

	p.Object = dec.Buffered()
	return err
}

var (
	_ msgpack.CustomEncoder = (*Packet)(nil)
	_ msgpack.CustomDecoder = (*Packet)(nil)
)
