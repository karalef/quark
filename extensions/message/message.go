package message

import (
	"github.com/karalef/quark"
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/extensions/message/compress"
	"github.com/karalef/quark/pack"
)

// PacketTagMessage is a message packet tag.
const PacketTagMessage = 0x03

func init() {
	pack.RegisterPacketType(pack.NewType(
		(*Message)(nil),
		"message",
		"QUARK MESSAGE",
	))
}

// Header contains the signature information and encryption parameters.
// It also contains the file info.
type Header struct {
	// If not empty, message is signed.
	Sender crypto.ID `msgpack:"sender,omitempty"`

	// Time of the message creation.
	Time int64 `msgpack:"time,omitempty"`

	// If not nil, message is encrypted.
	Encryption *Encryption `msgpack:"encryption,omitempty"`

	// If not nil, message is compressed.
	Compression *Compression `msgpack:"compression,omitempty"`

	// File info.
	File FileInfo `msgpack:"file,omitempty"`
}

// Compression represents compression algorithm.
type Compression struct {
	compress.Compression
}

// EncodeMsgpack implements pack.CustomEncoder interface.
func (c Compression) EncodeMsgpack(enc *pack.Encoder) error {
	return enc.EncodeString(c.Compression.Name())
}

// DecodeMsgpack implements pack.CustomDecoder interface.
func (c *Compression) DecodeMsgpack(dec *pack.Decoder) error {
	name, err := dec.DecodeString()
	if err == nil {
		c.Compression = compress.ByName(name)
	}
	return err
}

// FileInfo contains the file info.
type FileInfo struct {
	// name of the file
	Name string `msgpack:"name,omitempty"`

	// time of the file creation
	Created int64 `msgpack:"created,omitempty"`

	// time of the last file modification
	Modified int64 `msgpack:"modified,omitempty"`
}

// Auth provides authentication and data integrity.
type Auth struct {
	Signature quark.Signature `msgpack:"signature,omitempty"`
	Tag       []byte          `msgpack:"auth,omitempty"`
}

var _ pack.Packable = (*Message)(nil)
var _ pack.CustomDecoder = (*Message)(nil)

// Message contains a message.
type Message struct {
	_msgpack struct{} `msgpack:",as_array"`

	Header Header

	// if the object is used for unpacking, it will be available only after decryption;
	// Data.Reader is used to store the input stream before decryption.
	Data pack.Stream

	// if the object is used for unpacking, it will be available only after decryption.
	Auth Auth
}

// DecodeMsgpack implements pack.CustomDecoder interface.
// It decodes only a header and stores the input stream.
func (m *Message) DecodeMsgpack(dec *pack.Decoder) error {
	if _, err := dec.DecodeArrayLen(); err != nil {
		return err
	}
	if err := dec.Decode(&m.Header); err != nil {
		return err
	}
	// store the input stream to continue unpacking
	m.Data.Reader = dec.Buffered()
	return nil
}

// PacketTag implements pack.Packable interface.
func (*Message) PacketTag() pack.Tag { return PacketTagMessage }
