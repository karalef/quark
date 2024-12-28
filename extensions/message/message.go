package message

import (
	"github.com/karalef/quark"
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/extensions/message/compress"
	"github.com/karalef/quark/pack"
)

// PacketTagMessage is a message packet tag.
const PacketTagMessage = 0x05

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
	// Message sender.
	Sender crypto.Fingerprint `msgpack:"sender,omitempty"`

	// Time of the message creation.
	Time int64 `msgpack:"time,omitempty"`

	// If not nil, message is encrypted.
	Encryption *Encryption `msgpack:"encryption,omitempty"`

	// If not nil, message is compressed.
	Compression *compress.Algorithm `msgpack:"compression,omitempty"`

	// File info.
	File FileInfo `msgpack:"file,omitempty"`
}

// IsEncrypted returns true if message is encrypted.
func (h Header) IsEncrypted() bool { return h.Encryption != nil }

// IsCompressed returns true if message is compressed.
func (h Header) IsCompressed() bool { return h.Compression != nil }

// IsFile returns true if message contains file info.
func (h Header) IsFile() bool { return h.File != FileInfo{} }

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
	Tag       []byte          `msgpack:"auth,omitempty"`
	Signature quark.Signature `msgpack:"signature,omitempty"`
}

var (
	_ pack.Packable      = (*Message)(nil)
	_ pack.CustomDecoder = (*Message)(nil)
)

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
