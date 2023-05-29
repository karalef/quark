package quark

import (
	"errors"
	"time"

	"github.com/karalef/quark/pack"
)

// errors
var (
	ErrEmpty = errors.New("empty data")
)

// NewMessage creates a new message.
// If the sender is nil, the message will be Anonymous.
// If the recipient is nil, the message will be Clear-Signed.
func NewMessage(plaintext []byte, recipient Public, sender Private) (Message, error) {
	if len(plaintext) == 0 {
		return Message{}, errors.New("empty plaintext")
	}

	msg := Message{
		Data: plaintext,
		Time: time.Now().Unix(),
	}

	if sender != nil {
		var err error
		msg.Signature, err = Sign(plaintext, sender)
		if err != nil {
			return Message{}, err
		}
	}

	if recipient != nil {
		msg.Data, msg.Encryption = Encrypt(nil, plaintext, recipient)
	}

	return msg, nil
}

// NewMessageFile creates a new message containing a file.
// If the filename is empty it just returns the result of NewMessage.
func NewMessageFile(data []byte, filename string, mtime int64, recipient Public, sender Private) (Message, error) {
	msg, err := NewMessage(data, recipient, sender)
	if err != nil || filename == "" {
		return msg, err
	}

	msg.Filename = filename
	if mtime != 0 {
		msg.Time = mtime
	}

	return msg, nil
}

// MessageType represents a message type.
type MessageType byte

// message flags and types
const (
	MessageFlagEncrypted MessageType = 1 << iota
	MessageFlagSigned

	// rawly encoded message that is not encrypted and not signed
	MessageTypeRaw = 0x00
	// anonymous message that is only encrypted and not signed
	MessageTypeAnonymous = MessageFlagEncrypted
	// clear-signed message that is only signed and not encrypted
	MessageTypeClearSign = MessageFlagSigned
	// message that is encrypted and signed
	MessageTypeSignedEncrypted = MessageFlagEncrypted | MessageFlagSigned
)

// IsEncrypted returns true if the message is encrypted.
func (t MessageType) IsEncrypted() bool { return t&MessageFlagEncrypted != 0 }

// IsSigned returns true if the message is signed.
func (t MessageType) IsSigned() bool { return t&MessageFlagSigned != 0 }

func (t MessageType) String() string {
	switch t {
	case MessageTypeRaw:
		return "Raw"
	case MessageTypeAnonymous:
		return "Anonymous"
	case MessageTypeClearSign:
		return "Clear-Signed"
	case MessageTypeSignedEncrypted:
		return "Signed and Encrypted"
	default:
		return "unknown"
	}
}

var _ pack.Packable = (*Message)(nil)

// Message contains a message.
type Message struct {
	// signature
	Signature *Signature `msgpack:"signature,omitempty"`

	// encryption
	Encryption *Encryption `msgpack:"encryption,omitempty"`

	// name of the file
	Filename string `msgpack:"filename,omitempty"`

	// time of the last file modification or message creation
	Time int64 `msgpack:"time,omitempty"`

	// data
	Data []byte `msgpack:"data"`
}

// PacketTag implements pack.Packable interface.
func (*Message) PacketTag() pack.Tag { return PacketTagMessage }

// Type returns the message type.
func (m *Message) Type() (typ MessageType) {
	if m.Encryption != nil {
		typ |= MessageFlagEncrypted
	}
	if m.Signature != nil {
		typ |= MessageFlagSigned
	}
	return
}
