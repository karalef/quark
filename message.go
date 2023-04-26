package quark

import "errors"

// errors
var (
	ErrEmpty = errors.New("empty data")
)

// EncryptMessage encrypts a plaintext message.
// If signWith is nil, the message will be anonymous.
func EncryptMessage(plaintext []byte, to *Public, signWith *Private) (Message, error) {
	if len(plaintext) == 0 {
		return Message{}, ErrEmpty
	}

	ck, ct, err := Encrypt(plaintext, to)
	if err != nil {
		return Message{}, err
	}

	m := Message{
		Recipient: to.Fingerprint(),
		Key:       ck,
		Data:      ct,
	}

	if signWith == nil {
		return m, nil
	}

	signature, err := Sign(plaintext, signWith)
	if err != nil {
		return Message{}, err
	}

	m.Signature = signature
	m.Sender = signWith.Fingerprint()

	return m, nil
}

// ClearSign signs a plaintext message.
// If signWith is nil, the message will be raw.
func ClearSign(plaintext []byte, signWith *Private) (Message, error) {
	if len(plaintext) == 0 {
		return Message{}, ErrEmpty
	}

	if signWith == nil {
		return Message{Data: plaintext}, nil
	}

	signature, err := Sign(plaintext, signWith)
	if err != nil {
		return Message{}, err
	}

	return Message{
		Sender:    signWith.Fingerprint(),
		Signature: signature,
		Data:      plaintext,
	}, nil
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

// Message contains a message.
type Message struct {
	// sender`s public keyset fingerprint
	Sender Fingerprint

	// recipient`s public keyset fingerprint
	Recipient Fingerprint

	// signature
	Signature []byte

	// encapsulated shared secret
	Key []byte

	// data
	Data []byte
}

// Type returns the message type.
func (m Message) Type() (typ MessageType) {
	if len(m.Key) != 0 {
		typ |= MessageFlagEncrypted
	}
	if len(m.Signature) != 0 {
		typ |= MessageFlagSigned
	}
	return
}
