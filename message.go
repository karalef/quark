package quark

import "errors"

// file errors.
var (
	ErrEmpty         = errors.New("empty data")
	ErrEmptyFileName = errors.New("empty file name")
)

// EncryptPlain encrypts a plaintext message.
// If signWith is nil, the message will be anonymous.
func EncryptPlain(plaintext []byte, to PublicKeyset, signWith PrivateKeyset) (Message, error) {
	if len(plaintext) == 0 {
		return Message{}, ErrEmpty
	}

	ck, ct, err := Encrypt(plaintext, to)
	if err != nil {
		return Message{}, err
	}

	m := Message{
		Key:  ck,
		Data: ct,
	}

	if signWith == nil {
		return m, nil
	}

	signature, err := Sign(plaintext, signWith)
	if err != nil {
		return Message{}, err
	}

	m.Signature = signature
	m.Fingerprint = FingerprintOf(signWith)

	return m, nil
}

// EncryptFile encrypts a file.
// If signWith is nil, the message will be anonymous.
func EncryptFile(fileName string, data []byte, to PublicKeyset, signWith PrivateKeyset) (Message, error) {
	if fileName == "" {
		return Message{}, ErrEmptyFileName
	}

	m, err := EncryptPlain(data, to, signWith)
	if err != nil {
		return m, err
	}
	m.File = fileName

	return m, nil
}

// ClearSign signs a plaintext message.
func ClearSign(plaintext []byte, signWith PrivateKeyset) (Message, error) {
	if len(plaintext) == 0 {
		return Message{}, ErrEmpty
	}

	signature, err := Sign(plaintext, signWith)
	if err != nil {
		return Message{}, err
	}

	return Message{
		Fingerprint: FingerprintOf(signWith),
		Signature:   signature,
		Data:        plaintext,
	}, nil
}

// ClearSignFile signs a file.
func ClearSignFile(fileName string, data []byte, signWith PrivateKeyset) (Message, error) {
	if fileName == "" {
		return Message{}, ErrEmptyFileName
	}

	m, err := ClearSign(data, signWith)
	if err != nil {
		return m, err
	}
	m.File = fileName

	return m, nil
}

// Message contains a message.
type Message struct {
	// sender`s public keyset fingerprint
	Fingerprint Fingerprint

	// signature
	Signature []byte

	// encapsulated shared secret
	Key []byte

	// file name
	File string

	// data
	Data []byte
}

// IsEncrypted returns true if the message is encrypted.
func (m Message) IsEncrypted() bool { return len(m.Key) != 0 }

// IsClearSign returns true if the message is signed and not encrypted.
func (m Message) IsClearSign() bool { return !m.IsEncrypted() && m.IsSigned() }

// IsAnonymous returns true if the message is not signed and has no fingerprint.
func (m Message) IsAnonymous() bool { return !m.IsSigned() && m.Fingerprint == Fingerprint{} }

// IsSigned returns true if the message is signed.
func (m Message) IsSigned() bool { return len(m.Signature) != 0 }
