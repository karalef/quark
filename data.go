package quark

import "errors"

// file errors.
var (
	ErrEmpty         = errors.New("empty data")
	ErrEmptyFileName = errors.New("empty file name")
)

func encryptData(data []byte, to PublicKeyset, signWith PrivateKeyset) (Data, error) {
	if len(data) == 0 {
		return Data{}, ErrEmpty
	}

	ck, ct, err := Encrypt(data, to)
	if err != nil {
		return Data{}, err
	}

	d := Data{
		EncryptedKey:  ck,
		EncryptedData: ct,
	}

	if signWith == nil {
		return d, nil
	}

	signature, err := signWith.Sign(data)
	if err != nil {
		return Data{}, err
	}

	d.Signature = signature
	d.Fingerprint = FingerprintOf(signWith)

	return d, nil
}

// EncryptMessage encrypts a message.
func EncryptMessage(msg []byte, to PublicKeyset, signWith PrivateKeyset) (*Message, error) {
	d, err := encryptData(msg, to, signWith)
	if err != nil {
		return nil, err
	}

	return &Message{
		Data: d,
	}, nil
}

// EncryptFile encrypts a file.
func EncryptFile(fileName string, data []byte, to PublicKeyset, signWith PrivateKeyset) (*File, error) {
	if fileName == "" {
		return nil, ErrEmptyFileName
	}

	d, err := encryptData(data, to, signWith)
	if err != nil {
		return nil, err
	}

	return &File{
		Name: fileName,
		Data: d,
	}, nil
}

// Data contains an encrypted data.
type Data struct {
	// sender`s public key fingerprint
	Fingerprint Fingerprint

	// signature
	Signature []byte

	// encrypted session key
	EncryptedKey []byte

	// encrypted data
	EncryptedData []byte
}

// IsAnonymous returns true if the message is anonymous.
func (d Data) IsAnonymous() bool { return !d.IsSigned() && d.Fingerprint == Fingerprint{} }

// IsSigned returns true if the message is signed.
func (d Data) IsSigned() bool { return len(d.Signature) != 0 }

// Message contains an encrypted message.
type Message struct {
	Data
}

// File contains an encrypted file.
type File struct {
	Data

	// file name
	Name string
}
