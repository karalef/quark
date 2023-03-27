package quark

import "errors"

// file errors.
var (
	ErrEmptyFile     = errors.New("empty file")
	ErrEmptyFileName = errors.New("empty file name")
)

func EncryptFile(fileName string, data []byte, to PublicKeyset, signWith PrivateKeyset) (*File, error) {
	if len(data) == 0 {
		return nil, ErrEmptyFile
	}
	if fileName == "" {
		return nil, ErrEmptyFileName
	}

	cipherkey, ciphertext, err := Encrypt(data, to)
	if err != nil {
		return nil, err
	}

	file := &File{
		Key:  cipherkey,
		Name: fileName,
		Data: ciphertext,
	}

	if signWith == nil {
		return file, nil
	}

	signature, err := signWith.Sign(data)
	if err != nil {
		return nil, err
	}

	file.Signature = signature
	file.Fingerprint = PublicFingerprint(signWith)

	return file, nil
}

func DecryptFile(file *File, to PrivateKeyset) ([]byte, error) {
	if file == nil {
		return nil, nil
	}

	return Decrypt(file.Data, file.Key, to)
}

// File contains an encrypted file.
type File struct {
	// sender`s public key fingerprint
	Fingerprint Fingerprint

	// signature
	Signature []byte

	// encrypted session key
	Key []byte

	// file name
	Name string

	// encrypted data
	Data []byte
}

// IsAnonymous returns true if the message is anonymous.
func (f File) IsAnonymous() bool { return !f.IsSigned() && f.Fingerprint == Fingerprint{} }

func (f File) IsSigned() bool { return len(f.Signature) != 0 }
