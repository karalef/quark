package quark

import (
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/pbkdf"
	"github.com/karalef/quark/crypto/pke"
)

// Openable represents the scheme to open a key/secret/message using
// any secret long term key.
type Openable[LTK any] interface {
	// OpenWith opens a secret using a long term key.
	OpenWith(LTK) ([]byte, error)
}

// Secret is a serialaizable Openable secret.
type Secret[T Openable[LTK], LTK any] struct {
	Data T `msgpack:",inline"`
}

// OpenWith opens a secret using a long term key.
func (s Secret[_, LTK]) OpenWith(sec LTK) ([]byte, error) {
	return s.Data.OpenWith(sec)
}

var (
	_ Openable[kem.PrivateKey] = Encapsulated{}
	_ Openable[pke.PrivateKey] = Encrypted{}
	_ Openable[[]byte]         = Passphrase{}
)

// Encapsulate encapsulates a random shared secret for recipient.
func Encapsulate(recipient kem.PublicKey) (Secret[Encapsulated, kem.PrivateKey], []byte, error) {
	ct, ss, err := kem.Encapsulate(recipient)
	return Secret[Encapsulated, kem.PrivateKey]{ct}, ss, err
}

// Encapsulated implements Openable for encapsulated shared secret.
type Encapsulated []byte

// OpenWith decapsulates the shared secret.
func (e Encapsulated) OpenWith(sk kem.PrivateKey) ([]byte, error) {
	return sk.Decapsulate(e)
}

// Encrypt encrypts a message for recipient.
func Encrypt(recipient pke.PublicKey, plaintext []byte) (Secret[Encrypted, pke.PrivateKey], error) {
	ct, err := pke.Encrypt(recipient, plaintext)
	return Secret[Encrypted, pke.PrivateKey]{ct}, err
}

// Encrypted implements Openable for assymetrically encrypted message.
type Encrypted []byte

// OpenWith decrypts the message.
func (e Encrypted) OpenWith(sk pke.PrivateKey) ([]byte, error) {
	return sk.Decrypt(e)
}

// NewPassphrase derives the key from a passphrase.
func NewPassphrase(pass []byte, sch pbkdf.KDF, saltSize, size uint32) (Secret[Passphrase, []byte], []byte, error) {
	salt := crypto.Rand(int(saltSize))
	key, err := sch.Derive(pass, salt, size)
	if err != nil {
		return Secret[Passphrase, []byte]{}, nil, err
	}
	return Secret[Passphrase, []byte]{Passphrase{
		KDF:  sch,
		Salt: salt,
		Len:  size,
	}}, key, nil
}

// Passphrase implements Openable for is a fixed-length parametrized PBKDF.
type Passphrase struct {
	KDF  pbkdf.KDF `msgpack:"kdf"`
	Len  uint32    `msgpack:"len"`
	Salt []byte    `msgpack:"salt"`
}

// OpenWith derives a fixed-length key from a passphrase.
func (m Passphrase) OpenWith(passphrase []byte) ([]byte, error) {
	return m.KDF.Derive(passphrase, m.Salt, m.Len)
}
