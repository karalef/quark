// Package password provides password-based authenticated encryption.
package password

import (
	"github.com/karalef/quark/crypto/ae"
	"github.com/karalef/quark/crypto/kdf"
)

// Scheme represents password-based authenticated encryption scheme.
type Scheme interface {
	AE() ae.Scheme
	KDF() kdf.KDF

	// Encrypter returns Crypter in encryption mode.
	// Panics if iv is not of length AE().Cipher().IVSize().
	Encrypter(password string, iv, salt []byte, params kdf.Params) (Crypter, error)

	// Decrypter returns Crypter in decryption mode.
	// Panics if iv is not of length AE().Cipher().IVSize().
	Decrypter(password string, iv, salt []byte, params kdf.Params) (Crypter, error)
}

// DeriveKey derives a key from a password and salt.
func DeriveKey(s Scheme, password string, salt []byte, params kdf.Params) ([]byte, error) {
	size := s.AE().Cipher().KeySize()
	if s.AE().Approach() == ae.EncryptThanMAC {
		size *= 2
	}
	return s.KDF().Derive([]byte(password), salt, size, params)
}

// Crypter represents en/decrypter.
type Crypter interface {
	Scheme() Scheme
	Crypt(dst, src []byte)
	MAC() []byte
}

type crypter struct {
	scheme Scheme
	ae.AE
}

func (c crypter) Scheme() Scheme { return c.scheme }
