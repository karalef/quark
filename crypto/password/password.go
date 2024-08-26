// Package password provides password-based authenticated encryption.
package password

import (
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/internal"
)

// Scheme represents password-based authenticated encryption scheme.
type Scheme interface {
	internal.Scheme
	// If AEAD's MAC has not fixed key size, the mac key size will be min(len(cipherKey), MaxKeySize()).
	AEAD() aead.Scheme
	KDF() kdf.KDF

	// Encrypter returns Cipher in encryption mode.
	// Panics if iv is not of length AEAD().Cipher().IVSize().
	Encrypter(password string, iv, salt, ad []byte, params kdf.Params) (aead.Cipher, error)

	// Decrypter returns Cipher in decryption mode.
	// Panics if iv is not of length AEAD().Cipher().IVSize().
	Decrypter(password string, iv, salt, ad []byte, params kdf.Params) (aead.Cipher, error)
}

// DeriveKeys derives cipher and MAC keys from a password and salt.
func DeriveKeys(s Scheme, password string, salt []byte, params kdf.Params) ([]byte, []byte, error) {
	cipherSize, macSize := s.AEAD().Cipher().KeySize(), s.AEAD().MAC().KeySize()
	if macSize == 0 {
		macSize = min(s.AEAD().MAC().MaxKeySize(), cipherSize)
	}
	keys, err := s.KDF().Derive([]byte(password), salt, cipherSize+macSize, params)
	if err != nil {
		return nil, nil, err
	}
	return keys[:cipherSize], keys[cipherSize:], nil
}
