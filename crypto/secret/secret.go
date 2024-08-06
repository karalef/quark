// Package secret provides a wrapper for AEAD that uses XOF to derive keys from shared secret.
package secret

import (
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/xof"
)

// Scheme represents an authenticated encryption scheme based on XOF.
type Scheme interface {
	AEAD() aead.Scheme
	XOF() xof.XOF

	// Encrypter returns Cipher in encryption mode.
	// Panics if iv is not of length AEAD().Cipher().IVSize().
	Encrypter(iv, sharedSecret, associatedData []byte) (aead.Cipher, error)

	// Decrypter returns Cipher in decryption mode.
	// Panics if iv is not of length AEAD().Cipher().IVSize().
	Decrypter(iv, sharedSecret, associatedData []byte) (aead.Cipher, error)
}

// DeriveKeys derives cipher and MAC keys from an IV and shared secret.
func DeriveKeys(s Scheme, iv, sharedSecret []byte) ([]byte, []byte, error) {
	key := make([]byte, s.AEAD().Cipher().KeySize())
	macKey := make([]byte, s.AEAD().MAC().KeySize())
	xof := s.XOF().New()
	xof.Write(sharedSecret)
	xof.Write(iv)
	xof.Read(key)
	xof.Read(macKey)
	return key, macKey, nil
}
