// Package secret provides a wrapper for AEAD that uses XOF to derive keys from shared secret.
package secret

import (
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/xof"
	"github.com/karalef/quark/internal"
)

// Scheme represents an authenticated encryption scheme based on XOF.
type Scheme interface {
	internal.Scheme
	// If AEAD's MAC has not fixed key size, the mac key size will be min(len(cipherKey), MaxKeySize()).
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
func DeriveKeys(s Scheme, sharedSecret []byte) ([]byte, []byte, error) {
	cipherSize, macSize := s.AEAD().Cipher().KeySize(), s.AEAD().MAC().KeySize()
	if macSize == 0 {
		macSize = min(s.AEAD().MAC().MaxKeySize(), cipherSize)
	}
	key := make([]byte, cipherSize)
	macKey := make([]byte, macSize)
	xof := s.XOF().New()
	xof.Write(sharedSecret)
	xof.Read(key)
	xof.Read(macKey)
	return key, macKey, nil
}
