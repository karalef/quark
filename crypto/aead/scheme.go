package aead

import (
	"github.com/karalef/quark/crypto/cipher"
	"github.com/karalef/quark/crypto/mac"
)

// Scheme represents an AEAD scheme.
type Scheme interface {
	Cipher() cipher.Scheme
	MAC() mac.Scheme

	// Encrypter returns Cipher in encryption mode.
	// Panics if iv is not of length Cipher().IVSize().
	Encrypter(iv, key, macKey, associatedData []byte) (Cipher, error)

	// Decrypter returns Cipher in decryption mode.
	// Panics if iv is not of length Cipher().IVSize().
	Decrypter(iv, key, macKey, associatedData []byte) (Cipher, error)
}

// Build creates an AEAD scheme with the given approach.
// Panics if one of the arguments is nil.
func Build(cipher cipher.Scheme, mac mac.Scheme) Scheme {
	if cipher == nil || mac == nil {
		panic("nil scheme part")
	}
	return &scheme{
		cipher: cipher,
		mac:    mac,
	}
}

var _ Scheme = (*scheme)(nil)

type scheme struct {
	cipher cipher.Scheme
	mac    mac.Scheme
}

func (s *scheme) Cipher() cipher.Scheme { return s.cipher }
func (s *scheme) MAC() mac.Scheme       { return s.mac }

func (s *scheme) Encrypter(iv, key, macKey, associatedData []byte) (Cipher, error) {
	return New(s, iv, key, macKey, associatedData, false)
}
func (s *scheme) Decrypter(iv, key, macKey, associatedData []byte) (Cipher, error) {
	return New(s, iv, key, macKey, associatedData, true)
}
