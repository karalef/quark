package aead

import (
	"github.com/karalef/quark/crypto/cipher"
	"github.com/karalef/quark/crypto/mac"
)

// Scheme represents an AEAD scheme.
type Scheme interface {
	Cipher() cipher.Scheme
	MAC() mac.Scheme

	// Encrypter returns Cipher in de/encryption mode.
	// Panics if iv is not of length Cipher().IVSize().
	Crypter(iv, key, macKey, associatedData []byte, decrypt bool) (Cipher, error)
}

// Build creates an AEAD scheme.
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

func (s *scheme) Crypter(iv, key, macKey, associatedData []byte, decrypt bool) (Cipher, error) {
	return New(s, iv, key, macKey, associatedData, decrypt)
}
