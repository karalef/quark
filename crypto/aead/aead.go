// Package aead provides authenticated encryption with associated data
// but unlike the standard cipher.AEAD has a cipher.Stream-based interface
// and allows encrypting data streams.
// This is based on a combination of stream cipher and MAC using the Encrypt-then-MAC approach.
package aead

import (
	"github.com/karalef/quark/crypto/cipher"
	"github.com/karalef/quark/crypto/mac"
)

// Cipher represents authenticated cipher.
type Cipher interface {
	Crypt(dst, src []byte)

	// Tag appends the current mac to b and returns the resulting slice.
	// It does not change the underlying MAC state.
	Tag(b []byte) []byte
}

// New returns a new AE cipher.
func New(s Scheme, iv, cipherKey, macKey, associatedData []byte, decrypt bool) (Cipher, error) {
	cipher, err := s.Cipher().New(cipherKey, iv)
	if err != nil {
		return nil, err
	}

	if len(macKey) != s.MAC().KeySize() {
		return nil, mac.ErrKeySize
	}
	mac := s.MAC().New(macKey)
	mac.Write(iv)
	mac.Write(associatedData)

	crypt := xorThenMAC
	if decrypt {
		crypt = macThenXOR
	}
	return &baseAE{
		cipher: cipher,
		mac:    mac,
		crypt:  crypt,
	}, nil
}

type baseAE struct {
	cipher cipher.Cipher
	mac    mac.MAC
	crypt  func(ae *baseAE, dst, src []byte)
}

func (e *baseAE) Tag(b []byte) []byte   { return e.mac.Tag(b) }
func (e *baseAE) Crypt(dst, src []byte) { e.crypt(e, dst, src) }

func xorThenMAC(ae *baseAE, dst, src []byte) {
	ae.cipher.XORKeyStream(dst, src)
	ae.mac.Write(dst)
}

func macThenXOR(ae *baseAE, dst, src []byte) {
	ae.mac.Write(src)
	ae.cipher.XORKeyStream(dst, src)
}
