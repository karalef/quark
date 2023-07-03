// Package ae provides authenticated encryption.
// This is based on a combination of a stream cipher with MAC.
package ae

import (
	"github.com/karalef/quark/crypto/cipher"
	"github.com/karalef/quark/crypto/mac"
	"github.com/karalef/quark/crypto/xof"
)

// AE represents authenticated cipher.
type AE interface {
	Crypt(dst, src []byte)

	// Tag appends the current mac to b and returns the resulting slice.
	// It does not change the underlying MAC state.
	Tag(b []byte) []byte
}

// Scheme represents authenticated encryption scheme.
type Scheme interface {
	Approach() Approach
	Cipher() cipher.Scheme
	MAC() mac.Scheme
	XOF() xof.XOF

	// Encrypter returns AE in encryption mode.
	// Panics if iv is not of length Cipher().IVSize().
	Encrypter(sharedSecret, iv []byte) (AE, error)

	// Decrypter returns AE in decryption mode.
	// Panics if iv is not of length Cipher().IVSize().
	Decrypter(sharedSecret, iv []byte) (AE, error)
}

func newAE(s Scheme, cipherKey, macKey, iv []byte, crypt func(*baseAE, []byte, []byte)) (AE, error) {
	cipher, err := s.Cipher().New(cipherKey, iv)
	if err != nil {
		return nil, err
	}

	mac := s.MAC().New(macKey)
	mac.Write(iv)

	return &baseAE{
		cipher: cipher,
		mac:    mac,
		crypt:  crypt,
	}, nil
}

type baseAE struct {
	cipher cipher.Stream
	mac    mac.MAC
	crypt  func(ae *baseAE, dst, src []byte)
}

func (e *baseAE) Tag(b []byte) []byte   { return e.mac.Tag(b) }
func (e *baseAE) Crypt(dst, src []byte) { e.crypt(e, dst, src) }
