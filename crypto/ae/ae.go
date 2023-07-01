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
	Scheme() Scheme
	Crypt(dst, src []byte)
	MAC() []byte
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

var (
	_ AE = (*baseAE)(nil)
)

func newAE(s Scheme, cipherKey, macKey, iv []byte, crypt func(*baseAE, []byte, []byte)) (AE, error) {
	cipher, err := s.Cipher().New(cipherKey, iv)
	if err != nil {
		return nil, err
	}

	mac := s.MAC().New(macKey)
	_, err = mac.Write(iv)
	if err != nil {
		panic(err)
	}

	return &baseAE{
		scheme: s,
		cipher: cipher,
		mac:    mac,
		crypt:  crypt,
	}, nil
}

type baseAE struct {
	scheme Scheme
	cipher cipher.Stream
	mac    mac.MAC
	crypt  func(ae *baseAE, dst, src []byte)
}

func (e *baseAE) Scheme() Scheme        { return e.scheme }
func (e *baseAE) MAC() []byte           { return e.mac.Tag(nil) }
func (e *baseAE) Crypt(dst, src []byte) { e.crypt(e, dst, src) }

func (e *baseAE) writeMAC(p []byte) {
	_, err := e.mac.Write(p)
	if err != nil {
		panic(err)
	}
}
