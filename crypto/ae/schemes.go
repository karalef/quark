package ae

import (
	"github.com/karalef/quark/crypto/cipher"
	"github.com/karalef/quark/crypto/mac"
	"github.com/karalef/quark/crypto/xof"
)

// BuildEtM creates an AE scheme with Encrypt-than-MAC approach.
func BuildEtM(cipher cipher.Scheme, mac mac.Scheme, xof xof.XOF) Scheme {
	return &scheme{
		cipher:    cipher,
		mac:       mac,
		xof:       xof,
		encrypter: NewEtMEncrypter,
		decrypter: NewEtMDecrypter,
	}
}

// BuildEandM creates an AE scheme with Encrypt-and-MAC approach.
func BuildEandM(cipher cipher.Scheme, mac mac.Scheme, xof xof.XOF) Scheme {
	return &scheme{
		cipher:    cipher,
		mac:       mac,
		xof:       xof,
		encrypter: NewEandMEncrypter,
		decrypter: NewEandMDecrypter,
	}
}

type newAEFunc func(s Scheme, sharedSecret, iv []byte) (AE, error)

var _ Scheme = (*scheme)(nil)

type scheme struct {
	cipher    cipher.Scheme
	mac       mac.Scheme
	xof       xof.XOF
	encrypter newAEFunc
	decrypter newAEFunc
}

func (s *scheme) Cipher() cipher.Scheme { return s.cipher }
func (s *scheme) MAC() mac.Scheme       { return s.mac }
func (s *scheme) XOF() xof.XOF          { return s.xof }

func (s *scheme) Encrypter(sharedSecret, iv []byte) (AE, error) {
	return s.encrypter(s, sharedSecret, iv)
}

func (s *scheme) Decrypter(sharedSecret, iv []byte) (AE, error) {
	return s.decrypter(s, sharedSecret, iv)
}
