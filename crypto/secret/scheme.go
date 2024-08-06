package secret

import (
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/xof"
)

// Build creates a password-based authenticated encryption scheme.
// Panics if one of the arguments is nil.
func Build(aead aead.Scheme, xof xof.XOF) Scheme {
	if aead == nil || xof == nil {
		panic("secret.Build: nil scheme part")
	}
	return &scheme{
		aead: aead,
		xof:  xof,
	}
}

type scheme struct {
	aead aead.Scheme
	xof  xof.XOF
}

func (s scheme) AEAD() aead.Scheme { return s.aead }
func (s scheme) XOF() xof.XOF      { return s.xof }

func (s scheme) crypter(iv, sharedSecret, associatedData []byte, decrypt bool) (aead.Cipher, error) {
	cipherKey, macKey, err := DeriveKeys(s, iv, sharedSecret)
	if err != nil {
		return nil, err
	}
	if decrypt {
		return s.AEAD().Decrypter(iv, cipherKey, macKey, associatedData)
	}
	return s.AEAD().Encrypter(iv, cipherKey, macKey, associatedData)
}

func (s scheme) Encrypter(iv, sharedSecret, associatedData []byte) (aead.Cipher, error) {
	return s.crypter(iv, sharedSecret, associatedData, false)
}

func (s scheme) Decrypter(iv, sharedSecret, associatedData []byte) (aead.Cipher, error) {
	return s.crypter(iv, sharedSecret, associatedData, true)
}
