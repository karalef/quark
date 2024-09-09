package secret

import (
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/xof"
	"github.com/karalef/quark/internal"
)

// Build creates a password-based authenticated encryption scheme.
// Panics if one of the arguments is nil.
func Build(aead aead.Scheme, xof xof.XOF) Scheme {
	if aead == nil || xof == nil {
		panic("secret.Build: nil scheme part")
	}
	return &scheme{
		name: internal.CompleteSchemeName(aead, xof),
		aead: aead,
		xof:  xof,
	}
}

type scheme struct {
	name string
	aead aead.Scheme
	xof  xof.XOF
}

func (s scheme) Name() string      { return s.name }
func (s scheme) AEAD() aead.Scheme { return s.aead }
func (s scheme) XOF() xof.XOF      { return s.xof }

func (s scheme) crypter(iv, sharedSecret, associatedData []byte, decrypt bool) (aead.Cipher, error) {
	cipherKey, macKey, err := DeriveKeys(s, sharedSecret)
	if err != nil {
		return nil, err
	}
	return s.AEAD().Crypter(iv, cipherKey, macKey, associatedData, decrypt)
}

func (s scheme) Encrypter(iv, sharedSecret, associatedData []byte) (aead.Cipher, error) {
	return s.crypter(iv, sharedSecret, associatedData, false)
}

func (s scheme) Decrypter(iv, sharedSecret, associatedData []byte) (aead.Cipher, error) {
	return s.crypter(iv, sharedSecret, associatedData, true)
}
