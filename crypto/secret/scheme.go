package secret

import (
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/xof"
	"github.com/karalef/quark/scheme"
)

// Build creates a password-based authenticated encryption scheme.
// Panics if one of the arguments is nil.
func Build(aead aead.Scheme, xof xof.Scheme) Scheme {
	if aead == nil || xof == nil {
		panic("secret.Build: nil scheme part")
	}
	return &baseScheme{
		StringName: scheme.StringName(scheme.Join(aead, xof)),
		aead:       aead,
		xof:        xof,
	}
}

// FromName creates a secret scheme from its name.
func FromName(schemeName string) (Scheme, error) {
	parts, err := scheme.SplitN(schemeName, 3)
	if err != nil {
		return nil, err
	}
	return FromNames(parts[0], parts[1], parts[2])
}

// FromNames creates a secret scheme from its part names.
func FromNames(cipherName, macName, xofName string) (Scheme, error) {
	xof, err := xof.ByName(xofName)
	if err != nil {
		return nil, err
	}
	aead, err := aead.FromNames(cipherName, macName)
	if err != nil {
		return nil, err
	}
	return Build(aead, xof), nil
}

type baseScheme struct {
	scheme.StringName
	aead aead.Scheme
	xof  xof.Scheme
}

func (s baseScheme) AEAD() aead.Scheme { return s.aead }
func (s baseScheme) XOF() xof.Scheme   { return s.xof }

func (s baseScheme) crypter(iv, sharedSecret, associatedData []byte, decrypt bool) (aead.Cipher, error) {
	cipherKey, macKey, err := DeriveKeys(s, sharedSecret)
	if err != nil {
		return nil, err
	}
	return s.AEAD().Crypter(iv, cipherKey, macKey, associatedData, decrypt)
}

func (s baseScheme) Encrypter(iv, sharedSecret, associatedData []byte) (aead.Cipher, error) {
	return s.crypter(iv, sharedSecret, associatedData, false)
}

func (s baseScheme) Decrypter(iv, sharedSecret, associatedData []byte) (aead.Cipher, error) {
	return s.crypter(iv, sharedSecret, associatedData, true)
}
