package password

import (
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/scheme"
)

// Build creates a password-based authenticated encryption scheme.
// Panics if one of the arguments is nil.
func Build(aead aead.Scheme, kdf kdf.Scheme) Scheme {
	if aead == nil || kdf == nil {
		panic("password.Build: nil scheme part")
	}
	return &baseScheme{
		StringName: scheme.StringName(scheme.Join(aead, kdf)),
		aead:       aead,
		kdf:        kdf,
	}
}

// FromName creates a password scheme from its name.
func FromName(schemeName string) (Scheme, error) {
	parts, err := scheme.SplitN(schemeName, 3)
	if err != nil {
		return nil, err
	}
	return FromNames(parts[0], parts[1], parts[2])
}

// FromNames creates a password scheme from its part names.
func FromNames(cipherName, macName, kdfName string) (Scheme, error) {
	kdf, err := kdf.ByName(kdfName)
	if err != nil {
		return nil, err
	}
	aead, err := aead.FromNames(cipherName, macName)
	if err != nil {
		return nil, err
	}
	return Build(aead, kdf), nil
}

type baseScheme struct {
	scheme.StringName
	aead aead.Scheme
	kdf  kdf.Scheme
}

func (s baseScheme) AEAD() aead.Scheme { return s.aead }
func (s baseScheme) KDF() kdf.Scheme   { return s.kdf }

func (s baseScheme) crypter(password string, iv, salt, ad []byte, params kdf.Cost, decrypt bool) (aead.Cipher, error) {
	cipherKey, macKey, err := DeriveKeys(s, password, salt, params)
	if err != nil {
		return nil, err
	}
	return s.AEAD().Crypter(iv, cipherKey, macKey, ad, decrypt)
}

func (s baseScheme) Encrypter(password string, iv, salt, ad []byte, params kdf.Cost) (aead.Cipher, error) {
	return s.crypter(password, iv, salt, ad, params, false)
}

func (s baseScheme) Decrypter(password string, iv, salt, ad []byte, params kdf.Cost) (aead.Cipher, error) {
	return s.crypter(password, iv, salt, ad, params, true)
}
