package password

import (
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/internal"
)

// Build creates a password-based authenticated encryption scheme.
// Panics if one of the arguments is nil.
func Build(aead aead.Scheme, kdf kdf.KDF) Scheme {
	if aead == nil || kdf == nil {
		panic("password.Build: nil scheme part")
	}
	return &scheme{
		name: internal.CompleteSchemeName(aead, kdf),
		aead: aead,
		kdf:  kdf,
	}
}

type scheme struct {
	name string
	aead aead.Scheme
	kdf  kdf.KDF
}

func (s scheme) Name() string      { return s.name }
func (s scheme) AEAD() aead.Scheme { return s.aead }
func (s scheme) KDF() kdf.KDF      { return s.kdf }

func (s scheme) crypter(password string, iv, salt, ad []byte, params kdf.Params, decrypt bool) (aead.Cipher, error) {
	cipherKey, macKey, err := DeriveKeys(s, password, salt, params)
	if err != nil {
		return nil, err
	}
	return s.AEAD().Crypter(iv, cipherKey, macKey, ad, decrypt)
}

func (s scheme) Encrypter(password string, iv, salt, ad []byte, params kdf.Params) (aead.Cipher, error) {
	return s.crypter(password, iv, salt, ad, params, false)
}

func (s scheme) Decrypter(password string, iv, salt, ad []byte, params kdf.Params) (aead.Cipher, error) {
	return s.crypter(password, iv, salt, ad, params, true)
}
