package password

import (
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/kdf"
)

// Build creates a password-based authenticated encryption scheme.
// Panics if one of the arguments is nil.
func Build(aead aead.Scheme, kdf kdf.KDF) Scheme {
	if aead == nil || kdf == nil {
		panic("password.Build: nil scheme part")
	}
	return &scheme{
		aead: aead,
		kdf:  kdf,
	}
}

type scheme struct {
	aead aead.Scheme
	kdf  kdf.KDF
}

func (s scheme) AEAD() aead.Scheme { return s.aead }
func (s scheme) KDF() kdf.KDF      { return s.kdf }

func (s scheme) crypter(password string, iv, salt, ad []byte, params kdf.Params, decrypt bool) (aead.Cipher, error) {
	cipherKey, macKey, err := DeriveKeys(s, password, salt, params)
	if err != nil {
		return nil, err
	}
	if decrypt {
		return s.AEAD().Decrypter(iv, cipherKey, macKey, ad)
	}
	return s.AEAD().Encrypter(iv, cipherKey, macKey, ad)
}

func (s scheme) Encrypter(password string, iv, salt, ad []byte, params kdf.Params) (aead.Cipher, error) {
	return s.crypter(password, iv, salt, ad, params, false)
}

func (s scheme) Decrypter(password string, iv, salt, ad []byte, params kdf.Params) (aead.Cipher, error) {
	return s.crypter(password, iv, salt, ad, params, true)
}
