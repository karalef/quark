package password

import (
	"github.com/karalef/quark/crypto/ae"
	"github.com/karalef/quark/crypto/kdf"
)

// Build creates a password-based authenticated encryption scheme.
// Panics if one of the arguments is nil.
func Build(ae ae.Scheme, kdf kdf.KDF) Scheme {
	if ae == nil || kdf == nil {
		panic("password.Build: nil scheme part")
	}
	return &scheme{
		ae:  ae,
		kdf: kdf,
	}
}

type scheme struct {
	ae  ae.Scheme
	kdf kdf.KDF
}

func (s scheme) AE() ae.Scheme { return s.ae }
func (s scheme) KDF() kdf.KDF  { return s.kdf }

func (s scheme) Encrypter(password string, iv, salt []byte, params kdf.Params) (Crypter, error) {
	key, err := DeriveKey(s, password, salt, params)
	if err != nil {
		return nil, err
	}
	enc, err := s.AE().Encrypter(key, iv)
	if err != nil {
		return nil, err
	}
	return crypter{scheme: s, AE: enc}, nil
}

func (s scheme) Decrypter(password string, iv, salt []byte, params kdf.Params) (Crypter, error) {
	key, err := DeriveKey(s, password, salt, params)
	if err != nil {
		return nil, err
	}
	dec, err := s.AE().Decrypter(key, iv)
	if err != nil {
		return nil, err
	}
	return crypter{scheme: s, AE: dec}, nil
}
