package quark

import (
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/kdf"
)

// NewMaster returns a new master key.
func NewMaster(scheme aead.Scheme, kdf kdf.KDF) Master {
	return Master{
		sch: scheme,
		kdf: kdf,
	}
}

// Master is a key used to derive a cipher keys.
type Master struct {
	sch aead.Scheme
	kdf kdf.KDF
}

// Derive derives a key with the given info.
func (mk Master) Derive(info []byte) []byte {
	return mk.kdf.Derive(info, uint(mk.sch.KeySize()))
}

// New derives a cipher key with the given info.
func (mk Master) New(info []byte) (Cipher, error) {
	return NewCipher(mk.sch, mk.Derive(info))
}

// Encrypter returns a new encrypter using the key derived with info.
func (mk Master) Encrypter(info []byte, prf PRF) (Encrypter, error) {
	k, err := mk.New(info)
	if err != nil {
		return Encrypter{}, err
	}
	return NewEncrypter(k, prf), nil
}
