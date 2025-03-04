package quark

import (
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/scheme"
)

// NewMaster returns a new master key.
func NewMaster(scheme aead.Scheme, exp kdf.Expander) Master {
	return Master{
		sch: scheme,
		exp: exp,
	}
}

// Master is a key used to derive a cipher keys.
type Master struct {
	sch aead.Scheme
	exp kdf.Expander
}

// Derive derives a key with the given info.
func (mk Master) Derive(info []byte) []byte {
	return mk.exp.Expand(info, uint(mk.sch.KeySize()))
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

// Extractor is a custom extractor that can use any secret transport mechanism.
type Extractor[T kdf.Extractor[Secret], Secret any] struct {
	Extractor T      `msgpack:"ext"`
	Salt      []byte `msgpack:"salt"`
}

// Extract derives the expander from the secret.
func (e Extractor[T, Secret]) Extract(secret Secret) (kdf.Expander, error) {
	return e.Extractor.Extract(secret, e.Salt)
}

// Expand expands the master key.
func (e Extractor[T, Secret]) Expand(key []byte) kdf.Expander {
	return e.Extractor.Expand(key)
}

// NewMasterKey returns a new master key.
func NewMasterKey[T kdf.Extractor[Secret], Secret any](cipher aead.Scheme, salt []byte, ext T) MasterKey[T, Secret] {
	return MasterKey[T, Secret]{
		Extractor: Extractor[T, Secret]{
			Extractor: ext,
			Salt:      salt,
		},
		Cipher: scheme.NewAlgorithm[aead.Scheme, aead.Registry](cipher),
	}
}

// MasterKey is a master key that can use any secret transport mechanism.
type MasterKey[T kdf.Extractor[Secret], Secret any] struct {
	Extractor[T, Secret]
	Cipher aead.Algorithm `msgpack:"cipher"`
}

// Extract extracts the master key from the secret.
func (m MasterKey[T, Secret]) Extract(secret Secret) (Master, error) {
	master, err := m.Extractor.Extract(secret)
	if err != nil {
		return Master{}, err
	}
	return NewMaster(m.Cipher.Scheme, master), nil
}

// Expand expands the master key.
func (m MasterKey[T, Secret]) Expand(key []byte) kdf.Expander {
	return m.Extractor.Expand(key)
}
