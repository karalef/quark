package quark

import (
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/scheme"
)

// Extractor is a custom extractor that can use any secret transport mechanism.
type Extractor[T kdf.Extractor[Secret], Secret any] struct {
	Extractor T      `msgpack:"ext"`
	Salt      []byte `msgpack:"salt"`
}

// Extract derives the expander from the secret.
func (e Extractor[T, Secret]) Extract(secret Secret) (kdf.Expander, error) {
	return e.Extractor.Extract(secret, e.Salt)
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

// Sealed is a KEM-based scheme to derive the master key.
type Sealed = MasterKey[Decapsulator, kem.PrivateKey]

// Encapsulated is a KEM-based scheme to derive the key expander.
type Encapsulated = Extractor[Decapsulator, kem.PrivateKey]

// Decapsulator is a custom extractor for encapsulated shared secret.
type Decapsulator struct {
	Ciphertext []byte        `msgpack:"encapsulated"`
	KDF        kdf.Algorithm `msgpack:"kdf"`
}

// Extract implements kdf.Extractor.
func (e Decapsulator) Extract(sk kem.PrivateKey, salt []byte) (kdf.Expander, error) {
	ss, err := sk.Decapsulate(e.Ciphertext)
	if err != nil {
		return nil, err
	}
	return e.KDF.Scheme.Extract(ss, salt), nil
}

// Encapsulate encapsulates a random shared secret for recipient and creates a KDF with
// random salt.
func Encapsulate(recipient kem.PublicKey, kdfScheme kdf.Scheme, saltSize uint) (Encapsulated, kdf.Expander, error) {
	ct, ss, err := kem.Encapsulate(recipient)
	if err != nil {
		return Encapsulated{}, nil, err
	}
	salted := kdf.NewSalted(kdfScheme, saltSize)
	return Encapsulated{
		Extractor: Decapsulator{
			Ciphertext: ct,
			KDF:        scheme.NewAlgorithm[kdf.Scheme, kdf.Registry](kdfScheme),
		},
		Salt: salted.Salt,
	}, salted.Extract(ss), nil
}

// Seal encapsulates a random shared secret for recipient and creates a master key using specified cipher.
func Seal(recipient kem.PublicKey, cipher aead.Scheme, kdfScheme kdf.Scheme, saltSize uint) (Sealed, Master, error) {
	encapsulated, expander, err := Encapsulate(recipient, kdfScheme, saltSize)
	if err != nil {
		return Sealed{}, Master{}, err
	}
	return Sealed{
		Extractor: encapsulated,
		Cipher:    scheme.NewAlgorithm[aead.Scheme, aead.Registry](cipher),
	}, NewMaster(cipher, expander), nil
}
