package quark

import (
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/scheme"
)

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

// Expand implements kdf.Extractor.
func (e Decapsulator) Expand(ss []byte) kdf.Expander {
	return e.KDF.Scheme.Expander(ss)
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
