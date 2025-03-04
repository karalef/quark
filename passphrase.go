package quark

import (
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/crypto/pbkdf"
	"github.com/karalef/quark/scheme"
)

// NewPassphrase creates a new passphrase-based scheme.
func NewPassphrase(cipher aead.Scheme, salt []byte, sch pbkdf.KDF) Passphrase {
	return Passphrase{
		Scheme: pbkdf.Salted{
			KDF:  sch,
			Salt: salt,
		},
		Cipher: scheme.NewAlgorithm[aead.Scheme, aead.Registry](cipher),
	}
}

// Passphrase is a passphrase-based scheme to derive a cipher key.
type Passphrase struct {
	Scheme pbkdf.Salted   `msgpack:"scheme"`
	Cipher aead.Algorithm `msgpack:"cipher"`
}

// Derive derives a key from a passphrase.
func (p Passphrase) Derive(passphrase []byte) ([]byte, error) {
	return p.Scheme.Derive(passphrase, uint32(p.Cipher.Scheme.KeySize()))
}

// Key derives a cipher key from a passphrase.
func (p Passphrase) Key(passphrase []byte) (Cipher, error) {
	key, err := p.Derive(passphrase)
	if err != nil {
		return Cipher{}, err
	}
	return NewCipher(p.Cipher.Scheme, key)
}

// NewMasterPassphrase creates a new passphrase-based scheme to derive the master key.
func NewMasterPassphrase(sch pbkdf.Fixed, cipher aead.Scheme, salt []byte, exp kdf.Scheme) MasterPassphrase {
	return NewMasterKey(cipher, salt, PassphraseExtractor{
		Scheme: sch,
		KDF:    scheme.NewAlgorithm[kdf.Scheme, kdf.Registry](exp),
	},
	)
}

// MasterPassphrase is a passphrase-based scheme to derive the master key.
// The PBKDF is used instead of KDF extraction phase since the result has
// enough entropy.
type MasterPassphrase = MasterKey[PassphraseExtractor, []byte]

// PassphraseExtractor is a PBKDF kdf.Extractor.
type PassphraseExtractor struct {
	Scheme pbkdf.Fixed   `msgpack:"scheme"`
	KDF    kdf.Algorithm `msgpack:"kdf"`
}

// Extract returns kdf.Expander derived from passphrase.
// It skips the master key extraction step since the key derived using PBKDF
// already has enough entropy.
func (m PassphraseExtractor) Extract(passphrase, salt []byte) (kdf.Expander, error) {
	master, err := m.Scheme.Derive(passphrase, salt)
	if err != nil {
		return nil, err
	}
	return m.KDF.Scheme.Expander(master), nil
}

// Expand implements kdf.Extractor.
func (m PassphraseExtractor) Expand(ss []byte) kdf.Expander { return m.KDF.Scheme.Expander(ss) }
