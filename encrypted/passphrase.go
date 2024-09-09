package encrypted

import (
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/crypto/password"
)

type PassphraseParams struct {
	Scheme   password.Scheme
	Cost     kdf.Cost
	SaltSize int
}

// NewPassphrase creates a new Passphrase with the given scheme, cost and salt size.
func NewPassphrase(p PassphraseParams) Passphrase {
	return Passphrase{
		Passphrase: PassphraseHeader{
			KDF:  KDF{Scheme: p.Scheme.KDF()},
			Cost: p.Cost,
			Salt: crypto.Rand(p.SaltSize),
		},
		Scheme: Scheme{Scheme: p.Scheme.AEAD()},
	}
}

// Passphrase contains passphrase-based encryption parameters.
type Passphrase struct {
	Passphrase PassphraseHeader `msgpack:"passphrase"`
	Scheme     Scheme           `msgpack:"scheme"`
}

// NewCrypter creates a new Crypter with the given passphrase.
func (p Passphrase) NewCrypter(passphrase string) (*Crypter, error) {
	key, mackey, err := p.Passphrase.DeriveKeys(p.Scheme, passphrase)
	if err != nil {
		return nil, err
	}
	return NewCrypter(p.Scheme, key, mackey)
}

// PassphraseHeader contains the parameters required to derive keys from a passphrase.
type PassphraseHeader struct {
	KDF  KDF      `msgpack:"kdf"`
	Cost kdf.Cost `msgpack:"cost"`
	Salt []byte   `msgpack:"salt"`
}

func (p PassphraseHeader) Build(aead aead.Scheme) password.Scheme {
	return password.Build(aead, p.KDF)
}

func (p PassphraseHeader) DeriveKeys(aead aead.Scheme, pasphrase string) ([]byte, []byte, error) {
	return password.DeriveKeys(p.Build(aead), pasphrase, p.Salt, p.Cost)
}
