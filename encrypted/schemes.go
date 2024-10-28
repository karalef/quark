package encrypted

import (
	"bytes"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/encrypted/password"
	"github.com/karalef/quark/encrypted/secret"
	"github.com/karalef/quark/pack"
)

// NewSecret creates a new Secret with the given scheme.
func NewSecret(scheme *secret.Scheme) Secret {
	return Secret{Secret: scheme}
}

// Secret contains shared secret based encryption parameters.
type Secret struct {
	Secret *secret.Scheme `msgpack:"secret"`
}

// NewCrypter creates a new Crypter with the given shared secret.
func (s Secret) NewCrypter(sharedSecret []byte) (*Crypter, error) {
	return NewCrypter(s.Secret.AEAD(), s.Secret.DeriveKey(sharedSecret))
}

type PassphraseParams struct {
	Scheme   *password.Scheme
	Cost     kdf.Cost
	SaltSize int
}

// NewPassphrase creates a new Passphrase with the given scheme, cost and salt size.
func NewPassphrase(p PassphraseParams) Passphrase {
	return Passphrase{
		Scheme: p.Scheme,
		Salt:   crypto.Rand(p.SaltSize),
		Cost:   p.Cost,
	}
}

// Passphrase contains passphrase-based encryption parameters.
type Passphrase struct {
	Scheme *password.Scheme `msgpack:"scheme"`
	Salt   []byte           `msgpack:"salt"`
	Cost   kdf.Cost         `msgpack:"cost"`
}

// NewCrypter creates a new Crypter with the given passphrase.
func (p Passphrase) NewCrypter(passphrase string) (*Crypter, error) {
	key, err := p.Scheme.DeriveKey(passphrase, p.Salt, p.Cost)
	if err != nil {
		return nil, err
	}
	return NewCrypter(p.Scheme.AEAD(), key)
}

// DecodeMsgpack implements pack.CustomDecoder
func (p *Passphrase) DecodeMsgpack(dec *pack.Decoder) error {
	var m struct {
		Scheme *password.Scheme `msgpack:"scheme"`
		Salt   []byte           `msgpack:"salt"`
		Cost   pack.Raw         `msgpack:"cost"`
	}
	err := dec.Decode(&m)
	if err != nil {
		return err
	}
	p.Scheme = m.Scheme
	p.Salt = m.Salt
	p.Cost = p.Scheme.KDF().NewCost()
	return pack.DecodeBinary(bytes.NewReader(m.Cost), p.Cost)
}
