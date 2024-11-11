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
func NewSecret(scheme secret.Scheme) Secret { return Secret(scheme) }

// Secret contains shared secret based encryption parameters.
type Secret secret.Scheme

// Scheme returns the secret scheme.
func (s Secret) Scheme() secret.Scheme { return secret.Scheme(s) }

// NewCrypter creates a new Crypter with the given shared secret.
func (s Secret) NewCrypter(sharedSecret []byte) (*Crypter, error) {
	scheme := s.Scheme()
	return NewCrypter(scheme.AEAD(), scheme.DeriveKey(sharedSecret))
}

func (s Secret) EncodeMsgpack(enc *pack.Encoder) error { return s.Scheme().EncodeMsgpack(enc) }
func (s *Secret) DecodeMsgpack(dec *pack.Decoder) error {
	return (*secret.Scheme)(s).DecodeMsgpack(dec)
}

type PassphraseParams struct {
	Cost     kdf.Cost
	Scheme   password.Scheme
	SaltSize int
}

func (p PassphraseParams) New() Passphrase { return NewPassphrase(p) }

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
	Cost   kdf.Cost        `msgpack:"cost"`
	Scheme password.Scheme `msgpack:"scheme"`
	Salt   []byte          `msgpack:"salt"`
}

// Params returns the passphrase parameters.
func (p Passphrase) Params() PassphraseParams {
	return PassphraseParams{
		Scheme:   p.Scheme,
		Cost:     p.Cost,
		SaltSize: len(p.Salt),
	}
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
		Scheme password.Scheme `msgpack:"scheme"`
		Salt   []byte          `msgpack:"salt"`
		Cost   pack.Raw        `msgpack:"cost"`
	}
	if err := dec.Decode(&m); err != nil {
		return err
	}
	p.Scheme = m.Scheme
	p.Salt = m.Salt
	p.Cost = p.Scheme.KDF().NewCost()
	return pack.DecodeBinary(bytes.NewReader(m.Cost), p.Cost)
}
