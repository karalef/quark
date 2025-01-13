package encrypted

import (
	"bytes"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/pack"
)

// PassphraseParams contains passphrase-based encryption parameters.
type PassphraseParams struct {
	Cost     kdf.Cost
	Scheme   Passphrase
	SaltSize int
}

func (p PassphraseParams) New() Passphrased { return NewPassphrased(p) }

// NewPassphrased creates a new Passphrased with the given passphrase parameters.
func NewPassphrased(p PassphraseParams) Passphrased {
	return Passphrased{
		Passphrase: p.Scheme,
		Salt:       crypto.Rand(p.SaltSize),
		Cost:       p.Cost,
	}
}

// NewPassphrasedFrom creates a new Passphrased with the given scheme, cost and salt size.
func NewPassphrasedFrom(scheme Passphrase, cost kdf.Cost, saltSize int) Passphrased {
	return NewPassphrased(PassphraseParams{Scheme: scheme, Cost: cost, SaltSize: saltSize})
}

// Passphrased contains passphrase-based encryption parameters.
type Passphrased struct {
	Passphrase `msgpack:"scheme"`
	Cost       kdf.Cost `msgpack:"cost"`
	Salt       []byte   `msgpack:"salt"`
}

// Params returns the passphrase parameters.
func (p Passphrased) Params() PassphraseParams {
	return PassphraseParams{
		Scheme:   p.Passphrase,
		Cost:     p.Cost,
		SaltSize: len(p.Salt),
	}
}

// Crypter creates a new Crypter with the given passphrase.
func (p Passphrased) Crypter(passphrase string) (*Crypter, error) {
	return p.Passphrase.Crypter(passphrase, p.Salt, p.Cost)
}

// Encrypter returns Cipher in encryption mode.
// Panics if nonce is not of length NonceSize().
func (p Passphrased) Encrypter(passphrase string, nonce, ad []byte) (aead.Cipher, error) {
	return p.Passphrase.Encrypter(passphrase, nonce, p.Salt, ad, p.Cost)
}

// Decrypter returns Cipher in decryption mode.
// Panics if nonce is not of length NonceSize().
func (p Passphrased) Decrypter(passphrase string, nonce, ad []byte) (aead.Cipher, error) {
	return p.Passphrase.Decrypter(passphrase, nonce, p.Salt, ad, p.Cost)
}

// DecodeMsgpack implements pack.CustomDecoder
func (p *Passphrased) DecodeMsgpack(dec *pack.Decoder) error {
	var m struct {
		Scheme Passphrase `msgpack:"scheme"`
		Salt   []byte     `msgpack:"salt"`
		Cost   pack.Raw   `msgpack:"cost"`
	}
	if err := dec.Decode(&m); err != nil {
		return err
	}
	p.Passphrase = m.Scheme
	p.Salt = m.Salt
	p.Cost = p.KDF().NewCost()
	return pack.DecodeBinary(bytes.NewReader(m.Cost), p.Cost)
}
