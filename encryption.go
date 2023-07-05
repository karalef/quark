package quark

import (
	"errors"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/ae"
)

// Encrypt creates an authenticated cipher and Encryption.
func Encrypt(scheme SymmetricScheme, recipient Public) (ae.AE, *Encryption, error) {
	kem := recipient.KEM()
	ciphertext, secret, err := kem.Encapsulate(crypto.Rand(kem.Scheme().EncapsulationSeedSize()))
	if err != nil {
		return nil, nil, err
	}
	iv := crypto.Rand(scheme.Cipher().IVSize())
	ae, err := scheme.Encrypter(secret, iv)
	if err != nil {
		return nil, nil, err
	}

	return ae, &Encryption{
		ID: recipient.ID(),
		Symmetric: Symmetric{
			Scheme: scheme,
			IV:     iv,
		},
		Secret: ciphertext,
	}, nil
}

// Decrypt creates an authenticated cipher from Encryption and recipient.
func Decrypt(enc *Encryption, recipient Private) (ae.AE, error) {
	if enc.ID != recipient.ID() {
		return nil, errors.New("wrong recipient")
	}
	sharedSecret, err := recipient.KEM().Decapsulate(enc.Secret)
	if err != nil {
		return nil, err
	}
	return enc.Symmetric.Scheme.Decrypter(sharedSecret, enc.Symmetric.IV)
}

// Encryption contains encapsulated shared secret with symmetric encryption parameters.
type Encryption struct {
	// keyset id used for encapsulation
	ID ID `msgpack:"id"`

	// symmetric encryption parameters.
	Symmetric Symmetric `msgpack:"symmetric"`

	// encapsulated shared secret
	Secret []byte `msgpack:"secret"`
}

// Validate compares the encryption data against the private keyset id and scheme.
func (e *Encryption) Validate(p Private) error {
	if e.ID != p.ID() {
		return errors.New("wrong recipient")
	}
	if len(e.Secret) != p.Scheme().KEM.CiphertextSize() {
		return errors.New("invalid encrypted secret size")
	}
	return nil
}
