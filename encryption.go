package quark

import (
	"errors"

	"github.com/karalef/quark/internal"
	"github.com/karalef/quark/kem"
)

// Encryption contains encryption data.
type Encryption struct {
	// keyset id used for encapsulation
	ID ID `msgpack:"id"`

	// cipher nonce
	Nonce []byte `msgpack:"nonce"`

	// encapsulated shared secret
	Secret []byte `msgpack:"secret"`
}

// IsValid returns true if the encryption data is valid.
func (e *Encryption) IsValid() bool {
	if e == nil {
		return false
	}
	return !e.ID.IsEmpty() && len(e.Nonce) > 0 && len(e.Secret) > 0
}

func (e *Encryption) Error() string {
	switch {
	case e == nil, len(e.Secret) == 0, len(e.Nonce) == 0:
		return "empty encryption"
	case e.ID.IsEmpty():
		return "empty keyset id"
	}
	return ""
}

// Validate compares the encryption data against the private keyset id and scheme.
func (e *Encryption) Validate(p Private) error {
	if e.ID != p.ID() {
		return errors.New("wrong recipient")
	}
	if len(e.Nonce) != p.KEM().Scheme().Cipher().NonceSize() {
		return errors.New("invalid nonce size")
	}
	if len(e.Secret) != p.KEM().Scheme().CiphertextSize() {
		return errors.New("invalid encrypted secret size")
	}
	return nil
}

// Encrypt encrypts data for the public key and appends the result to dst, returning the updated slice.
// The result ciphertext includes encrypted data with appended auth tag.
func Encrypt(dst, data []byte, recipient Public) (ciphertext []byte, enc *Encryption) {
	nonce := internal.Rand(recipient.KEM().Scheme().Cipher().NonceSize())
	secretSeed := internal.Rand(recipient.KEM().Scheme().EncapsulationSeedSize())

	ciphertext, encryptedSecret := kem.Seal(recipient.KEM(), dst, secretSeed, nonce, data)
	return ciphertext, &Encryption{
		ID:     recipient.ID(),
		Nonce:  nonce,
		Secret: encryptedSecret,
	}
}

// Decrypt decrypts data for the private key and appends the result to dst, returning the updated slice.
// dst can be ciphertext[:0] to reuse the storage of ciphertext.
func Decrypt(dst, ciphertext []byte, enc *Encryption, recipient Private) ([]byte, error) {
	err := enc.Validate(recipient)
	if err != nil {
		return nil, err
	}
	return kem.Open(recipient.KEM(), dst, enc.Secret, enc.Nonce, ciphertext)
}
