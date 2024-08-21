package encryption

import (
	"errors"

	"github.com/karalef/quark"
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/secret"
	"github.com/karalef/quark/encaps"
)

// Encryption contains encapsulated shared secret with symmetric encryption parameters.
type Encryption struct {
	// key id used for encapsulation.
	// If id is empty, only password-based symmetric encryption is used
	ID quark.ID `msgpack:"id,omitempty"`

	// symmetric encryption parameters
	Symmetric Symmetric `msgpack:"symmetric"`

	// encapsulated shared secret
	Secret []byte `msgpack:"secret,omitempty"`
}

// IsEncapsulated returns true if there is encapsulated shared secret.
func (e *Encryption) IsEncapsulated() bool { return !e.ID.IsEmpty() }

// Encapsulate generates and encapsulates a shared secret and creates an authenticated stream cipher.
func Encapsulate(scheme secret.Scheme, recipient *encaps.PublicKey, associatedData []byte) (aead.Cipher, *Encryption, error) {
	ciphertext, secret, err := encaps.Encapsulate(recipient)
	if err != nil {
		return nil, nil, err
	}

	aead, enc, err := Encrypt(scheme, secret, associatedData)
	if err != nil {
		return nil, nil, err
	}
	enc.ID = recipient.ID()
	enc.Secret = ciphertext

	return aead, enc, err
}

// Decapsulate creates an authenticated cipher from Encryption and recipient.
func (e *Encryption) Decapsulate(recipient *encaps.PrivateKey, associatedData []byte) (aead.Cipher, error) {
	if !e.IsEncapsulated() {
		return nil, errors.New("there is no encapsulated shared secret")
	}
	if e.ID != recipient.ID() {
		return nil, errors.New("wrong recipient")
	}
	sharedSecret, err := recipient.Decapsulate(e.Secret)
	if err != nil {
		return nil, err
	}
	return e.Symmetric.Decrypt(sharedSecret, associatedData)
}
