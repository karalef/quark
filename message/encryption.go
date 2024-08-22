package message

import (
	"errors"

	"github.com/karalef/quark"
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/crypto/password"
	"github.com/karalef/quark/crypto/secret"
	"github.com/karalef/quark/encrypted"
	"github.com/karalef/quark/keys/kem"
)

// Encryption contains encapsulated shared secret with symmetric encryption parameters.
type Encryption struct {
	// key id used for encapsulation.
	// If id is empty, only password-based symmetric encryption is used
	ID quark.ID `msgpack:"id,omitempty"`

	// symmetric encryption parameters
	Symmetric encrypted.Symmetric `msgpack:"symmetric"`

	// encapsulated shared secret
	Secret []byte `msgpack:"secret,omitempty"`
}

// IsEncapsulated returns true if there is encapsulated shared secret.
func (e *Encryption) IsEncapsulated() bool { return !e.ID.IsEmpty() }

// Encapsulate generates and encapsulates a shared secret and creates an authenticated stream cipher.
func Encapsulate(scheme secret.Scheme, recipient *kem.PublicKey, associatedData []byte) (aead.Cipher, *Encryption, error) {
	ciphertext, secret, err := kem.Encapsulate(recipient)
	if err != nil {
		return nil, nil, err
	}

	aead, sym, err := encrypted.Encrypt(scheme, secret, associatedData)
	if err != nil {
		return nil, nil, err
	}

	return aead, &Encryption{
		ID:        recipient.ID(),
		Symmetric: *sym,
		Secret:    ciphertext,
	}, err
}

// Password uses password-based symmetric encryption to create an authenticated stream cipher.
func Password(scheme password.Scheme, passphrase string, ad []byte, params kdf.Params) (aead.Cipher, *Encryption, error) {
	aead, sym, err := encrypted.PasswordEncrypt(scheme, passphrase, 32, ad, params)
	if err != nil {
		return nil, nil, err
	}

	return aead, &Encryption{
		Symmetric: *sym,
	}, nil
}

// Decapsulate creates an authenticated cipher for recipient using encapsulated shared secret.
func (e *Encryption) Decapsulate(recipient *kem.PrivateKey, ad []byte) (aead.Cipher, error) {
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
	return e.Symmetric.Decrypt(sharedSecret, ad)
}

// Decrypt creates an authenticated cipher using password-based symmetric encryption.
func (e *Encryption) Decrypt(passphrase string, ad []byte) (aead.Cipher, error) {
	if e.IsEncapsulated() {
		return nil, errors.New("there is encapsulated shared secret (not password-encrypted)")
	}
	return e.Symmetric.PasswordDecrypt(passphrase, ad)
}
