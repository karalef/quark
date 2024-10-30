package message

import (
	"errors"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/encrypted"
	"github.com/karalef/quark/encrypted/secret"
)

// Encryption contains encapsulated shared secret with symmetric encryption parameters.
type Encryption struct {
	// key id used for encapsulation.
	// If id is empty, only password-based symmetric encryption is used
	ID crypto.ID `msgpack:"id,omitempty"`

	// nonce
	Nonce []byte `msgpack:"nonce"`

	// symmetric encryption parameters
	Symmetric encrypted.Symmetric `msgpack:"symmetric"`

	// encapsulated shared secret
	Secret []byte `msgpack:"secret,omitempty"`
}

// IsEncapsulated returns true if there is encapsulated shared secret.
func (e *Encryption) IsEncapsulated() bool { return !e.ID.IsEmpty() }

// Encapsulate generates and encapsulates a shared secret and creates an authenticated stream cipher.
func Encapsulate(scheme *secret.Scheme, recipient kem.PublicKey, associatedData []byte) (aead.Cipher, *Encryption, error) {
	ciphertext, secret, err := kem.Encapsulate(recipient)
	if err != nil {
		return nil, nil, err
	}

	sym := encrypted.New(scheme)
	crypter, err := sym.NewCrypter(secret)
	if err != nil {
		return nil, nil, err
	}
	nonce := crypto.Rand(scheme.AEAD().NonceSize())
	aead, err := crypter.Encrypt(nonce, associatedData)
	if err != nil {
		return nil, nil, err
	}

	return aead, &Encryption{
		ID:        recipient.ID(),
		Nonce:     nonce,
		Symmetric: sym,
		Secret:    ciphertext,
	}, err
}

// Password uses password-based symmetric encryption to create an authenticated stream cipher.
func Password(passphrase string, ad []byte, params encrypted.PassphraseParams) (aead.Cipher, *Encryption, error) {
	sym := encrypted.NewWithPassphrase(params)
	crypter, err := sym.NewPassphraseCrypter(passphrase)
	if err != nil {
		return nil, nil, err
	}
	nonce := crypto.Rand(params.Scheme.AEAD().NonceSize())
	aead, err := crypter.Encrypt(nonce, ad)
	if err != nil {
		return nil, nil, err
	}

	return aead, &Encryption{
		Nonce:     nonce,
		Symmetric: sym,
	}, nil
}

// Decapsulate creates an authenticated cipher for recipient using encapsulated shared secret.
func (e *Encryption) Decapsulate(recipient kem.PrivateKey, ad []byte) (aead.Cipher, error) {
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
	crypter, err := e.Symmetric.NewCrypter(sharedSecret)
	if err != nil {
		return nil, err
	}
	return crypter.Decrypt(e.Nonce, ad)
}

// Decrypt creates an authenticated cipher using password-based symmetric encryption.
func (e *Encryption) Decrypt(passphrase string, ad []byte) (aead.Cipher, error) {
	if e.IsEncapsulated() {
		return nil, errors.New("there is encapsulated shared secret (not password-encrypted)")
	}
	crypter, err := e.Symmetric.NewPassphraseCrypter(passphrase)
	if err != nil {
		return nil, err
	}
	return crypter.Decrypt(e.Nonce, ad)
}
