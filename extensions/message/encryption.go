package message

import (
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/pke"
	"github.com/karalef/quark/encrypted"
)

type Encrypter interface {
	Encrypt(associatedData []byte) (aead.Cipher, *Encryption, error)
}

var (
	_ Encrypter = passphraseEncrypter{}
	_ Encrypter = secretEncrypter{}
	_ Encrypter = groupEncrypter{}
)

type passphraseEncrypter struct {
	passphrase string
	params     encrypted.PassphraseParams
}

// Encrypt uses passhprase-based symmetric encryption to create an authenticated stream cipher.
func (p passphraseEncrypter) Encrypt(ad []byte) (aead.Cipher, *Encryption, error) {
	pass := encrypted.NewPassphrased(p.params)
	nonce := crypto.Rand(p.params.Scheme.NonceSize())
	aead, err := pass.Encrypter(p.passphrase, nonce, ad)
	if err != nil {
		return nil, nil, err
	}

	return aead, &Encryption{
		Nonce:     nonce,
		Passphase: &pass,
	}, nil
}

type secretEncrypter struct {
	recipient kem.PublicKey
	scheme    encrypted.Secret
}

// Encrypt generates and encapsulates a shared secret and creates an authenticated stream cipher.
func (s secretEncrypter) Encrypt(ad []byte) (aead.Cipher, *Encryption, error) {
	nonce := crypto.Rand(s.scheme.NonceSize())
	aead, ss, err := encrypted.Encapsulate(s.scheme, s.recipient, nonce, ad)
	if err != nil {
		return nil, nil, err
	}

	return aead, &Encryption{
		Nonce:  nonce,
		Secret: ss,
	}, err
}

type groupEncrypter struct {
	scheme     encrypted.Secret
	recipients []pke.PublicKey
}

// Encrypt generates and encapsulates a shared secret for each recipient and creates an authenticated stream cipher.
func (g groupEncrypter) Encrypt(ad []byte) (aead.Cipher, *Encryption, error) {
	nonce := crypto.Rand(g.scheme.NonceSize())
	aead, gs, err := encrypted.EncryptGroup(g.scheme, g.recipients, nonce, ad)
	if err != nil {
		return nil, nil, err
	}

	return aead, &Encryption{
		Nonce: nonce,
		Group: gs,
	}, err
}

type derivedEncrypter struct {
	scheme aead.Scheme
	key    []byte
}

// Encrypt uses derived key to create an authenticated stream cipher.
func (d derivedEncrypter) Encrypt(ad []byte) (aead.Cipher, *Encryption, error) {
	nonce := crypto.Rand(d.scheme.NonceSize())
	aead, err := d.scheme.Encrypt(d.key, nonce, ad)
	if err != nil {
		return nil, nil, err
	}

	return aead, &Encryption{
		Nonce:   nonce,
		Derived: d.scheme,
	}, nil
}

// Encryption contains nonce and one of encryption types.
type Encryption struct {
	Passphase *encrypted.Passphrased  `msgpack:"passphase,omitempty"`
	Secret    *encrypted.SharedSecret `msgpack:"secret,omitempty"`
	Group     *encrypted.GroupSecret  `msgpack:"group,omitempty"`

	// Derived is used when the shared secret is established and the key is derived.
	Derived aead.Scheme `msgpack:"derived,omitempty"`

	Nonce []byte `msgpack:"nonce"`
}

// IsPassphrased returns true if message is encrypted using passphrase-based symmetric encryption.
func (e Encryption) IsPassphrased() bool { return e.Passphase != nil }

// IsEncapsulated returns true if message is encrypted using key encapsulation mechanism.
func (e Encryption) IsEncapsulated() bool { return e.Secret != nil }

// IsGroup returns true if message is encrypted using public key encryption.
func (e Encryption) IsGroup() bool { return e.Group != nil }

// IsDerived returns true if message is encrypted using derived key.
func (e Encryption) IsDerived() bool { return e.Derived != nil }

// DecryptPassphrase creates an authenticated cipher using passphrase-based symmetric encryption.
func (e Encryption) DecryptPassphrase(passphrase string, ad []byte) (aead.Cipher, error) {
	return e.Passphase.Decrypter(passphrase, e.Nonce, ad)
}

// Decapsulate creates an authenticated cipher for recipient using encapsulated shared secret.
func (e Encryption) Decapsulate(recipient kem.PrivateKey, ad []byte) (aead.Cipher, error) {
	return e.Secret.Decapsulate(recipient, e.Nonce, ad)
}

// DecryptFor creates an authenticated cipher for provided recipient.
func (e Encryption) DecryptFor(recipient pke.PrivateKey, ad []byte) (aead.Cipher, error) {
	return e.Group.DecryptTo(recipient, e.Nonce, ad)
}

// Decrypt creates an authenticated cipher using derived key.
func (e Encryption) Decrypt(key, ad []byte) (aead.Cipher, error) {
	return e.Derived.Decrypt(key, e.Nonce, ad)
}

// Passphrase uses passhprase-based symmetric encryption to create an authenticated stream cipher.
func Passphrase(passphrase string, params encrypted.PassphraseParams) Encrypter {
	return passphraseEncrypter{
		passphrase: passphrase,
		params:     params,
	}
}

// Encapsulate generates and encapsulates a shared secret and creates an authenticated stream cipher.
func Encapsulate(scheme encrypted.Secret, recipient kem.PublicKey) Encrypter {
	return secretEncrypter{
		recipient: recipient,
		scheme:    scheme,
	}
}

// EncryptFor generates and encapsulates a shared secret for each recipient and creates an authenticated stream cipher.
func EncryptFor(scheme encrypted.Secret, recipients []pke.PublicKey) Encrypter {
	return groupEncrypter{
		recipients: recipients,
		scheme:     scheme,
	}
}

// Encrypt uses derived key to create an authenticated stream cipher.
func Encrypt(scheme aead.Scheme, key []byte) Encrypter {
	return derivedEncrypter{scheme: scheme, key: key}
}
